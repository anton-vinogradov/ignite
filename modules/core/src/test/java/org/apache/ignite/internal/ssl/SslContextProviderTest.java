/*
 * Licensed to the Apache Software Foundation (ASF) under one or more
 * contributor license agreements.  See the NOTICE file distributed with
 * this work for additional information regarding copyright ownership.
 * The ASF licenses this file to You under the Apache License, Version 2.0
 * (the "License"); you may not use this file except in compliance with
 * the License.  You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package org.apache.ignite.internal.ssl;

import java.io.Serial;
import java.security.KeyStore;
import java.security.cert.X509Certificate;
import java.util.List;
import java.util.Map;
import java.util.concurrent.Callable;
import java.util.concurrent.atomic.AtomicReference;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLException;
import javax.net.ssl.TrustManager;
import org.apache.ignite.IgniteCheckedException;
import org.apache.ignite.IgniteException;
import org.apache.ignite.configuration.ClientConnectorConfiguration;
import org.apache.ignite.internal.IgniteEx;
import org.apache.ignite.ssl.AbstractSslContextFactory;
import org.apache.ignite.ssl.KeyMaterial;
import org.apache.ignite.ssl.SslBundle;
import org.apache.ignite.testframework.GridTestUtils;
import org.apache.ignite.testframework.TestCertificateAuthority;
import org.apache.ignite.testframework.junits.common.GridCommonAbstractTest;
import org.junit.Test;

import static org.apache.ignite.internal.ssl.SslContextRegistry.CLIENT_CONNECTOR;
import static org.apache.ignite.internal.ssl.SslContextRegistry.COMMUNICATION;
import static org.apache.ignite.internal.ssl.SslContextRegistry.DISCOVERY;
import static org.apache.ignite.ssl.SslContextFactory.DFLT_KEY_ALGORITHM;
import static org.apache.ignite.ssl.SslTestUtils.discoveryPort;
import static org.apache.ignite.ssl.SslTestUtils.reload;
import static org.apache.ignite.ssl.SslTestUtils.servedCertificate;
import static org.apache.ignite.ssl.SslTestUtils.status;
import static org.apache.ignite.testframework.GridTestUtils.assertContains;
import static org.apache.ignite.testframework.GridTestUtils.assertThrowsWithCause;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

/** Tests manual reload validation and certificate sources that supply optional metadata. */
public class SslContextProviderTest extends GridCommonAbstractTest {
    /** */
    private static final long MINUTE = 60_000L;

    /** */
    private static final long HOUR = 60 * MINUTE;

    /** Default certificate authority for the tests. */
    private TestCertificateAuthority ca;

    /** {@inheritDoc} */
    @Override protected void beforeTest() throws Exception {
        ca = new TestCertificateAuthority("reloadca");
    }

    /** {@inheritDoc} */
    @Override protected void afterTest() {
        stopAllGrids();
    }

    /** The node retains a bundle until reload and uses metadata from the factory's store loader. */
    @Test
    public void testNodeKeepsBundleUntilReload() throws Exception {
        ScriptedSslContextFactory factory = new ScriptedSslContextFactory(ca::keyStoreWithPrivateKey);
        SslContextProvider provider = new SslContextProvider(factory);
        SSLContext first = provider.context();

        assertSame(first, provider.context());
        assertNotNull(provider.certificateChains());
        assertEquals(1, factory.calls);

        provider.reload();

        assertNotSame(first, provider.context());
        assertNotNull(provider.certificateChains());
        assertEquals(2, factory.calls);
    }

    /** Nodes with different certificates from one authority keep communicating when only one node reloads. */
    @Test
    public void testReloadWithDifferentCertificatesFromSameAuthority() throws Exception {
        assertNodesReconnectAfterRotationAndRestart(ca);
    }

    /** Nodes need to trust each other's authorities, not their own, when one node reloads its certificate. */
    @Test
    public void testReloadWithDifferentAuthorities() throws Exception {
        assertNodesReconnectAfterRotationAndRestart(new TestCertificateAuthority("peerca"));
    }

    /** Reload installs the administrator's material; an actual TLS connection still rejects an authority the peer does not trust. */
    @Test
    public void testReloadDoesNotBypassPeerTrust() throws Exception {
        String untrustedCaName = "untrusted-ca";
        TestCertificateAuthority peerCa = new TestCertificateAuthority("peerca");
        TestCertificateAuthority untrusted = new TestCertificateAuthority(untrustedCaName);
        AtomicReference<KeyStore> keys = new AtomicReference<>(ca.keyStoreWithPrivateKey());
        KeyStore peerKeys = peerCa.keyStoreWithPrivateKey();

        ScriptedSslContextFactory factory = factory(keys::get, peerCa.trustStore());
        ScriptedSslContextFactory peerFactory = factory(() -> peerKeys, ca.trustStore());

        IgniteEx g0 = startNode(0, factory);
        IgniteEx g1 = startNode(1, peerFactory);

        X509Certificate peerCert = certificate(provider(g1));

        assertEquals(certificate(provider(g0)), servedCertificate(peerFactory.createSslBundle().context(), discoveryPort(g0)));

        keys.set(untrusted.keyStoreWithPrivateKey());

        assertContains(log, reload(g0), ": reloaded " + COMMUNICATION + ", " + DISCOVERY);
        assertTrue(provider(g0).reloadOutcome().successTime() > 0);
        assertEquals("CN=" + untrustedCaName, certificate(provider(g0)).getIssuerX500Principal().getName());
        assertEquals(peerCert, certificate(provider(g1)));

        assertThrowsWithCause(() -> servedCertificate(peerFactory.createSslBundle().context(), discoveryPort(g0)), SSLException.class);
    }

    /** Commands report both private-key aliases before and after reloading a store with multiple keys. */
    @Test
    public void testCommandsReportEveryPrivateKey() throws Exception {
        ScriptedSslContextFactory factory = new ScriptedSslContextFactory(this::twoKeys);

        IgniteEx g = startClientConnectorOn(factory);

        SslContextProvider p = provider(g, CLIENT_CONNECTOR);

        assertEquals(2, p.certificateChains().size());

        for (String report : List.of(status(g), reload(g))) {
            for (String alias : p.certificateChains().keySet())
                assertContains(log, report, "alias=" + alias);
        }
    }

    /** Replacing one key with several keys must not prevent manual reload. */
    @Test
    public void testReloadCanAddPrivateKeys() throws Exception {
        ScriptedSslContextFactory factory = new ScriptedSslContextFactory(ca::keyStoreWithPrivateKey, this::twoKeys);

        SslContextProvider p = new SslContextProvider(factory);
        SSLContext inUse = p.context();

        assertEquals(1, p.certificateChains().size());

        p.reload();

        assertNotSame(inUse, p.context());
        assertEquals(2, p.certificateChains().size());
        assertTrue(p.reloadOutcome().successTime() > 0);
        assertEquals(0, p.reloadOutcome().failures());
    }

    /** Reload failures keep the active context and last success time. A successful retry clears the failure history. */
    @Test
    public void testReloadFailureRetainsContextUntilRecovery() throws Exception {
        String failureReason = "Certificate source is unavailable";
        Callable<KeyStore> unavailable = () -> {
            throw new IgniteException(failureReason);
        };

        Callable<KeyStore> startupKeys = freshKeysValidFor(HOUR);
        Callable<KeyStore> successfulReloadKeys = freshKeysValidFor(HOUR);
        Callable<KeyStore> recoveryKeys = freshKeysValidFor(2 * HOUR);
        ScriptedSslContextFactory factory = new ScriptedSslContextFactory(
            startupKeys, successfulReloadKeys, unavailable, unavailable, recoveryKeys);
        SslContextProvider p = new SslContextProvider(factory);

        p.reload();

        SSLContext inUse = p.context();
        Map<String, List<X509Certificate>> chains = p.certificateChains();
        long lastSuccess = p.reloadOutcome().successTime();

        assertTrue(lastSuccess > 0);

        for (int failures = 1; failures <= 2; failures++) {
            long attemptStart = System.currentTimeMillis();

            GridTestUtils.assertThrows(log, p::reload, IgniteException.class, failureReason);

            assertSame(inUse, p.context());
            assertEquals(chains, p.certificateChains());
            assertEquals(lastSuccess, p.reloadOutcome().successTime());
            assertEquals(failures, p.reloadOutcome().failures());
            assertTrue(p.reloadOutcome().failureTime() >= attemptStart);
            assertContains(log, p.reloadOutcome().failureReason(), failureReason);
        }

        long recoveryStart = System.currentTimeMillis();

        SslBundle recovered = p.reload();

        assertNotSame(inUse, p.context());
        assertSame(recovered.context(), p.context());
        assertEquals(recovered.certificateChains(), p.certificateChains());
        assertTrue(certificate(p).getNotAfter().after(chains.values().iterator().next().get(0).getNotAfter()));
        assertTrue(p.reloadOutcome().successTime() >= recoveryStart);
        assertEquals(0, p.reloadOutcome().failures());
        assertEquals(0, p.reloadOutcome().failureTime());
        assertNull(p.reloadOutcome().failureReason());
    }

    /** A not yet valid candidate leaves the working context and its metadata in use. */
    @Test
    public void testNotYetValidCertificateNotApplied() throws Exception {
        long now = System.currentTimeMillis();
        ScriptedSslContextFactory factory = new ScriptedSslContextFactory(ca::keyStoreWithPrivateKey,
            () -> ca.keyStoreWithPrivateKey("future", now + HOUR, now + 2 * HOUR));
        SslContextProvider p = new SslContextProvider(factory);
        SSLContext inUse = p.context();
        Map<String, List<X509Certificate>> chains = p.certificateChains();

        GridTestUtils.assertThrows(log, p::reload, IgniteCheckedException.class, "The new certificate chain is not valid now");

        assertSame(inUse, p.context());
        assertEquals(chains, p.certificateChains());
        assertEquals(1, p.reloadOutcome().failures());
    }

    /** A valid leaf does not make a replacement usable when its issuer has expired. */
    @Test
    public void testExpiredIssuerNotApplied() throws Exception {
        long now = System.currentTimeMillis();
        String expiredCaName = "expired-ca";
        TestCertificateAuthority expiredCa = new TestCertificateAuthority(expiredCaName, now - 2 * HOUR, now - HOUR);
        KeyStore candidate = expiredCa.keyStoreWithPrivateKey();

        TestCertificateAuthority.certificateChain(candidate)[0].checkValidity();

        SslContextProvider p = new SslContextProvider(new ScriptedSslContextFactory(ca::keyStoreWithPrivateKey, () -> candidate));
        SSLContext inUse = p.context();
        Map<String, List<X509Certificate>> chains = p.certificateChains();

        GridTestUtils.assertThrows(log, p::reload, IgniteCheckedException.class, "subject=CN=" + expiredCaName);

        assertSame(inUse, p.context());
        assertEquals(chains, p.certificateChains());
        assertEquals(1, p.reloadOutcome().failures());
    }

    /** A valid first key must not hide an expired certificate belonging to another key. */
    @Test
    public void testEveryPrivateKeyIsValidated() throws Exception {
        long now = System.currentTimeMillis();
        String validAlias = "a-valid";
        String expiredAlias = "z-expired";
        KeyStore keys = ca.keyStoreWithPrivateKey(validAlias);
        KeyStore expired = ca.keyStoreWithPrivateKey(expiredAlias, now - 2 * HOUR, now - HOUR);

        keys.setKeyEntry(expiredAlias, expired.getKey(expiredAlias, TestCertificateAuthority.PWD), TestCertificateAuthority.PWD,
            expired.getCertificateChain(expiredAlias));

        SslContextProvider provider = new SslContextProvider(new ScriptedSslContextFactory(ca::keyStoreWithPrivateKey, () -> keys));
        SSLContext original = provider.context();
        Map<String, List<X509Certificate>> originalChains = provider.certificateChains();

        GridTestUtils.assertThrows(log, provider::reload, IgniteCheckedException.class, "alias=" + expiredAlias);

        assertSame(original, provider.context());
        assertEquals(originalChains, provider.certificateChains());
    }

    /** A known private key without an X.509 chain cannot replace the working material. */
    @Test
    public void testMissingCertificateChainNotApplied() throws Exception {
        String alias = "missing-chain";

        assertMissingChainRejected(Map.of(alias, List.of()), alias);
    }

    /** A valid key does not hide another key whose X.509 chain is absent. */
    @Test
    public void testMissingChainAmongOtherKeysNotApplied() throws Exception {
        String validAlias = "a-valid";
        String missingAlias = "z-missing";
        List<X509Certificate> validChain = List.of(TestCertificateAuthority.certificateChain(ca.keyStoreWithPrivateKey(validAlias)));

        assertMissingChainRejected(Map.of(validAlias, validChain, missingAlias, List.of()), missingAlias);
    }

    /**
     * @param candidateChains Explicit metadata supplied by a factory, with a known key lacking an X.509 chain.
     * @param missingAlias Alias of that key.
     */
    private void assertMissingChainRejected(Map<String, List<X509Certificate>> candidateChains, String missingAlias) throws Exception {
        SslBundle init = TestCertificateAuthority.bundle(ca.keyStoreWithPrivateKey(), ca.trustStore());
        SSLContext candidate = TestCertificateAuthority.context(ca.keyStoreWithPrivateKey(), ca.trustStore());
        AbstractSslContextFactory factory = mock(AbstractSslContextFactory.class);

        when(factory.createSslBundle()).thenReturn(init, new SslBundle(candidate, candidateChains));

        SslContextProvider provider = new SslContextProvider(factory);

        Throwable failure = GridTestUtils.assertThrows(log, provider::reload, IgniteCheckedException.class,
            "The private key has no X.509 certificate chain");

        assertContains(log, failure.getMessage(), "alias=" + missingAlias);
        assertContains(log, failure.getMessage(), "remove the key or provide its X.509 certificate chain");
        assertSame(init.context(), provider.context());
        assertEquals(init.certificateChains(), provider.certificateChains());
        assertEquals(1, provider.reloadOutcome().failures());
    }

    /** An unsupported protocol in a replacement context leaves the working context in use. */
    @Test
    public void testUnsupportedProtocolNotApplied() {
        String invalidProtocol = "SSLvDoesNotExist";
        ScriptedSslContextFactory factory = new ScriptedSslContextFactory(ca::keyStoreWithPrivateKey);
        SslContextProvider p = new SslContextProvider(factory);
        SSLContext inUse = p.context();

        factory.setProtocols(invalidProtocol);

        GridTestUtils.assertThrows(log, p::reload, IllegalArgumentException.class, invalidProtocol);

        assertSame(inUse, p.context());
        assertEquals(1, p.reloadOutcome().failures());
    }

    /** @return Store with two private keys, each with its own valid certificate chain. */
    private KeyStore twoKeys() throws Exception {
        String firstAlias = "first-key";
        String secondAlias = "second-key";
        KeyStore keys = ca.keyStoreWithPrivateKey(firstAlias);
        KeyStore other = ca.keyStoreWithPrivateKey(secondAlias);

        keys.setKeyEntry(secondAlias, other.getKey(secondAlias, TestCertificateAuthority.PWD), TestCertificateAuthority.PWD,
            other.getCertificateChain(secondAlias));

        return keys;
    }

    /**
     * @param factory SSL context factory of the client connector.
     * @return Started node whose client connector runs on the factory and whose other transports run without SSL.
     */
    private IgniteEx startClientConnectorOn(AbstractSslContextFactory factory) throws Exception {
        return startGrid(getTestIgniteInstanceName(0), cfg -> cfg
            .setClientConnectorConfiguration(new ClientConnectorConfiguration().setSslEnabled(true).setSslClientAuth(false)
                .setUseIgniteSslContextFactory(false).setSslContextFactory(factory)));
    }

    /**
     * @param idx Node index.
     * @param factory SSL context factory of the node.
     * @return Started node.
     */
    private IgniteEx startNode(int idx, AbstractSslContextFactory factory) throws Exception {
        return startGrid(getTestIgniteInstanceName(idx), cfg -> cfg.setSslContextFactory(factory));
    }

    /**
     * @param source Key store to use on each request.
     * @param trust Authorities the node accepts.
     * @return Configured factory.
     */
    private ScriptedSslContextFactory factory(Callable<KeyStore> source, KeyStore trust) {
        ScriptedSslContextFactory factory = new ScriptedSslContextFactory(source);

        factory.trust = trust;

        return factory;
    }

    /**
     * Rotates one node's certificate, then restarts each node to check that they load their current certificates and reconnect.
     *
     * @param peerCa Authority of the peer whose certificate stays unchanged.
     */
    private void assertNodesReconnectAfterRotationAndRestart(TestCertificateAuthority peerCa) throws Exception {
        AtomicReference<KeyStore> keys = new AtomicReference<>(ca.keyStoreWithPrivateKey());
        KeyStore peerKeys = peerCa.keyStoreWithPrivateKey();
        ScriptedSslContextFactory factory = factory(keys::get, peerCa.trustStore());
        ScriptedSslContextFactory peerFactory = factory(() -> peerKeys, ca.trustStore());

        IgniteEx g0 = startNode(0, factory);
        IgniteEx g1 = startNode(1, peerFactory);

        X509Certificate peerCert = certificate(provider(g1));

        assertFalse(certificate(provider(g0)).equals(peerCert));
        assertComputeWorks(g0, g1);

        KeyStore replacement = ca.keyStoreWithPrivateKey();
        X509Certificate replacementCert = TestCertificateAuthority.certificateChain(replacement)[0];

        keys.set(replacement);

        assertContains(log, reload(g0), ": reloaded " + COMMUNICATION + ", " + DISCOVERY);

        assertEquals(replacementCert, certificate(provider(g0)));
        assertEquals(peerCert, certificate(provider(g1)));
        assertEquals(0, provider(g1).reloadOutcome().successTime());
        assertEquals(replacementCert, servedCertificate(peerFactory.createSslBundle().context(), discoveryPort(g0)));
        assertEquals(peerCert, servedCertificate(factory.createSslBundle().context(), discoveryPort(g1)));

        assertComputeWorks(g0, g1);

        stopGrid(1);

        g1 = startNode(1, factory(() -> peerKeys, ca.trustStore()));

        assertEquals(replacementCert, certificate(provider(g0)));
        assertEquals(peerCert, certificate(provider(g1)));
        assertComputeWorks(g0, g1);

        stopGrid(0);

        IgniteEx restarted = startNode(0, factory(keys::get, peerCa.trustStore()));

        assertEquals(replacementCert, certificate(provider(restarted)));
        assertEquals(replacementCert, servedCertificate(peerFactory.createSslBundle().context(), discoveryPort(restarted)));
        assertEquals(peerCert, certificate(provider(g1)));
        assertComputeWorks(restarted, g1);
    }

    /** Runs a job from each node on its peer. */
    private void assertComputeWorks(IgniteEx g0, IgniteEx g1) {
        for (IgniteEx from : List.of(g0, g1)) {
            IgniteEx to = from == g0 ? g1 : g0;

            assertEquals((Integer)1, from.compute(from.cluster().forNodeId(to.localNode().id())).withTimeout(10_000).call(() -> 1));
        }
    }

    /**
     * @param lifetime Lifetime of the certificate.
     * @return Step that issues a certificate valid from the moment it is issued.
     */
    private Callable<KeyStore> freshKeysValidFor(long lifetime) {
        return () -> {
            long now = System.currentTimeMillis();

            return ca.keyStoreWithPrivateKey("node", now, now + lifetime);
        };
    }

    /**
     * @param g Node.
     * @return SSL context provider used by communication.
     */
    private static SslContextProvider provider(IgniteEx g) {
        return provider(g, COMMUNICATION);
    }

    /**
     * @param g Node.
     * @param transport Transport.
     * @return SSL context provider used by the transport.
     */
    private static SslContextProvider provider(IgniteEx g, String transport) {
        for (SslContextProvider p : g.context().sslContexts().providers()) {
            if (p.transports().contains(transport))
                return p;
        }

        throw new AssertionError("Nothing serves " + transport);
    }

    /** @return The sole leaf certificate of a provider used by a single-key test. */
    private static X509Certificate certificate(SslContextProvider provider) {
        Map<String, List<X509Certificate>> chains = provider.certificateChains();

        assertNotNull(chains);
        assertEquals(1, chains.size());

        return chains.values().iterator().next().get(0);
    }

    /** Factory that answers each request the way the test scripted it, the last step repeated for the rest. */
    private class ScriptedSslContextFactory extends AbstractSslContextFactory {
        /** */
        @Serial
        private static final long serialVersionUID = 0L;

        /** Answers to the requests in order, the last one repeated for the rest. */
        private final List<Callable<KeyStore>> steps;

        /** Requests so far. */
        private int calls;

        /** Trust store for new contexts, or {@code null} to trust only the default test authority. */
        private volatile KeyStore trust;

        /** @param steps Answers to the requests in order, the last one repeated for the rest. */
        @SafeVarargs
        private ScriptedSslContextFactory(Callable<KeyStore>... steps) {
            this.steps = List.of(steps);
        }

        /** {@inheritDoc} */
        @Override protected void checkParameters() {
            // No-op.
        }

        /** {@inheritDoc} */
        @Override protected KeyMaterial loadKeyMaterial() {
            Callable<KeyStore> step = steps.get(Math.min(calls++, steps.size() - 1));

            try {
                KeyStore store = step.call();

                return new KeyMaterial(store, TestCertificateAuthority.PWD, DFLT_KEY_ALGORITHM);
            }
            catch (IgniteException e) {
                throw e;
            }
            catch (Exception e) {
                throw new IgniteException(e);
            }
        }

        /** {@inheritDoc} */
        @Override protected TrustManager[] createTrustManagers() throws SSLException {
            try {
                return TestCertificateAuthority.trustManagers(trust != null ? trust : ca.trustStore());
            }
            catch (Exception e) {
                throw new SSLException(e);
            }
        }
    }
}
