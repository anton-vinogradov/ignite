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
import org.apache.ignite.testframework.GridTestUtils;
import org.apache.ignite.testframework.TestCertificateAuthority;
import org.apache.ignite.testframework.junits.common.GridCommonAbstractTest;
import org.junit.Test;

import static org.apache.ignite.internal.ssl.SslContextRegistry.CLIENT_CONNECTOR;
import static org.apache.ignite.internal.ssl.SslContextRegistry.COMMUNICATION;
import static org.apache.ignite.internal.ssl.SslContextRegistry.DISCOVERY;
import static org.apache.ignite.ssl.SslTestUtils.discoveryPort;
import static org.apache.ignite.ssl.SslTestUtils.reload;
import static org.apache.ignite.ssl.SslTestUtils.servedCertificate;
import static org.apache.ignite.ssl.SslTestUtils.status;
import static org.apache.ignite.testframework.GridTestUtils.assertContains;
import static org.apache.ignite.testframework.GridTestUtils.assertThrowsWithCause;
import static org.junit.Assert.assertArrayEquals;

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

    /** Changing a returned chain must not change the provider's certificate or chain. */
    @Test
    public void testCertificateChainCannotChangeProvider() {
        SslContextProvider p = new SslContextProvider(new ScriptedSslContextFactory(ca::keyStoreWithPrivateKey));

        X509Certificate[] chain = p.certificateChain();

        assertNotNull(chain);

        X509Certificate[] expected = chain.clone();

        chain[0] = null;

        assertSame(expected[0], p.certificate());
        assertArrayEquals(expected, p.certificateChain());
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

        X509Certificate peerCert = provider(g1).certificate();

        assertEquals(provider(g0).certificate(), servedCertificate(peerFactory.createNew(), discoveryPort(g0)));

        keys.set(untrusted.keyStoreWithPrivateKey());

        assertContains(log, reload(g0), ": reloaded " + COMMUNICATION + ", " + DISCOVERY);
        assertTrue(provider(g0).reloadOutcome().successTime() > 0);
        assertEquals("CN=" + untrustedCaName, provider(g0).certificate().getIssuerX500Principal().getName());
        assertEquals(peerCert, provider(g1).certificate());

        assertThrowsWithCause(() -> servedCertificate(peerFactory.createNew(), discoveryPort(g0)), SSLException.class);
    }

    /** Commands reload a store with multiple private keys and report that its certificate metadata is unavailable. */
    @Test
    public void testCommandsReportUnknownMetadataForMultipleKeys() throws Exception {
        ScriptedSslContextFactory factory = new ScriptedSslContextFactory(this::twoKeys);

        IgniteEx g = startClientConnectorOn(factory);

        SslContextProvider p = provider(g, CLIENT_CONNECTOR);

        assertNull(p.certificateChain());
        assertContains(log, status(g), "certificate metadata is unavailable");
        assertContains(log, reload(g), ": reloaded " + CLIENT_CONNECTOR);
    }

    /** Replacing one key with several keys must not prevent manual reload. */
    @Test
    public void testReloadCanLoseMetadata() throws Exception {
        ScriptedSslContextFactory factory = new ScriptedSslContextFactory(ca::keyStoreWithPrivateKey, this::twoKeys);

        SslContextProvider p = new SslContextProvider(factory);
        SSLContext inUse = p.context();

        assertNotNull(p.certificateChain());

        p.reload();

        assertNotSame(inUse, p.context());
        assertNull(p.certificateChain());
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
        X509Certificate[] chain = p.certificateChain();
        long lastSuccess = p.reloadOutcome().successTime();

        assertTrue(lastSuccess > 0);

        for (int failures = 1; failures <= 2; failures++) {
            long attemptStart = System.currentTimeMillis();

            GridTestUtils.assertThrows(log, p::reload, IgniteException.class, failureReason);

            assertSame(inUse, p.context());
            assertArrayEquals(chain, p.certificateChain());
            assertEquals(lastSuccess, p.reloadOutcome().successTime());
            assertEquals(failures, p.reloadOutcome().failures());
            assertTrue(p.reloadOutcome().failureTime() >= attemptStart);
            assertContains(log, p.reloadOutcome().failureReason(), failureReason);
        }

        long recoveryStart = System.currentTimeMillis();

        X509Certificate recovered = p.reload();

        assertNotSame(inUse, p.context());
        assertEquals(recovered, p.certificate());
        assertTrue(recovered.getNotAfter().after(chain[0].getNotAfter()));
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
        X509Certificate[] chain = p.certificateChain();

        GridTestUtils.assertThrows(log, p::reload, IgniteCheckedException.class, "The new certificate chain is not valid now");

        assertSame(inUse, p.context());
        assertArrayEquals(chain, p.certificateChain());
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
        X509Certificate[] chain = p.certificateChain();

        GridTestUtils.assertThrows(log, p::reload, IgniteCheckedException.class, "subject=CN=" + expiredCaName);

        assertSame(inUse, p.context());
        assertArrayEquals(chain, p.certificateChain());
        assertEquals(1, p.reloadOutcome().failures());
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

    /** @return Store with two valid private keys and therefore no single chain for certificate metadata. */
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

        X509Certificate peerCert = provider(g1).certificate();

        assertFalse(provider(g0).certificate().equals(peerCert));
        assertComputeWorks(g0, g1);

        KeyStore replacement = ca.keyStoreWithPrivateKey();
        X509Certificate replacementCert = TestCertificateAuthority.certificateChain(replacement)[0];

        keys.set(replacement);

        assertContains(log, reload(g0), ": reloaded " + COMMUNICATION + ", " + DISCOVERY);

        assertEquals(replacementCert, provider(g0).certificate());
        assertEquals(peerCert, provider(g1).certificate());
        assertEquals(0, provider(g1).reloadOutcome().successTime());
        assertEquals(replacementCert, servedCertificate(peerFactory.createNew(), discoveryPort(g0)));
        assertEquals(peerCert, servedCertificate(factory.createNew(), discoveryPort(g1)));

        assertComputeWorks(g0, g1);

        stopGrid(1);

        g1 = startNode(1, factory(() -> peerKeys, ca.trustStore()));

        assertEquals(replacementCert, provider(g0).certificate());
        assertEquals(peerCert, provider(g1).certificate());
        assertComputeWorks(g0, g1);

        stopGrid(0);

        IgniteEx restarted = startNode(0, factory(keys::get, peerCa.trustStore()));

        assertEquals(replacementCert, provider(restarted).certificate());
        assertEquals(replacementCert, servedCertificate(peerFactory.createNew(), discoveryPort(restarted)));
        assertEquals(peerCert, provider(g1).certificate());
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
        @Override protected KeyMaterial createKeyMaterial() throws SSLException {
            Callable<KeyStore> step = steps.get(Math.min(calls++, steps.size() - 1));

            try {
                KeyStore store = step.call();

                return KeyMaterial.fromKeyStore(TestCertificateAuthority.keyManagers(store), store);
            }
            catch (IgniteException e) {
                throw e;
            }
            catch (Exception e) {
                throw new SSLException(e);
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
