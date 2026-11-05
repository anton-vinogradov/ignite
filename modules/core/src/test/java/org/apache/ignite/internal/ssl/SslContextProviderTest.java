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

import java.io.IOException;
import java.security.KeyStore;
import java.security.cert.X509Certificate;
import java.util.List;
import java.util.Map;
import java.util.concurrent.atomic.AtomicInteger;
import javax.cache.configuration.Factory;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLEngine;
import javax.net.ssl.SSLException;
import javax.net.ssl.SSLSessionContext;
import javax.net.ssl.SSLSocket;
import javax.net.ssl.SSLSocketFactory;
import org.apache.ignite.IgniteException;
import org.apache.ignite.internal.processors.cache.persistence.wal.reader.StandaloneGridKernalContext;
import org.apache.ignite.internal.ssl.SslFactoryAccess.ReloadOutcome;
import org.apache.ignite.ssl.SslContextFactory;
import org.apache.ignite.testframework.GridTestUtils;
import org.apache.ignite.testframework.TestCertificateAuthority;
import org.apache.ignite.testframework.junits.common.GridCommonAbstractTest;
import org.junit.Assert;
import org.junit.Test;

import static org.apache.ignite.internal.ssl.SslContextRegistry.BINARY_REST;
import static org.apache.ignite.internal.ssl.SslContextRegistry.COMMUNICATION;
import static org.apache.ignite.internal.ssl.SslContextRegistry.DISCOVERY;
import static org.apache.ignite.testframework.GridTestUtils.assertContains;
import static org.apache.ignite.testframework.TestCertificateAuthority.PWD;
import static org.apache.ignite.testframework.TestCertificateAuthority.chain;
import static org.apache.ignite.testframework.TestCertificateAuthority.context;
import static org.apache.ignite.testframework.TestCertificateAuthority.merged;
import static org.apache.ignite.testframework.TestCertificateAuthority.trustManagers;
import static org.junit.Assert.assertArrayEquals;

/**
 * The provider exposes the material and reload results owned by its factory. Reload validates the complete candidate before
 * replacing the material in use. The registry shares a provider between transports using the same factory object.
 */
public class SslContextProviderTest extends GridCommonAbstractTest {
    /** */
    private static final long HOUR = 60 * 60_000L;

    /** Authority that signs the certificates the providers start on. */
    private TestCertificateAuthority ca;

    /** {@inheritDoc} */
    @Override protected void beforeTest() throws Exception {
        ca = new TestCertificateAuthority("provider-ca");
    }

    /**
     * Reload installs the context and metadata of a new factory call; the factory is called once on creation and once per reload.
     * The new keys come from another authority: reload does not check them against the trust of the node.
     */
    @Test
    public void testReloadInstallsNewContextAndChains() throws Exception {
        TestCertificateAuthority otherCa = new TestCertificateAuthority("other-ca");
        KeyStore a = otherCa.keyStoreWithPrivateKey("a");
        KeyStore b = otherCa.keyStoreWithPrivateKey("b");
        TestSslContextFactory f = new TestSslContextFactory(ca.keyStoreWithPrivateKey("startup"), ca.trustStore());
        SslContextProvider p = new SslContextProvider(f);
        SSLContext original = f.create();

        f.keys = merged(a, b);

        Map<String, List<X509Certificate>> expectedChains = Map.of("a", chain(a), "b", chain(b));

        assertEquals(expectedChains, p.reload());
        assertNotSame(original, f.create());
        assertSame(f.create().getServerSessionContext(), p.sharedContext().getServerSessionContext());
        assertEquals(expectedChains, p.certificateChains());
        assertEquals(2, f.loads);
        assertTrue(p.reloadOutcome().successTime() > 0);
    }

    /** Registration reuses accepted startup material. An earlier failed first load is not a reload failure. */
    @Test
    public void testRegistrationAfterInitialLoadFailure() throws Exception {
        TestSslContextFactory factory = new TestSslContextFactory(ca.keyStoreWithPrivateKey("startup"), ca.trustStore());

        factory.loadFailure = new IgniteException("Source unavailable");

        GridTestUtils.assertThrows(log, factory::reloadFromSource, IgniteException.class, "Source unavailable");

        factory.loadFailure = null;
        factory.reloadFromSource();

        SSLContext accepted = factory.create();
        SslContextProvider provider = new SslContextProvider(factory);

        assertSame(accepted, factory.create());
        assertSame(accepted.getServerSessionContext(), provider.sharedContext().getServerSessionContext());
        assertEquals(new ReloadOutcome(0, 0, null, 0), provider.reloadOutcome());
        assertEquals(2, factory.loads);
    }

    /** Direct initialization updates new provider engines, while captured contexts and engines retain their material. */
    @Test
    public void testDirectFactoryInitUpdatesProvider() throws Exception {
        String[] startupProtocols = {"TLSv1.2"};
        String[] replacementProtocols = {"TLSv1.3"};
        KeyStore replacementKeys = ca.keyStoreWithPrivateKey("replacement");
        TestSslContextFactory f = new TestSslContextFactory(ca.keyStoreWithPrivateKey("startup"), ca.trustStore());

        f.setProtocols(startupProtocols);

        SslContextProvider p = new SslContextProvider(f);
        SSLContext shared = p.sharedContext();
        SSLContext captured = f.create();
        SSLEngine existing = shared.createSSLEngine();
        SSLSocketFactory capturedSockets = shared.getSocketFactory();

        f.keys = replacementKeys;
        f.setProtocols(replacementProtocols);

        f.reloadFromSource();

        SSLContext next = f.create();

        assertNotSame(captured, next);
        assertEquals(Map.of("replacement", chain(replacementKeys)), p.certificateChains());
        assertSame(next.getClientSessionContext(), shared.getClientSessionContext());
        assertSame(next.getServerSessionContext(), shared.getServerSessionContext());
        assertArrayEquals(startupProtocols, captured.createSSLEngine().getEnabledProtocols());
        assertArrayEquals(startupProtocols, existing.getEnabledProtocols());
        assertArrayEquals(replacementProtocols, shared.createSSLEngine().getEnabledProtocols());

        String host = "peer.example";
        int port = 10800;
        SSLEngine addressed = shared.createSSLEngine(host, port);

        assertEquals(host, addressed.getPeerHost());
        assertEquals(port, addressed.getPeerPort());
        assertArrayEquals(replacementProtocols, addressed.getEnabledProtocols());

        try (SSLSocket old = (SSLSocket)capturedSockets.createSocket();
             SSLSocket current = (SSLSocket)shared.getSocketFactory().createSocket()) {
            assertArrayEquals(startupProtocols, old.getEnabledProtocols());
            assertArrayEquals(replacementProtocols, current.getEnabledProtocols());
        }

        assertTrue(p.reloadOutcome().successTime() > 0);
    }

    /**
     * A failed reload keeps the context, metadata and success time in use, counts failures in a row and records the time and the
     * reason without the messages of wrappers; a successful reload clears the failures.
     */
    @Test
    public void testReloadFailureRetainsContextUntilRecovery() throws Exception {
        KeyStore reloadedKeys = ca.keyStoreWithPrivateKey("reloaded");
        KeyStore recoveredKeys = ca.keyStoreWithPrivateKey("recovered");
        IgniteException failure = new IgniteException("Failed to load", new SSLException(new IOException("bad file")));
        TestSslContextFactory f = new TestSslContextFactory(ca.keyStoreWithPrivateKey("startup"), ca.trustStore());
        SslContextProvider p = new SslContextProvider(f);

        // A successful reload first, so that the success time the failures must keep is not 0.
        f.keys = reloadedKeys;
        p.reload();

        SSLContext reloaded = f.create();
        long successTime = p.reloadOutcome().successTime();
        long failureStart = System.currentTimeMillis();

        f.loadFailure = failure;

        GridTestUtils.assertThrows(log, p::reload, IgniteException.class, "Failed to load");
        GridTestUtils.assertThrows(log, p::reload, IgniteException.class, "Failed to load");

        ReloadOutcome failed = p.reloadOutcome();

        assertSame(reloaded, f.create());
        assertEquals(Map.of("reloaded", chain(reloadedKeys)), p.certificateChains());
        assertTrue(failed.failureTime() >= failureStart);
        assertEquals(new ReloadOutcome(successTime, failed.failureTime(), "Failed to load: bad file", 2), failed);

        f.loadFailure = null;
        f.keys = recoveredKeys;

        p.reload();

        ReloadOutcome recovered = p.reloadOutcome();

        assertEquals(Map.of("recovered", chain(recoveredKeys)), p.certificateChains());
        assertTrue(recovered.successTime() >= failed.failureTime());
        assertEquals(new ReloadOutcome(recovered.successTime(), 0, null, 0), recovered);
    }

    /** Key material with no certificate chains, such as a trust store put in place of the key store, is not applied. */
    @Test
    public void testMaterialWithoutCertificateChainsNotApplied() throws Exception {
        TestSslContextFactory f = new TestSslContextFactory(ca.keyStoreWithPrivateKey("startup"), ca.trustStore());
        SslContextProvider p = new SslContextProvider(f);

        f.keys = ca.trustStore();

        assertReloadRejected(p,
            "The new key material has no X.509 certificate chains, so the node would present no certificate");
    }

    /** A factory that returns the context in use, as a caching custom factory does, gives the node no new certificates. */
    @Test
    public void testContextInUseNotReloaded() throws Exception {
        SSLContext ctx = context(ca.keyStoreWithPrivateKey(), ca.trustStore());
        AtomicInteger loads = new AtomicInteger();
        SslContextProvider p = new SslContextProvider(() -> {
            loads.incrementAndGet();

            return ctx;
        });

        p.sharedContext().createSSLEngine();
        p.sharedContext().createSSLEngine("peer.example", 10800);

        assertEquals(1, loads.get());
        assertNull(p.certificateChains());

        assertReloadRejected(p, "The SSL context factory returned the context already in use");

        p.sharedContext().createSSLEngine();

        assertEquals(2, loads.get());
    }

    /** Every certificate of every chain must be valid now: a later key that is not valid yet and an expired authority are refused. */
    @Test
    public void testEveryCertificateMustBeValidNow() throws Exception {
        long now = System.currentTimeMillis();
        KeyStore valid = ca.keyStoreWithPrivateKey("a-valid");
        KeyStore notYetValid = ca.keyStoreWithPrivateKey("z-not-yet-valid", now + HOUR, now + 2 * HOUR);
        KeyStore expiredCaLeaf = new TestCertificateAuthority("expired-ca", now - 2 * HOUR, now - HOUR).keyStoreWithPrivateKey("leaf");
        TestSslContextFactory f = new TestSslContextFactory(ca.keyStoreWithPrivateKey("startup"), ca.trustStore());
        SslContextProvider p = new SslContextProvider(f);

        f.keys = merged(valid, notYetValid);
        assertReloadRejected(p, "The new certificate chain is not valid now [alias=z-not-yet-valid, subject=CN=z-not-yet-valid,");

        f.keys = expiredCaLeaf;
        assertReloadRejected(p, "The new certificate chain is not valid now [alias=leaf, subject=CN=expired-ca,");
    }

    /**
     * The registry keeps one provider per factory object: transports of one factory share it, while an equal factory, here a record
     * over the same context, gets its own.
     */
    @Test
    public void testRegistryKeepsProviderPerFactoryObject() throws Exception {
        /** Factory that always returns the same context; records with the same context are equal. */
        record Fixed(SSLContext ctx) implements Factory<SSLContext> {
            /** {@inheritDoc} */
            @Override public SSLContext create() {
                return ctx;
            }
        }

        SSLContext ctx = context(ca.keyStoreWithPrivateKey(), ca.trustStore());
        Fixed shared = new Fixed(ctx);
        SslContextRegistry registry = new SslContextRegistry(new StandaloneGridKernalContext(log, null));

        SSLContext communication = registry.register(shared, COMMUNICATION);
        SSLContext discovery = registry.register(shared, DISCOVERY);
        SSLContext binaryRest = registry.register(new Fixed(ctx), BINARY_REST);

        assertSame(communication, discovery);
        assertNotSame(communication, binaryRest);
        assertEquals(2, registry.providers().size());
    }

    /**
     * Checks that reload fails with the reason in its message and in the recorded outcome, keeps the context and metadata in use
     * and counts one more failure.
     *
     * @param p Provider.
     * @param reason Expected part of the failure message; also names the case in assertion messages.
     */
    private void assertReloadRejected(SslContextProvider p, String reason) {
        SSLSessionContext inUse = p.sharedContext().getServerSessionContext();
        Map<String, List<X509Certificate>> chains = p.certificateChains();
        int failures = p.reloadOutcome().failures();

        GridTestUtils.assertThrows(log, p::reload, Exception.class, reason);

        Assert.assertSame(reason, inUse, p.sharedContext().getServerSessionContext());
        assertEquals(reason, chains, p.certificateChains());
        assertEquals(reason, failures + 1, p.reloadOutcome().failures());
        assertContains(log, p.reloadOutcome().failureReason(), reason);
    }

    /** Reads a replaceable key store from memory and supplies trust managers directly. */
    private static class TestSslContextFactory extends SslContextFactory {
        /** Key store returned by the next read. */
        private KeyStore keys;

        /** Failure injected by the source, if any. */
        private IgniteException loadFailure;

        /** Number of key store reads. */
        private int loads;

        /**
         * @param keys Initial key store.
         * @param trust Trust store.
         */
        TestSslContextFactory(KeyStore keys, KeyStore trust) throws Exception {
            this.keys = keys;

            setKeyStoreFilePath("in-memory");
            setKeyStorePassword(PWD);
            setTrustManagers(trustManagers(trust));
        }

        /** A subclass can reload its material without going through the node. */
        void reloadFromSource() {
            init();
        }

        /** {@inheritDoc} */
        @Override protected KeyStore loadKeyStore(String type, String path, char[] pwd) {
            loads++;

            if (loadFailure != null)
                throw loadFailure;

            return keys;
        }
    }
}
