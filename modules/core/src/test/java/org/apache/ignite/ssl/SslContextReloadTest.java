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

package org.apache.ignite.ssl;

import java.nio.file.Files;
import java.nio.file.Path;
import java.security.KeyStore;
import java.security.cert.X509Certificate;
import java.time.Instant;
import java.util.List;
import java.util.UUID;
import java.util.concurrent.TimeUnit;
import java.util.regex.Pattern;
import javax.cache.configuration.Factory;
import javax.net.ssl.SSLContext;
import org.apache.ignite.Ignite;
import org.apache.ignite.IgniteException;
import org.apache.ignite.Ignition;
import org.apache.ignite.client.IgniteClient;
import org.apache.ignite.client.SslMode;
import org.apache.ignite.compute.ComputeJobResult;
import org.apache.ignite.configuration.ClientConfiguration;
import org.apache.ignite.configuration.ClientConnectorConfiguration;
import org.apache.ignite.configuration.ConnectorConfiguration;
import org.apache.ignite.configuration.IgniteConfiguration;
import org.apache.ignite.internal.IgniteEx;
import org.apache.ignite.internal.management.api.NoArg;
import org.apache.ignite.internal.management.ssl.AbstractSslTask;
import org.apache.ignite.internal.management.ssl.SslReloadTask;
import org.apache.ignite.internal.management.ssl.SslStatusTask;
import org.apache.ignite.internal.ssl.SslContextProvider;
import org.apache.ignite.internal.ssl.SslContextRegistry;
import org.apache.ignite.internal.util.typedef.G;
import org.apache.ignite.internal.util.typedef.X;
import org.apache.ignite.internal.util.typedef.internal.U;
import org.apache.ignite.internal.visor.VisorTaskArgument;
import org.apache.ignite.spi.communication.tcp.TcpCommunicationSpi;
import org.apache.ignite.spi.communication.tcp.internal.ConnectionClientPool;
import org.apache.ignite.testframework.GridTestNode;
import org.apache.ignite.testframework.GridTestUtils;
import org.apache.ignite.testframework.ListeningTestLogger;
import org.apache.ignite.testframework.LogListener;
import org.apache.ignite.testframework.TestCertificateAuthority;
import org.apache.ignite.testframework.junits.common.GridCommonAbstractTest;
import org.junit.Test;
import org.mockito.Mockito;

import static org.apache.ignite.internal.IgniteNodeAttributes.ATTR_REST_TCP_PORT;
import static org.apache.ignite.internal.ssl.SslContextRegistry.BINARY_REST;
import static org.apache.ignite.internal.ssl.SslContextRegistry.CLIENT_CONNECTOR;
import static org.apache.ignite.internal.ssl.SslContextRegistry.COMMUNICATION;
import static org.apache.ignite.internal.ssl.SslContextRegistry.DISCOVERY;
import static org.apache.ignite.ssl.SslTestUtils.assertClientAuthentication;
import static org.apache.ignite.ssl.SslTestUtils.discoveryPort;
import static org.apache.ignite.ssl.SslTestUtils.node;
import static org.apache.ignite.ssl.SslTestUtils.reload;
import static org.apache.ignite.ssl.SslTestUtils.reloadFailure;
import static org.apache.ignite.ssl.SslTestUtils.servedCertificate;
import static org.apache.ignite.ssl.SslTestUtils.status;
import static org.apache.ignite.testframework.GridTestUtils.assertContains;
import static org.apache.ignite.testframework.TestCertificateAuthority.certificateChain;

/**
 * Tests {@code --ssl reload} and {@code --ssl status} on running nodes. Each node has separate key and trust stores so that tests
 * can replace or corrupt them independently. The tests generate the keys, trust roots and validity periods explicitly.
 */
public class SslContextReloadTest extends GridCommonAbstractTest {
    /** Transports of a node whose client connector shares the factory of the node. */
    private static final String ALL_TRANSPORTS = CLIENT_CONNECTOR + ", " + COMMUNICATION + ", " + DISCOVERY;

    /** Validity margin for generated certificates. */
    private static final long HOUR = TimeUnit.HOURS.toMillis(1);

    /** Alias and subject of the initial node key. */
    private static final String OLD_NODE = "old-node";

    /** Alias and subject of the replacement node key. */
    private static final String NEW_NODE = "new-node";

    /** Directory the stores of the nodes are placed in. */
    private Path dir;

    /** Whether the client connector runs on a factory of its own. */
    private boolean ownClientConnectorFactory;

    /** Time used to generate certificates for this test. */
    private long now;

    /** Initial authority. */
    private TestCertificateAuthority oldCa;

    /** Replacement authority. */
    private TestCertificateAuthority newCa;

    /** Initial node key and certificate. */
    private KeyStore oldKeys;

    /** Replacement node key and certificate. */
    private KeyStore newKeys;

    /** Certificate initially served by the node. */
    private X509Certificate oldCert;

    /** Certificate installed by a successful reload. */
    private X509Certificate newCert;

    /** Trust roots for probes and the transitional rotation step. */
    private KeyStore trustBoth;

    /** Trust store every node starts on, unless one is placed for it. */
    private KeyStore initTrustStore;

    /** */
    private final ListeningTestLogger nodeLog = new ListeningTestLogger(log);

    /** {@inheritDoc} */
    @Override protected IgniteConfiguration getConfiguration(String igniteInstanceName) throws Exception {
        IgniteConfiguration cfg = super.getConfiguration(igniteInstanceName).setGridLogger(nodeLog);

        if (!Files.exists(keyStore(igniteInstanceName)))
            TestCertificateAuthority.save(oldKeys, keyStore(igniteInstanceName));

        if (!Files.exists(trustStore(igniteInstanceName)))
            TestCertificateAuthority.save(initTrustStore, trustStore(igniteInstanceName));

        ClientConnectorConfiguration cliCfg = new ClientConnectorConfiguration().setSslEnabled(true).setSslClientAuth(false)
            .setUseIgniteSslContextFactory(!ownClientConnectorFactory);

        if (ownClientConnectorFactory)
            cliCfg.setSslContextFactory(storeFactory(igniteInstanceName));

        return cfg.setSslContextFactory(storeFactory(igniteInstanceName)).setClientConnectorConfiguration(cliCfg);
    }

    /** {@inheritDoc} */
    @Override protected void beforeTest() throws Exception {
        dir = Files.createTempDirectory("ignite-ssl-reload-");
        now = System.currentTimeMillis();
        oldCa = new TestCertificateAuthority("old-ca");

        // The replacement issuer expires before its leaf, so status must show the chain's earlier expiry.
        long issuerExpiry = now + HOUR;
        long leafExpiry = now + 2 * HOUR;

        newCa = new TestCertificateAuthority("new-ca", now - HOUR, issuerExpiry);
        oldKeys = oldCa.keyStoreWithPrivateKey(OLD_NODE);
        newKeys = newCa.keyStoreWithPrivateKey(NEW_NODE, now - HOUR, leafExpiry);
        oldCert = certificateChain(oldKeys)[0];
        newCert = certificateChain(newKeys)[0];
        trustBoth = TestCertificateAuthority.trustStore(oldCa, newCa);
        initTrustStore = trustBoth;
    }

    /** {@inheritDoc} */
    @Override protected void afterTest() {
        stopAllGrids();

        U.delete(dir);
    }

    /**
     * A rotation on a running cluster reaches new connections, the report, the node log and status, and leaves established
     * connections working.
     */
    @Test
    public void testReloadOnRunningCluster() throws Exception {
        initTrustStore = trustBoth;

        X509Certificate[] replacementChain = certificateChain(newKeys);
        long issuerExpiry = replacementChain[1].getNotAfter().getTime();

        assertTrue("The issuer must expire before its leaf", issuerExpiry < newCert.getNotAfter().getTime());

        IgniteEx g0 = startGrid(0);
        IgniteEx g1 = startGrid(1);

        LogListener logged = LogListener.matches(Pattern.compile("TLS certificates reloaded \\[transports=" + ALL_TRANSPORTS +
            ", alias=" + NEW_NODE + ", subject=" + Pattern.quote(newCert.getSubjectX500Principal().getName()) +
            ", .*initiator=management command, originNodeId=" + g0.localNode().id())).times(2).build();

        nodeLog.registerListener(logged);

        // The client trusts only the old CA, so it cannot reconnect after the node switches to a certificate from the new CA.
        SSLContext clientCtx = TestCertificateAuthority.context(oldKeys, oldCa.trustStore());

        try (IgniteClient cli = Ignition.startClient(new ClientConfiguration()
            .setAddresses("127.0.0.1:" + g0.context().clientListener().port())
            .setSslMode(SslMode.REQUIRED).setSslContextFactory(() -> clientCtx)
            .setPartitionAwarenessEnabled(false).setClusterDiscoveryEnabled(false))) {
            placeKeys(newKeys);

            String res = reload(g0, g1);

            cli.cacheNames();

            assertReloaded(res, g0, ALL_TRANSPORTS);
            assertReloaded(res, g1, ALL_TRANSPORTS);
            assertTrue(logged.check());
        }

        assertEquals(newCert, certificateAt(g0.context().clientListener().port()));
        assertEquals(newCert, certificateAt(((TcpCommunicationSpi)g0.configuration().getCommunicationSpi()).boundPort()));
        assertEquals(newCert, certificateAt(discoveryPort(g0)));

        SslContextProvider p = g0.context().sslContexts().providers().iterator().next();

        assertEquals(newCert, p.certificateChains().get(NEW_NODE).get(0));
        assertTrue(p.reloadOutcome().successTime() > 0);

        String status = status(g0);

        assertContains(log, status, "chainNotAfter=" + Instant.ofEpochMilli(issuerExpiry));
        assertContains(log, status, "last reload succeeded at " + Instant.ofEpochMilli(p.reloadOutcome().successTime()));

        stopGrid(0);

        IgniteEx restarted = startGrid(0);

        assertEquals(newCert, certificateAt(restarted.context().clientListener().port()));
        assertEquals(newCert, certificateAt(discoveryPort(restarted)));
    }

    /** One node fails: the others still take the new certificate and appear in the report; the command fails. */
    @Test
    public void testPartialFailureAcrossNodes() throws Exception {
        IgniteEx g0 = startGrid(0);
        IgniteEx g1 = startGrid(1);

        TestCertificateAuthority.save(newKeys, keyStore(g0.name()));
        Files.write(keyStore(g1.name()), "not a key store".getBytes());

        String res = reloadFailure(g0, g1);

        assertReloaded(res, g0, ALL_TRANSPORTS);
        assertFailed(res, g1, ALL_TRANSPORTS);
        assertContains(log, res, "Failed to initialize key store");

        String failed = "Failed on 1 node(s):\n" + node(g1) + ": failed on ";
        String succeeded = "\n\nSucceeded on 1 node(s):\n" + node(g0) + ": reloaded ";

        assertTrue("The failed node must be listed first, in a separate block: " + res,
            res.contains(failed) && res.indexOf(succeeded) > res.indexOf(failed));

        assertEquals(newCert, certificateAt(g0.context().clientListener().port()));
        assertEquals(oldCert, certificateAt(g1.context().clientListener().port()));

        String status = status(g1);

        assertContains(log, status, "last reload failed 1 time(s) in a row");
        assertContains(log, status, "Failed to initialize key store");
        assertContains(log, status, "loaded alias=" + OLD_NODE + ", subject=" + oldCert.getSubjectX500Principal().getName() + ',');
    }

    /**
     * A factory that is not an {@link AbstractSslContextFactory} and returns the context in use fails the reload: the node gets no
     * new certificates from it.
     */
    @Test
    public void testCachingFactoryNotReloaded() throws Exception {
        IgniteEx g = startGrid(0, cfg -> {
            SSLContext ctx = cfg.getSslContextFactory().create();

            cfg.setSslContextFactory(() -> ctx);
        });

        placeKeys(newKeys);

        String res = reloadFailure(g);

        assertFailed(res, g, ALL_TRANSPORTS);
        assertContains(log, res, "returns the context in use");

        assertEquals(oldCert, certificateAt(g.context().clientListener().port()));
    }

    /** A shared custom factory loads once at startup and once per reload. Status does not load it. */
    @Test
    public void testCustomFactoryReloaded() throws Exception {
        TestFactory factory = new TestFactory();
        int loadsAfterStart = 1;
        int loadsAfterReload = loadsAfterStart + 1;

        IgniteEx g = startGrid(0, cfg -> {
            cfg.setSslContextFactory(factory);
            cfg.setConnectorConfiguration(new ConnectorConfiguration().setSslEnabled(true));
        });

        String transports = BINARY_REST + ", " + ALL_TRANSPORTS;

        assertEquals("Startup must load the shared factory once", loadsAfterStart, factory.calls);
        assertContains(log, status(g), node(g) + ": " + transports);
        assertEquals("Status must not load the factory", loadsAfterStart, factory.calls);

        SslContextRegistry registry = g.context().sslContexts();
        SSLContext ctx = registry.register(factory, COMMUNICATION);

        assertSame(ctx, registry.register(factory, DISCOVERY));
        assertSame(ctx, registry.register(factory, CLIENT_CONNECTOR));
        assertSame(ctx, registry.register(factory, BINARY_REST));
        assertEquals(1, registry.providers().size());
        assertEquals(loadsAfterStart, factory.calls);

        placeKeys(newKeys);

        assertReloaded(reload(g), g, transports);
        assertEquals("Reload must load the shared factory once", loadsAfterReload, factory.calls);
        assertSame(ctx, registry.register(factory, COMMUNICATION));
        assertContains(log, status(g), "certificate metadata is unavailable");
        assertEquals("Status must not load the factory", loadsAfterReload, factory.calls);

        assertEquals(newCert, certificateAt(discoveryPort(g)));
        assertEquals(newCert, certificateAt(g.context().clientListener().port()));
        assertEquals(newCert, certificateAt(g.localNode().attribute(ATTR_REST_TCP_PORT)));
    }

    /** Equal but distinct factories reload independently, including when one of them fails. */
    @Test
    public void testEqualFactoriesReloadIndependently() throws Exception {
        TestFactory nodeFactory = new TestFactory();
        TestFactory clientFactory = new TestFactory();
        int loadsAfterStart = 1;
        int loadsAfterReload = loadsAfterStart + 1;
        int loadsAfterFailure = loadsAfterReload + 1;

        assertNotSame(nodeFactory, clientFactory);
        assertEquals(nodeFactory, clientFactory);
        assertEquals(nodeFactory.hashCode(), clientFactory.hashCode());

        IgniteEx g = startGrid(0, cfg -> {
            cfg.setSslContextFactory(nodeFactory);
            cfg.getClientConnectorConfiguration().setUseIgniteSslContextFactory(false).setSslContextFactory(clientFactory);
        });

        SslContextRegistry registry = g.context().sslContexts();

        assertEquals(2, registry.providers().size());
        assertNotSame(registry.register(nodeFactory, COMMUNICATION), registry.register(clientFactory, CLIENT_CONNECTOR));
        assertEquals(loadsAfterStart, nodeFactory.calls);
        assertEquals(loadsAfterStart, clientFactory.calls);

        placeKeys(newKeys);

        String res = reload(g);

        assertReloaded(res, g, COMMUNICATION + ", " + DISCOVERY);
        assertReloaded(res, g, CLIENT_CONNECTOR);
        assertEquals(loadsAfterReload, nodeFactory.calls);
        assertEquals(loadsAfterReload, clientFactory.calls);

        nodeFactory.fail = true;

        KeyStore nextKeys = newCa.keyStoreWithPrivateKey();

        placeKeys(nextKeys);

        res = reloadFailure(g);

        assertFailed(res, g, COMMUNICATION + ", " + DISCOVERY);
        assertReloaded(res, g, CLIENT_CONNECTOR);
        assertEquals(loadsAfterFailure, nodeFactory.calls);
        assertEquals(loadsAfterFailure, clientFactory.calls);
        assertEquals(newCert, certificateAt(discoveryPort(g)));
        assertEquals(certificateChain(nextKeys)[0], certificateAt(g.context().clientListener().port()));
    }

    /** An expired certificate stays out of use, and the report, log and status identify the rejected chain. */
    @Test
    public void testExpiredCertificateNotApplied() throws Exception {
        KeyStore expiredStore = expiredKeys();
        String expiredSubj = certificateChain(expiredStore)[0].getSubjectX500Principal().getName();

        String failureReason = "The new certificate chain is not valid now [alias=expired-node, subject=" + expiredSubj + ',';
        LogListener expired = LogListener.matches(failureReason).build();

        nodeLog.registerListener(expired);

        IgniteEx g = startGrid(0);

        placeKeys(expiredStore);

        String res = reloadFailure(g);

        assertFailed(res, g, ALL_TRANSPORTS);
        assertContains(log, res, failureReason);
        assertTrue(expired.check());
        assertEquals(oldCert, certificateAt(discoveryPort(g)));

        String status = status(g);

        assertContains(log, status, "loaded alias=" + OLD_NODE + ", subject=" + oldCert.getSubjectX500Principal().getName() + ", issuer=");
        assertContains(log, status, "last reload failed 1 time(s) in a row");
        assertContains(log, status, "The new certificate chain is not valid now");
    }

    /** A trust-only store must not replace a working node's keys; new connections still receive the original certificate. */
    @Test
    public void testKeyStoreWithoutKeyNotApplied() throws Exception {
        IgniteEx g = startGrid(0);

        placeKeys(trustBoth);

        String res = reloadFailure(g);

        assertFailed(res, g, ALL_TRANSPORTS);
        assertContains(log, res, "The new key material has no private key, so the node would present no certificate");
        assertEquals(oldCert, certificateAt(g.context().clientListener().port()));
        assertEquals(oldCert, certificateAt(discoveryPort(g)));
        assertClientConnected(g, oldKeys);
    }

    /** A client connector and binary REST with factories of their own reload separately from the node-wide factory. */
    @Test
    public void testClientTransportsWithSeparateFactories() throws Exception {
        initTrustStore = oldCa.trustStore();
        KeyStore clientKeys = oldCa.keyStoreWithPrivateKey();
        KeyStore restKeys = oldCa.keyStoreWithPrivateKey();
        KeyStore nextRestKeys = newCa.keyStoreWithPrivateKey();
        Path clientPath = dir.resolve("client-key.jks");
        Path restPath = dir.resolve("binary-rest-key.jks");

        TestCertificateAuthority.save(clientKeys, clientPath);
        TestCertificateAuthority.save(restKeys, restPath);

        IgniteEx g = startGrid(0, cfg -> {
            Path trustPath = trustStore(cfg.getIgniteInstanceName());

            cfg.getClientConnectorConfiguration().setUseIgniteSslContextFactory(false)
                .setSslContextFactory(storeFactory(clientPath, trustPath));
            cfg.setConnectorConfiguration(new ConnectorConfiguration().setSslEnabled(true)
                .setSslFactory(storeFactory(restPath, trustPath)));
        });

        int clientPort = g.context().clientListener().port();
        int restPort = g.localNode().attribute(ATTR_REST_TCP_PORT);
        int commPort = ((TcpCommunicationSpi)g.configuration().getCommunicationSpi()).boundPort();

        assertEquals(oldCert, certificateAt(discoveryPort(g)));
        assertEquals(oldCert, certificateAt(commPort));
        assertEquals(certificateChain(clientKeys)[0], certificateAt(clientPort));
        assertEquals(certificateChain(restKeys)[0], certificateAt(restPort));

        TestCertificateAuthority.save(nextRestKeys, restPath);

        String res = reload(g);

        assertReloaded(res, g, CLIENT_CONNECTOR);
        assertReloaded(res, g, BINARY_REST);
        assertReloaded(res, g, COMMUNICATION + ", " + DISCOVERY);

        assertEquals(oldCert, certificateAt(discoveryPort(g)));
        assertEquals(oldCert, certificateAt(commPort));
        assertEquals(certificateChain(clientKeys)[0], certificateAt(clientPort));
        assertEquals(certificateChain(nextRestKeys)[0], certificateAt(restPort));
    }

    /** Manual reload reports every private key. Client operations and new TLS connections still work. */
    @Test
    public void testKeyStoreWithMultipleKeysReloaded() throws Exception {
        ownClientConnectorFactory = true;

        IgniteEx g = startGrid(0);
        SSLContext clientCtx = TestCertificateAuthority.context(oldKeys, trustBoth);
        KeyStore multipleKeys = KeyStore.getInstance("JKS");

        multipleKeys.load(null, TestCertificateAuthority.PWD);
        multipleKeys.setKeyEntry(OLD_NODE, oldKeys.getKey(OLD_NODE, TestCertificateAuthority.PWD),
            TestCertificateAuthority.PWD, oldKeys.getCertificateChain(OLD_NODE));
        multipleKeys.setKeyEntry(NEW_NODE, newKeys.getKey(NEW_NODE, TestCertificateAuthority.PWD),
            TestCertificateAuthority.PWD, newKeys.getCertificateChain(NEW_NODE));

        try (IgniteClient cli = Ignition.startClient(new ClientConfiguration()
            .setAddresses("127.0.0.1:" + g.context().clientListener().port())
            .setSslMode(SslMode.REQUIRED).setSslContextFactory(() -> clientCtx)
            .setPartitionAwarenessEnabled(false).setClusterDiscoveryEnabled(false))) {
            placeKeys(multipleKeys);

            String res = reload(g);

            assertContains(log, res, node(g) + ": reloaded " + CLIENT_CONNECTOR);
            assertContains(log, res, node(g) + ": reloaded " + COMMUNICATION + ", " + DISCOVERY);

            cli.cacheNames();
        }

        X509Certificate presented = certificateAt(g.context().clientListener().port());

        assertTrue("The connection must use one of the stored keys",
            List.of(oldCert, newCert).contains(presented));

        String status = status(g);

        assertContains(log, status, "alias=" + OLD_NODE);
        assertContains(log, status, "alias=" + NEW_NODE);
        assertContains(log, status, "last reload succeeded at");
    }

    /**
     * The authority is replaced in steps: trust the new one, present its certificates, drop the old one. Every TCP transport
     * accepts certificates from the new authority and rejects old certificates and clients without certificates. The nodes
     * reconnect and a node of the new authority joins.
     */
    @Test
    public void testCertificateAuthorityReplaced() throws Exception {
        initTrustStore = oldCa.trustStore();

        IgniteEx g0 = startGrid(0, cfg -> {
            cfg.getClientConnectorConfiguration().setSslClientAuth(true);
            cfg.setConnectorConfiguration(new ConnectorConfiguration().setSslEnabled(true).setSslClientAuth(true));
        });
        IgniteEx g1 = startGrid(1, cfg -> {
            cfg.getClientConnectorConfiguration().setSslClientAuth(true);
            cfg.setConnectorConfiguration(new ConnectorConfiguration().setSslEnabled(true).setSslClientAuth(true));
        });

        assertTransportClientAuthentication(g0, oldKeys, newKeys);

        placeTrust(trustBoth);
        reload(g0, g1);

        assertClientConnected(g0, oldKeys);
        assertClientConnected(g0, newKeys);

        placeKeys(newKeys);
        reload(g0, g1);

        placeTrust(newCa.trustStore());
        reload(g0, g1);

        String reloadedStatus = status(g0, g1);
        String issuer = newCert.getIssuerX500Principal().getName();

        assertTrue(reloadedStatus, Pattern.compile("issuer=[^;\\n]*" + Pattern.quote(issuer)).matcher(reloadedStatus).find());

        for (IgniteEx node : List.of(g0, g1)) {
            assertClientConnected(node, newKeys);
            assertTransportClientAuthentication(node, newKeys, oldKeys);
        }

        ConnectionClientPool pool = U.field(g0.configuration().getCommunicationSpi(), "clientPool");

        pool.forceCloseConnection(g1.localNode().id());

        assertEquals((Integer)1, g0.compute(g0.cluster().forNodeId(g1.localNode().id())).call(() -> 1));

        TestCertificateAuthority.save(newCa.keyStoreWithPrivateKey(), keyStore(getTestIgniteInstanceName(2)));
        TestCertificateAuthority.save(newCa.trustStore(), trustStore(getTestIgniteInstanceName(2)));

        IgniteEx g2 = startGrid(2);

        assertEquals(3, g2.cluster().nodes().size());

        g2.getOrCreateCache(DEFAULT_CACHE_NAME).put(1, 1);

        assertEquals((Integer)1, g0.<Integer, Integer>cache(DEFAULT_CACHE_NAME).get(1));
    }

    /** Status names the certificate of every transport, a client connector on its own factory included, and fails on an expired one. */
    @Test
    public void testStatus() throws Exception {
        ownClientConnectorFactory = true;

        KeyStore expiredStore = expiredKeys();
        X509Certificate expired = certificateChain(expiredStore)[0];
        String expiredSubj = expired.getSubjectX500Principal().getName();

        TestCertificateAuthority.save(expiredStore, keyStore(getTestIgniteInstanceName(0)));

        IgniteEx g = startGrid(0);

        String res = X.getFullStackTrace(GridTestUtils.assertThrows(log, () -> status(g), Exception.class, null));
        String id = node(g);

        assertContains(log, res, id + ": " + CLIENT_CONNECTOR + "\n    loaded alias=expired-node, subject=" + expiredSubj + ", issuer=");
        assertContains(log, res, id + ": " + COMMUNICATION + ", " + DISCOVERY +
            "\n    loaded alias=expired-node, subject=" + expiredSubj + ", issuer=");
        assertContains(log, res, expired.getIssuerX500Principal().getName());
        assertContains(log, res, "PROBLEM: the loaded certificate is not valid now");
    }

    /** A node that starts on an expired certificate logs a warning. */
    @Test
    public void testExpiredCertificateWarnedAtStart() throws Exception {
        TestCertificateAuthority.save(expiredKeys(), keyStore(getTestIgniteInstanceName(0)));

        LogListener expired = LogListener.matches("The TLS certificate chain in use is not valid now").build();

        nodeLog.registerListener(expired);

        startGrid(0);

        assertTrue(expired.check());
    }

    /** A failed job result still identifies the node by UUID and consistent ID. */
    @Test
    public void testFailedJobNamesNode() {
        GridTestNode n = new GridTestNode(UUID.randomUUID());
        String consistentId = "departed-node";
        String reason = "node left";

        n.setConsistentId(consistentId);

        ComputeJobResult res = Mockito.mock(ComputeJobResult.class);

        Mockito.when(res.getNode()).thenReturn(n);
        Mockito.when(res.getException()).thenReturn(new IgniteException(reason));

        Throwable e = GridTestUtils.assertThrows(log, () -> new SslReloadTask().reduce(List.of(res)).result(), IgniteException.class, null);

        assertContains(log, e.getMessage(), "Failed on 1 node(s):\n" + n.id() + " [consistentId=" + consistentId + "]: " + reason);
    }

    /** A target missing at mapping fails both commands without preventing work on the remaining node. */
    @Test
    public void testUnavailableNodeDoesNotSkipRemainingNode() throws Exception {
        IgniteEx g = startGrid(0);
        UUID unavailable = UUID.randomUUID();

        placeKeys(newKeys);

        String expectedSubj = newCert.getSubjectX500Principal().getName();
        VisorTaskArgument<NoArg> arg = new VisorTaskArgument<>(List.of(g.localNode().id(), unavailable), new NoArg(), false);

        for (Class<? extends AbstractSslTask> task : List.of(SslReloadTask.class, SslStatusTask.class)) {
            Throwable err = GridTestUtils.assertThrows(log, () -> g.compute().execute(task, arg).result(), IgniteException.class, null);

            assertContains(log, err.getMessage(), "Failed on 1 node(s):\n" + unavailable +
                ": node was unavailable to run the command");
            assertContains(log, err.getMessage(), "Succeeded on 1 node(s):\n" + node(g) + ':');
            assertContains(log, err.getMessage(), "subject=" + expectedSubj + ',');
        }

        assertEquals(newCert, certificateAt(g.context().clientListener().port()));
    }

    /** Both commands report that no SSL context factory is configured. */
    @Test
    public void testWithoutSsl() throws Exception {
        IgniteEx g = startGrid(getTestIgniteInstanceName(0), cfg -> cfg.setSslContextFactory(null)
            .setClientConnectorConfiguration(new ClientConnectorConfiguration()));

        assertContains(log, reload(g), node(g) + ": no SSL context factory is configured");
        assertContains(log, status(g), node(g) + ": no SSL context factory is configured");
    }

    /** Checks client authentication on discovery, communication, the client connector and binary REST. */
    private void assertTransportClientAuthentication(IgniteEx node, KeyStore trustedKeys, KeyStore untrustedKeys) throws Exception {
        for (int port : new int[] {
            discoveryPort(node),
            ((TcpCommunicationSpi)node.configuration().getCommunicationSpi()).boundPort(),
            node.context().clientListener().port(),
            node.localNode().attribute(ATTR_REST_TCP_PORT)
        })
            assertClientAuthentication(port, trustedKeys, untrustedKeys, trustBoth);
    }

    /** Opens a new authenticated client connection; its own trust store accepts both test authorities. */
    private void assertClientConnected(IgniteEx node, KeyStore keys) throws Exception {
        SSLContext ctx = TestCertificateAuthority.context(keys, trustBoth);

        try (IgniteClient cli = Ignition.startClient(new ClientConfiguration()
            .setAddresses("127.0.0.1:" + node.context().clientListener().port())
            .setSslMode(SslMode.REQUIRED).setSslContextFactory(() -> ctx)
            .setPartitionAwarenessEnabled(false).setClusterDiscoveryEnabled(false))) {
            cli.cacheNames();
        }
    }

    /** @return Factory reading the stores of the node. */
    private Factory<SSLContext> storeFactory(String igniteInstanceName) {
        return storeFactory(keyStore(igniteInstanceName), trustStore(igniteInstanceName));
    }

    /** @return Factory reading the specified JKS files. */
    private SslContextFactory storeFactory(Path keys, Path trust) {
        SslContextFactory factory = new SslContextFactory();

        factory.setKeyStoreType("JKS");
        factory.setTrustStoreType("JKS");
        factory.setKeyStoreFilePath(keys.toString());
        factory.setKeyStorePassword(TestCertificateAuthority.PWD);
        factory.setTrustStoreFilePath(trust.toString());
        factory.setTrustStorePassword(TestCertificateAuthority.PWD);

        return factory;
    }

    /** */
    private Path keyStore(String igniteInstanceName) {
        return dir.resolve(igniteInstanceName + "-key.jks");
    }

    /** */
    private Path trustStore(String igniteInstanceName) {
        return dir.resolve(igniteInstanceName + "-trust.jks");
    }

    /** @param store Key store to write for every running node. */
    private void placeKeys(KeyStore store) throws Exception {
        for (Ignite node : G.allGrids())
            TestCertificateAuthority.save(store, keyStore(node.name()));
    }

    /** @param store Trust store to write for every running node. */
    private void placeTrust(KeyStore store) throws Exception {
        for (Ignite node : G.allGrids())
            TestCertificateAuthority.save(store, trustStore(node.name()));
    }

    /** @return Certificate served on a fresh connection, using a probe that trusts both authorities. */
    private X509Certificate certificateAt(int port) throws Exception {
        return servedCertificate(TestCertificateAuthority.context(oldKeys, trustBoth), port);
    }

    /** @return Store with an expired leaf issued by the replacement authority. */
    private KeyStore expiredKeys() throws Exception {
        return newCa.keyStoreWithPrivateKey("expired-node", now - 2 * HOUR, now - HOUR);
    }

    /** */
    private void assertReloaded(String res, IgniteEx node, String transports) {
        assertContains(log, res, node(node) + ": reloaded " + transports);
    }

    /** */
    private void assertFailed(String res, IgniteEx node, String transports) {
        assertContains(log, res, node(node) + ": failed on " + transports + " (");
    }

    /** Counts loads and deliberately considers distinct instances equal. */
    private class TestFactory implements Factory<SSLContext> {
        /** Factory calls, including failed loads. */
        private int calls;

        /** Whether loads fail. */
        private boolean fail;

        /** {@inheritDoc} */
        @Override public SSLContext create() {
            calls++;

            if (fail)
                throw new IgniteException("Certificate source is unavailable");

            return storeFactory(getTestIgniteInstanceName(0)).create();
        }

        /** {@inheritDoc} */
        @Override public boolean equals(Object obj) {
            return obj instanceof TestFactory;
        }

        /** {@inheritDoc} */
        @Override public int hashCode() {
            return 0;
        }
    }
}
