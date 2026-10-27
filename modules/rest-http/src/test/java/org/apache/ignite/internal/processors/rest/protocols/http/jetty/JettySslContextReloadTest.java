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
package org.apache.ignite.internal.processors.rest.protocols.http.jetty;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.KeyStore;
import java.security.cert.X509Certificate;
import java.util.Arrays;
import java.util.Collection;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLSocket;
import org.apache.ignite.IgniteCheckedException;
import org.apache.ignite.configuration.ConnectorConfiguration;
import org.apache.ignite.configuration.IgniteConfiguration;
import org.apache.ignite.internal.IgniteEx;
import org.apache.ignite.internal.processors.rest.GridRestProtocol;
import org.apache.ignite.internal.util.typedef.internal.U;
import org.apache.ignite.ssl.SslContextFactory;
import org.apache.ignite.testframework.GridTestUtils;
import org.apache.ignite.testframework.TestCertificateAuthority;
import org.apache.ignite.testframework.junits.common.GridCommonAbstractTest;
import org.eclipse.jetty.server.Server;
import org.eclipse.jetty.server.ServerConnector;
import org.eclipse.jetty.server.SslConnectionFactory;
import org.junit.Test;

import static java.nio.charset.StandardCharsets.US_ASCII;
import static org.apache.ignite.internal.IgniteNodeAttributes.ATTR_REST_JETTY_PORT;
import static org.apache.ignite.internal.ssl.SslContextRegistry.HTTP_REST;
import static org.apache.ignite.ssl.SslTestUtils.assertClientAuthentication;
import static org.apache.ignite.ssl.SslTestUtils.clientContext;
import static org.apache.ignite.ssl.SslTestUtils.reload;
import static org.apache.ignite.ssl.SslTestUtils.reloadFailure;
import static org.apache.ignite.ssl.SslTestUtils.servedCertificate;
import static org.apache.ignite.ssl.SslTestUtils.status;
import static org.apache.ignite.testframework.GridTestUtils.assertContains;
import static org.apache.ignite.testframework.TestCertificateAuthority.PWD;
import static org.apache.ignite.testframework.TestCertificateAuthority.certificateChain;
import static org.apache.ignite.testframework.TestCertificateAuthority.save;
import static org.junit.Assert.assertArrayEquals;

/** Tests HTTP REST certificate reload through {@link ConnectorConfiguration#setHttpSslFactory}. */
public class JettySslContextReloadTest extends GridCommonAbstractTest {
    /** Bounds connection, handshake and response reads on the loopback probes. */
    private static final int SOCKET_TIMEOUT = 30_000;

    /** Jetty configuration with a plain connector and an explicit secure request customizer. */
    private static final String JETTY_HSTS_WITHOUT_HOST_CHECK =
        "modules/rest-http/src/test/resources/jetty-http-customizer.xml";

    /** Jetty configuration with a connector that has an SSL connection factory of its own. */
    private static final String JETTY_SSL = "modules/rest-http/src/test/resources/jetty-ssl.xml";

    /** Jetty configuration with a connector that expects the PROXY protocol before HTTP. */
    private static final String JETTY_PROXY = "modules/rest-http/src/test/resources/jetty-proxy.xml";

    /** Host named by the original server certificate. */
    private static final String OLD_SERVER_HOST = "node01";

    /** Host named by the replacement server certificate. */
    private static final String NEW_SERVER_HOST = "node02";

    /** Key store HTTP REST runs on; replaced on disk to rotate the certificate. */
    private Path keyStore;

    /** Trust store HTTP REST runs on; replaced on disk to rotate the trusted authority. */
    private Path trustStore;

    /** Server key and certificate signed by the old authority. */
    private KeyStore oldServerKeys;

    /** Replacement server key and certificate signed by the new authority. */
    private KeyStore newServerKeys;

    /** Certificate initially served over HTTPS. */
    private X509Certificate oldCert;

    /** Certificate served over HTTPS after reload. */
    private X509Certificate newCert;

    /** Client key and certificate signed by the old authority. */
    private KeyStore oldClientKeys;

    /** Client key and certificate signed by the new authority. */
    private KeyStore newClientKeys;

    /** Trusts only the old authority. */
    private KeyStore oldTrust;

    /** Trusts only the new authority. */
    private KeyStore newTrust;

    /** Lets probes trust the server before and after rotation. */
    private KeyStore bothTrust;

    /** Jetty configuration, {@code null} for the built-in one. */
    private String jettyPath;

    /** Protocols of the factory, {@code null} for the defaults. */
    private String[] protocols;

    /** Cipher suites of the factory, {@code null} for the defaults. */
    private String[] cipherSuites;

    /** Whether HTTP REST requires a certificate from clients. */
    private boolean clientAuth;

    /** Whether the node starts without {@code httpSslFactory}. */
    private boolean noFactory;

    /** {@inheritDoc} */
    @Override protected IgniteConfiguration getConfiguration(String igniteInstanceName) throws Exception {
        SslContextFactory factory = new SslContextFactory();

        factory.setKeyStoreType("JKS");
        factory.setKeyStoreFilePath(keyStore.toString());
        factory.setKeyStorePassword(PWD);
        factory.setTrustStoreType("JKS");
        factory.setTrustStoreFilePath(trustStore.toString());
        factory.setTrustStorePassword(PWD);

        if (protocols != null)
            factory.setProtocols(protocols);

        if (cipherSuites != null)
            factory.setCipherSuites(cipherSuites);

        return super.getConfiguration(igniteInstanceName)
            .setConnectorConfiguration(new ConnectorConfiguration().setJettyPath(jettyPath).setHttpSslFactory(noFactory ? null : factory)
                .setHttpSslClientAuth(clientAuth));
    }

    /** {@inheritDoc} */
    @Override protected void beforeTest() throws Exception {
        TestCertificateAuthority oldCa = new TestCertificateAuthority("old-http-ca");
        TestCertificateAuthority newCa = new TestCertificateAuthority("new-http-ca");

        oldServerKeys = oldCa.keyStoreWithPrivateKey(OLD_SERVER_HOST);
        newServerKeys = newCa.keyStoreWithPrivateKey(NEW_SERVER_HOST);
        oldCert = certificateChain(oldServerKeys)[0];
        newCert = certificateChain(newServerKeys)[0];
        oldClientKeys = oldCa.keyStoreWithPrivateKey();
        newClientKeys = newCa.keyStoreWithPrivateKey();
        oldTrust = oldCa.trustStore();
        newTrust = newCa.trustStore();
        bothTrust = TestCertificateAuthority.trustStore(oldCa, newCa);

        keyStore = Files.createTempFile("ignite-jetty-ssl-reload-", ".jks");
        trustStore = Files.createTempFile("ignite-jetty-ssl-trust-", ".jks");

        save(oldServerKeys, keyStore);
        save(bothTrust, trustStore);
    }

    /** {@inheritDoc} */
    @Override protected void afterTest() throws Exception {
        stopAllGrids();

        if (keyStore != null)
            Files.deleteIfExists(keyStore);

        if (trustStore != null)
            Files.deleteIfExists(trustStore);
    }

    /**
     * New HTTP REST connections use the reloaded certificate without resuming old TLS sessions. Existing connections stay open,
     * and clients without certificates can connect when client authentication is disabled. A failed reload keeps the last
     * working context.
     */
    @Test
    public void testReload() throws Exception {
        clientAuth = false;

        IgniteEx g = startGrid(0);

        SSLContext client = clientTrustingBothAuthorities();

        try (SSLSocket open = socket(client, port(g))) {
            assertEquals(oldCert, serverCertificate(open));

            save(newServerKeys, keyStore);

            assertContains(log, reload(g), ": reloaded " + HTTP_REST);
            assertVersionResponse(open, OLD_SERVER_HOST);
        }

        try (SSLSocket after = socket(client, port(g))) {
            assertEquals(newCert, serverCertificate(after));

            assertVersionResponse(after, NEW_SERVER_HOST);
        }

        try (SSLSocket byIp = socket(client, port(g))) {
            assertVersionResponse(byIp, "127.0.0.1");
        }

        try (SSLSocket anonymous = socket(clientContext(null, bothTrust), port(g))) {
            assertVersionResponse(anonymous, NEW_SERVER_HOST);
        }

        assertContains(log, status(g),
            "loaded alias=" + NEW_SERVER_HOST + ", subject=" + newCert.getSubjectX500Principal().getName() + ',');

        Files.write(keyStore, "not a key store".getBytes());

        assertContains(log, reloadFailure(g), "failed on " + HTTP_REST);
        assertEquals(newCert, servedCertificate(clientTrustingBothAuthorities(), port(g)));
    }

    /** Factory TLS settings survive reload while Jetty's cipher exclusions still apply. */
    @Test
    public void testFactoryProtocolsAndCipherSuites() throws Exception {
        String[] excludePatterns = new org.eclipse.jetty.util.ssl.SslContextFactory.Server().getExcludeCipherSuites();

        String excluded = Arrays.stream(clientTrustingBothAuthorities().getSupportedSSLParameters().getCipherSuites())
            .filter(cipher -> Arrays.stream(excludePatterns).anyMatch(cipher::matches))
            .findFirst().orElseThrow(() -> new AssertionError("The JVM must support a cipher suite excluded by Jetty"));

        String protocol = "TLSv1.2";
        String enabledCipher = "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256";

        protocols = new String[] {protocol};
        cipherSuites = new String[] {enabledCipher, excluded};

        IgniteEx g = startGrid(0);

        org.eclipse.jetty.util.ssl.SslContextFactory jetty = jettySslFactory(g);

        // Check the engines directly: JVM handshake policy can independently reject legacy cipher suites.
        assertArrayEquals(cipherSuites, jetty.getSslContext().createSSLEngine().getEnabledCipherSuites());
        assertArrayEquals(new String[] {enabledCipher}, jetty.newSSLEngine().getEnabledCipherSuites());

        try (SSLSocket sock = socket(clientTrustingBothAuthorities(), port(g))) {
            assertEquals(oldCert, serverCertificate(sock));
            assertEquals(protocol, sock.getSession().getProtocol());
            assertEquals(enabledCipher, sock.getSession().getCipherSuite());
        }

        save(newServerKeys, keyStore);

        assertContains(log, reload(g), ": reloaded " + HTTP_REST);

        assertArrayEquals(cipherSuites, jetty.getSslContext().createSSLEngine().getEnabledCipherSuites());
        assertArrayEquals(new String[] {enabledCipher}, jetty.newSSLEngine().getEnabledCipherSuites());

        try (SSLSocket sock = socket(clientTrustingBothAuthorities(), port(g))) {
            assertEquals(newCert, serverCertificate(sock));
            assertEquals(protocol, sock.getSession().getProtocol());
            assertEquals(enabledCipher, sock.getSession().getCipherSuite());
        }
    }

    /** A connector from a Jetty configuration file gets TLS and keeps its HSTS and host-check settings. */
    @Test
    public void testJettyConnectorFromFileGetsTls() throws Exception {
        jettyPath = JETTY_HSTS_WITHOUT_HOST_CHECK;

        IgniteEx g = startGrid(0);

        try (SSLSocket sock = socket(clientTrustingBothAuthorities(), port(g))) {
            assertEquals(oldCert, serverCertificate(sock));

            String headers = assertVersionResponse(sock, "localhost");

            assertTrue("HTTP REST must preserve the configured HSTS header: " + headers,
                headers.lines().anyMatch("Strict-Transport-Security: max-age=86400"::equalsIgnoreCase));
        }

        try (SSLSocket byIp = socket(clientTrustingBothAuthorities(), port(g))) {
            assertVersionResponse(byIp, "127.0.0.1");
        }
    }

    /** A node does not start when the connector in its Jetty configuration has an SSL connection factory of its own. */
    @Test
    public void testJettySslConnectionFactoryRefused() {
        jettyPath = JETTY_SSL;

        GridTestUtils.assertThrowsAnyCause(log, () -> startGrid(0), IgniteCheckedException.class,
            "must have no SSL connection factory of its own");
    }

    /** TLS configured in Jetty XML still works without a managed factory and stays outside the reload commands. */
    @Test
    public void testLegacyJettyTls() throws Exception {
        jettyPath = JETTY_SSL;
        noFactory = true;

        IgniteEx g = startGrid(0);

        // Keep the original XML and its checked-in stores as the legacy configuration compatibility check.
        try (SSLSocket sock = socket(GridTestUtils.sslTrustedFactory("node01", "trustboth").create(), port(g))) {
            assertEquals("CN=node01", serverCertificate(sock).getSubjectX500Principal().getName());
            assertVersionResponse(sock, "node01");
        }

        assertContains(log, status(g), "no SSL context factory is configured");
        assertContains(log, reload(g), "no SSL context factory is configured");
    }

    /** A node does not start when the connector in its Jetty configuration expects the PROXY protocol: TLS in front would break it. */
    @Test
    public void testJettyProxyProtocolRefused() {
        jettyPath = JETTY_PROXY;

        GridTestUtils.assertThrowsAnyCause(log, () -> startGrid(0), IgniteCheckedException.class, "with no PROXY protocol in front");
    }

    /** A node does not start with client authentication on but no factory: the setting would do nothing. */
    @Test
    public void testClientAuthWithoutFactoryRefused() {
        clientAuth = true;
        noFactory = true;

        GridTestUtils.assertThrowsAnyCause(log, () -> startGrid(0), IgniteCheckedException.class,
            "applies only to TLS set up with httpSslFactory");
    }

    /** Client authentication uses the reloaded trust store and remains required after replacing the server certificate. */
    @Test
    public void testClientAuth() throws Exception {
        clientAuth = true;

        save(oldTrust, trustStore);

        IgniteEx g = startGrid(0);
        int port = port(g);

        assertClientAuthentication(port, oldClientKeys, newClientKeys, bothTrust);

        try (SSLSocket sock = socket(clientContext(oldClientKeys, bothTrust), port)) {
            assertVersionResponse(sock, OLD_SERVER_HOST);
        }

        save(newServerKeys, keyStore);
        save(newTrust, trustStore);

        assertContains(log, reload(g), ": reloaded " + HTTP_REST);

        assertClientAuthentication(port, newClientKeys, oldClientKeys, bothTrust);

        try (SSLSocket sock = socket(clientContext(newClientKeys, bothTrust), port)) {
            assertEquals(newCert, serverCertificate(sock));
            assertVersionResponse(sock, NEW_SERVER_HOST);
        }
    }

    /** @return SSL factory used by the running Jetty connector. */
    private static org.eclipse.jetty.util.ssl.SslContextFactory jettySslFactory(IgniteEx g) {
        Collection<GridRestProtocol> protos = GridTestUtils.getFieldValue(g.context().rest(), "protos");

        GridRestProtocol jetty = protos.stream().filter(GridJettyRestProtocol.class::isInstance).findFirst().orElseThrow();
        Server srv = GridTestUtils.getFieldValue(jetty, "httpSrv");

        return ((ServerConnector)srv.getConnectors()[0]).getConnectionFactory(SslConnectionFactory.class).getSslContextFactory();
    }

    /** @return A fresh client context that trusts both server authorities. */
    private SSLContext clientTrustingBothAuthorities() throws Exception {
        return clientContext(oldClientKeys, bothTrust);
    }

    /** @return HTTP REST port of the node. */
    private static int port(IgniteEx g) {
        return g.localNode().attribute(ATTR_REST_JETTY_PORT);
    }

    /**
     * @param ctx Context to connect with.
     * @param port Port to connect to.
     * @return TLS socket to the port.
     */
    private static SSLSocket socket(SSLContext ctx, int port) throws IOException {
        SSLSocket sock = (SSLSocket)ctx.getSocketFactory().createSocket();

        try {
            sock.connect(new InetSocketAddress(InetAddress.getLoopbackAddress(), port), SOCKET_TIMEOUT);
            sock.setSoTimeout(SOCKET_TIMEOUT);

            return sock;
        }
        catch (IOException | RuntimeException e) {
            U.closeQuiet(sock);

            throw e;
        }
    }

    /** @return Certificate the server presents on the connection. */
    private static X509Certificate serverCertificate(SSLSocket sock) throws IOException {
        sock.startHandshake();

        return (X509Certificate)sock.getSession().getPeerCertificates()[0];
    }

    /**
     * Checks that HTTP REST answers a version request successfully.
     *
     * @param sock Connection.
     * @param host Host to ask for.
     * @return Response headers, one per line.
     */
    private static String assertVersionResponse(SSLSocket sock, String host) throws IOException {
        String req = "GET /ignite?cmd=version HTTP/1.1\r\nHost: " + host + "\r\nConnection: close\r\n\r\n";

        sock.getOutputStream().write(req.getBytes(US_ASCII));

        BufferedReader res = new BufferedReader(new InputStreamReader(sock.getInputStream(), US_ASCII));

        String status = res.readLine();

        assertNotNull("HTTP REST must answer a version request", status);
        assertTrue("Unexpected HTTP status for Host " + host + ": " + status, status.startsWith("HTTP/1.1 200"));

        StringBuilder headers = new StringBuilder();

        for (String line = res.readLine(); line != null && !line.isEmpty(); line = res.readLine())
            headers.append(line).append('\n');

        return headers.toString();
    }
}
