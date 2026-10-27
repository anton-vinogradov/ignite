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

import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.security.KeyStore;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.util.Arrays;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.atomic.AtomicBoolean;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLSocket;
import org.apache.ignite.IgniteException;
import org.apache.ignite.configuration.ConnectorConfiguration;
import org.apache.ignite.configuration.IgniteConfiguration;
import org.apache.ignite.internal.IgniteEx;
import org.apache.ignite.ssl.SslBundle;
import org.apache.ignite.ssl.SslContextFactory;
import org.apache.ignite.testframework.TestCertificateAuthority;
import org.apache.ignite.testframework.junits.common.GridCommonAbstractTest;
import org.junit.Test;

import static java.nio.charset.StandardCharsets.US_ASCII;
import static java.util.concurrent.TimeUnit.HOURS;
import static java.util.concurrent.TimeUnit.MINUTES;
import static org.apache.ignite.internal.IgniteNodeAttributes.ATTR_REST_JETTY_PORT;
import static org.apache.ignite.internal.ssl.SslContextRegistry.HTTP_REST;
import static org.apache.ignite.testframework.GridTestUtils.waitForCondition;
import static org.apache.ignite.testframework.TestCertificateAuthority.certificateChain;

/** Tests automatic certificate renewal for HTTPS through the managed HTTP REST factory. */
public class JettySslContextRenewalTest extends GridCommonAbstractTest {
    /** Factory used only by HTTP REST. */
    private SslContextFactory factory;

    /** {@inheritDoc} */
    @Override protected IgniteConfiguration getConfiguration(String igniteInstanceName) throws Exception {
        return super.getConfiguration(igniteInstanceName)
            .setConnectorConfiguration(new ConnectorConfiguration().setHttpSslFactory(factory));
    }

    /** {@inheritDoc} */
    @Override protected void afterTest() {
        stopAllGrids();
    }

    /** Automatic renewal installs a later-expiring chain that new HTTPS connections receive. */
    @Test
    public void testAutomaticRenewal() throws Exception {
        TestCertificateAuthority ca = new TestCertificateAuthority("http-renewal-ca");
        long now = System.currentTimeMillis();
        long lifetime = HOURS.toMillis(1);
        long timeLeft = MINUTES.toMillis(5);
        long renewalWindow = 2 * timeLeft;
        long initExpiry = now + timeLeft;
        String keyAlias = "https-key";
        KeyStore initKeys = ca.keyStoreWithPrivateKey(keyAlias, initExpiry - lifetime, initExpiry);
        KeyStore renewed = ca.keyStoreWithPrivateKey(keyAlias, now, now + lifetime);
        X509Certificate replacement = certificateChain(renewed)[0];
        KeyStore trust = ca.trustStore();
        CountDownLatch replacementReady = new CountDownLatch(1);
        AtomicBoolean first = new AtomicBoolean(true);

        factory = new SslContextFactory() {
            @Override public SslBundle createSslBundle() {
                boolean initLoad = first.getAndSet(false);

                try {
                    if (!initLoad)
                        replacementReady.await();

                    return TestCertificateAuthority.bundle(initLoad ? initKeys : renewed, trust);
                }
                catch (Exception e) {
                    throw new IgniteException(e);
                }
            }
        };

        factory.setRenewalEnabled(true);
        factory.setRenewBeforeFraction((double)renewalWindow / lifetime);

        try {
            IgniteEx g = startGrid(0);
            int port = g.localNode().attribute(ATTR_REST_JETTY_PORT);
            SslContextProvider provider = g.context().sslContexts().providers().stream()
                .filter(p -> p.transports().contains(HTTP_REST)).findFirst().orElseThrow();

            X509Certificate[] before = probe(port, trust);

            assertEquals(certificateChain(initKeys)[0], before[0]);

            replacementReady.countDown();

            assertTrue("HTTP REST must renew automatically",
                waitForCondition(() -> replacement.equals(provider.certificateChains().get(keyAlias).get(0)), 10_000));

            X509Certificate[] after = probe(port, trust);

            assertEquals(replacement, after[0]);
            assertTrue("The chain served over HTTPS must expire later",
                SslCertificates.chainNotAfter(Arrays.asList(after)) > SslCertificates.chainNotAfter(Arrays.asList(before)));
        }
        finally {
            replacementReady.countDown();
        }
    }

    /**
     * Makes a version request with a fresh client context so that the TLS session cannot resume.
     *
     * @param port HTTP REST port.
     * @param trust Trusted authority.
     * @return Certificate chain served over HTTPS.
     */
    private X509Certificate[] probe(int port, KeyStore trust) throws Exception {
        int timeout = 30_000;
        SSLContext client = SSLContext.getInstance("TLS");

        client.init(null, TestCertificateAuthority.trustManagers(trust), null);

        try (SSLSocket sock = (SSLSocket)client.getSocketFactory().createSocket()) {
            sock.connect(new InetSocketAddress(InetAddress.getLoopbackAddress(), port), timeout);
            sock.setSoTimeout(timeout);
            sock.startHandshake();

            Certificate[] chain = sock.getSession().getPeerCertificates();

            sock.getOutputStream().write(
                "GET /ignite?cmd=version HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n".getBytes(US_ASCII));

            String status = new BufferedReader(new InputStreamReader(sock.getInputStream(), US_ASCII)).readLine();

            assertNotNull("HTTP REST must answer the version request", status);
            assertTrue("Unexpected HTTP status: " + status, status.startsWith("HTTP/1.1 200"));

            return Arrays.copyOf(chain, chain.length, X509Certificate[].class);
        }
    }
}
