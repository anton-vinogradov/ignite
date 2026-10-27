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
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.KeyStore;
import java.security.cert.X509Certificate;
import java.time.Instant;
import java.util.Iterator;
import java.util.List;
import java.util.Map;
import java.util.concurrent.Callable;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.RunnableScheduledFuture;
import java.util.concurrent.ScheduledFuture;
import java.util.concurrent.ScheduledThreadPoolExecutor;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicLong;
import java.util.concurrent.atomic.AtomicReference;
import java.util.stream.Collectors;
import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLException;
import javax.net.ssl.TrustManager;
import org.apache.ignite.IgniteCheckedException;
import org.apache.ignite.IgniteException;
import org.apache.ignite.configuration.ClientConnectorConfiguration;
import org.apache.ignite.internal.IgniteEx;
import org.apache.ignite.internal.IgniteInternalFuture;
import org.apache.ignite.internal.IgniteInterruptedCheckedException;
import org.apache.ignite.internal.thread.context.OperationContext;
import org.apache.ignite.internal.thread.context.OperationContextAttribute;
import org.apache.ignite.internal.thread.context.Scope;
import org.apache.ignite.internal.util.typedef.internal.U;
import org.apache.ignite.spi.metric.IntMetric;
import org.apache.ignite.spi.metric.Metric;
import org.apache.ignite.spi.metric.ReadOnlyMetricRegistry;
import org.apache.ignite.ssl.AbstractSslContextFactory;
import org.apache.ignite.ssl.KeyMaterial;
import org.apache.ignite.ssl.SslBundle;
import org.apache.ignite.ssl.SslContextFactory;
import org.apache.ignite.testframework.GridTestUtils;
import org.apache.ignite.testframework.MemorizingAppender;
import org.apache.ignite.testframework.TestCertificateAuthority;
import org.apache.ignite.testframework.junits.common.GridCommonAbstractTest;
import org.apache.logging.log4j.Level;
import org.apache.logging.log4j.core.LogEvent;
import org.jetbrains.annotations.Nullable;
import org.junit.Test;

import static org.apache.ignite.internal.ssl.SslContextRegistry.CLIENT_CONNECTOR;
import static org.apache.ignite.internal.ssl.SslContextRegistry.COMMUNICATION;
import static org.apache.ignite.internal.ssl.SslContextRegistry.DISCOVERY;
import static org.apache.ignite.ssl.AbstractSslContextFactory.DFLT_RENEW_BEFORE_FRACTION;
import static org.apache.ignite.ssl.SslTestUtils.discoveryPort;
import static org.apache.ignite.ssl.SslTestUtils.reload;
import static org.apache.ignite.ssl.SslTestUtils.servedCertificate;
import static org.apache.ignite.ssl.SslTestUtils.status;
import static org.apache.ignite.testframework.GridTestUtils.assertContains;
import static org.apache.ignite.testframework.GridTestUtils.assertThrowsWithCause;
import static org.apache.ignite.testframework.GridTestUtils.waitForCondition;

/** Tests that a node renews the certificates of a factory with renewal enabled before they expire. */
public class SslRenewalTest extends GridCommonAbstractTest {
    /** */
    private static final long SECOND = 1_000L;

    /** */
    private static final long MINUTE = 60 * SECOND;

    /** */
    private static final long HOUR = 60 * MINUTE;

    /** Tolerance in milliseconds for differences in clock precision when checking scheduled times. */
    private static final long CLOCK_SLACK = 50;

    /** Failure of an issuer that cannot be reached. */
    private static final String ISSUER_DOWN = "Issuer is unavailable";

    /** What the node logs while the factory returns the certificates in use. */
    private static final String WAITING = "The SSL context factory has no newer TLS certificates yet, the ones in use stay";

    /** Transports that share the node-wide SSL context, as the log lists them. */
    private static final String NODE_TRANSPORTS = "transports=communication, discovery";

    /** Operation context attribute standing for whoever runs a reload. */
    private static final OperationContextAttribute<String> OPERATOR = OperationContextAttribute.newInstance();

    /** Default certificate authority for the tests. */
    private TestCertificateAuthority ca;

    /** What the renewals log, with the levels. */
    private final MemorizingAppender appender = new MemorizingAppender();

    /** {@inheritDoc} */
    @Override protected void beforeTest() throws Exception {
        ca = new TestCertificateAuthority("renewalca");

        appender.start();
        appender.installSelfOn(SslRenewal.class);

        pauses(100, 1_000);
    }

    /** {@inheritDoc} */
    @Override protected void afterTest() {
        try {
            stopAllGrids();
        }
        finally {
            appender.removeSelfFrom(SslRenewal.class);
            appender.stop();

            pauses(MINUTE, HOUR);
        }
    }

    /** Renewal starts within its window, serves the new certificate, schedules its next renewal and stops with the node. */
    @Test
    public void testRenewsBeforeExpiry() throws Exception {
        long now = System.currentTimeMillis();
        long renewalDelay = 5 * SECOND;
        long lifetime = 5 * MINUTE;
        long window = (long)(lifetime * DFLT_RENEW_BEFORE_FRACTION);
        AtomicLong due = new AtomicLong();

        Issuer issuer = new Issuer(() -> {
            long issued = System.currentTimeMillis();

            // Match certificate timestamp precision while keeping the renewal window ahead of this first load.
            long notAfter = (issued + renewalDelay + window) / SECOND * SECOND;
            long notBefore = notAfter - lifetime;

            due.set(notAfter - window);

            return ca.keyStoreWithPrivateKey(notBefore, notAfter);
        }, fresh(HOUR));

        IgniteEx g = startNode(issuer);

        assertTrue(waitForCondition(() -> automaticRenewals("transports=" + COMMUNICATION) == 1, 30_000));

        assertTrue("The certificate must have been renewed", chainNotAfter(g) > now + 30 * MINUTE);
        assertTrue("The renewal must not come before the window opens",
            issuer.calls.get(1).time >= due.get() - CLOCK_SLACK);
        assertEquals("New connections must get the renewed certificate", chainNotAfter(g),
            servedCertificate(probe(), discoveryPort(g)).getNotAfter().getTime());

        long next = dueTime(g);

        assertTrue(waitForCondition(() -> nextRenewalTime(g) == next, 10_000));

        assertTrue("A node renewing certificates must run the renewal thread", renewalThreadAlive(g.name()));

        stopGrid(0);

        assertTrue("The renewal thread must stop with the node", waitForCondition(() -> !renewalThreadAlive(g.name()), 10_000));
    }

    /** Plans renewal from the authority's expiry when it expires before the leaf certificate. */
    @Test
    public void testRenewalPlannedBeforeAuthorityExpiry() throws Exception {
        long now = System.currentTimeMillis() / SECOND * SECOND;
        long notBefore = now - HOUR;
        long authorityExpiry = now + HOUR;

        ca = new TestCertificateAuthority("renewalca", notBefore - HOUR, authorityExpiry);

        KeyStore keys = ca.keyStoreWithPrivateKey(notBefore, authorityExpiry + HOUR);

        long due = authorityExpiry - (long)((authorityExpiry - notBefore) * DFLT_RENEW_BEFORE_FRACTION);

        IgniteEx g = startNode(new Issuer(() -> keys));

        assertTrue("Renewal must be planned by the authority's expiry",
            waitForCondition(() -> nextRenewalTime(g) == due, 10_000));
    }

    /** Every private key affects the renewal date; equal expiries use the earliest leaf validity start. */
    @Test
    public void testRenewalPlannedByEarliestKey() throws Exception {
        long now = System.currentTimeMillis() / SECOND * SECOND;
        long firstExpiry = now + 2 * HOUR;
        long secondNotBefore = now - 2 * HOUR;
        String firstAlias = "first";
        String secondAlias = "second";

        for (long secondExpiry : List.of(now + HOUR, firstExpiry)) {
            KeyStore keys = ca.keyStoreWithPrivateKey(firstAlias, now - HOUR, firstExpiry);

            addKey(keys, ca.keyStoreWithPrivateKey(secondAlias, secondNotBefore, secondExpiry), secondAlias);

            Issuer issuer = new Issuer(() -> keys);
            SslContextProvider p = new SslContextProvider(issuer);
            ScheduledThreadPoolExecutor exec = new ScheduledThreadPoolExecutor(1);

            try {
                p.startRenewal(exec, log);

                exec.submit(() -> {}).get(10, TimeUnit.SECONDS);

                long expected = secondExpiry - (long)((secondExpiry - secondNotBefore) * DFLT_RENEW_BEFORE_FRACTION);

                assertEquals(expected, p.nextRenewalTime());
                assertEquals(2, p.certificateChains().size());
                assertEquals(1, issuer.calls.size());
            }
            finally {
                exec.shutdownNow();

                assertTrue(exec.awaitTermination(10, TimeUnit.SECONDS));
            }
        }
    }

    /** Rotation replaces all chains together and does not require old and new private-key aliases to match. */
    @Test
    public void testAllKeysRenewedTogether() throws Exception {
        long now = System.currentTimeMillis() / SECOND * SECOND;
        long originalExpiry = now + HOUR;
        long replacementExpiry = now + 2 * HOUR;
        String firstAlias = "first";
        String secondAlias = "second";
        String replacementAlias = "replacement";
        String otherReplacementAlias = "other-replacement";

        KeyStore original = ca.keyStoreWithPrivateKey(firstAlias, now - HOUR, originalExpiry);
        KeyStore replacement = ca.keyStoreWithPrivateKey(replacementAlias, now - HOUR, replacementExpiry);

        addKey(original, ca.keyStoreWithPrivateKey(secondAlias, now - HOUR, originalExpiry), secondAlias);
        addKey(replacement, ca.keyStoreWithPrivateKey(otherReplacementAlias, now - HOUR, replacementExpiry), otherReplacementAlias);

        SslContextProvider p = new SslContextProvider(new Issuer(() -> original, () -> original, () -> replacement));
        SslBundle before = p.bundle();

        assertNull(p.renew(before.context()));
        assertEquals(1, p.renewalFailures());

        SslBundle renewed = p.renew(before.context());

        assertSame(renewed, p.bundle());
        assertNotSame(before.context(), renewed.context());
        assertEquals(2, renewed.certificateChains().size());
        assertEquals(replacement.getCertificate(replacementAlias), renewed.certificateChains().get(replacementAlias).get(0));
        assertEquals(replacement.getCertificate(otherReplacementAlias), renewed.certificateChains().get(otherReplacementAlias).get(0));
        assertEquals(replacementExpiry, SslCertificates.chainNotAfter(SslContextProvider.renewalChain(renewed)));
        assertEquals(0, p.renewalFailures());
    }

    /** A replacement cannot leave another key at the original earliest expiry. */
    @Test
    public void testPartialRotationDoesNotAdvanceEarliestExpiry() throws Exception {
        long now = System.currentTimeMillis() / SECOND * SECOND;
        long originalExpiry = now + HOUR;
        String firstAlias = "first";
        String unchangedAlias = "unchanged";
        KeyStore unchanged = ca.keyStoreWithPrivateKey(unchangedAlias, now - HOUR, originalExpiry);
        KeyStore original = ca.keyStoreWithPrivateKey(firstAlias, now - HOUR, originalExpiry);
        KeyStore replacement = ca.keyStoreWithPrivateKey(firstAlias, now - HOUR, originalExpiry + HOUR);

        addKey(original, unchanged, unchangedAlias);
        addKey(replacement, unchanged, unchangedAlias);

        SslContextProvider p = new SslContextProvider(new Issuer(() -> original, () -> replacement));

        assertRenewalRejected(p, "The new certificate chains expire no later than the ones in use");
    }

    /** Every candidate chain must be valid even when another key has been renewed successfully. */
    @Test
    public void testInvalidSecondaryChainRejected() throws Exception {
        long now = System.currentTimeMillis();
        String validAlias = "first";
        String invalidAlias = "second";
        KeyStore original = ca.keyStoreWithPrivateKey(validAlias, now - HOUR, now + HOUR);
        KeyStore replacement = ca.keyStoreWithPrivateKey(validAlias, now - HOUR, now + 2 * HOUR);

        addKey(replacement, ca.keyStoreWithPrivateKey(invalidAlias, now + HOUR, now + 3 * HOUR), invalidAlias);

        SslContextProvider p = new SslContextProvider(new Issuer(() -> original, () -> replacement));

        assertRenewalRejected(p, "The new certificate chain is not valid now [alias=" + invalidAlias);
    }

    /** With less than half of the window left, failures must be logged as errors and counted, and the status must show the next attempt. */
    @Test
    public void testLateFailureLoggedAsError() throws Exception {
        long now = System.currentTimeMillis();
        long lifetime = HOUR;
        long window = (long)(lifetime * DFLT_RENEW_BEFORE_FRACTION);
        long timeLeft = window / 4;
        long notAfter = now + timeLeft;

        Issuer issuer = new Issuer(valid(notAfter - lifetime, notAfter), failure());

        IgniteEx g = startNode(issuer);

        String late = "Failed to reload TLS certificates, the ones in use stay and expire soon [" + NODE_TRANSPORTS +
            ", initiator=automatic renewal, reason=" + ISSUER_DOWN;

        assertTrue(waitForCondition(() -> logged(Level.ERROR, late) >= 2, 30_000));

        assertTrue(metrics(g).<IntMetric>findMetric("ConsecutiveRenewalFailures").value() >= 2);
        assertContains(log, status(g), "next automatic renewal at");
    }

    /** A certificate that expires no later than the one in use must not be put in use. */
    @Test
    public void testRenewalNotMovingExpiryRejected() throws Exception {
        long now = System.currentTimeMillis();
        long notBefore = now - HOUR;
        long notAfter = now + HOUR;
        KeyStore startupKeys = ca.keyStoreWithPrivateKey("startup", notBefore, notAfter);
        KeyStore replacement = ca.keyStoreWithPrivateKey("replacement", notBefore, notAfter);

        SslContextProvider p = new SslContextProvider(new Issuer(() -> startupKeys, () -> replacement));

        assertRenewalRejected(p, "The new certificate chains expire no later than the ones in use");
    }

    /** An automatic renewal preserves connections to a peer whose certificate and different authority stay unchanged. */
    @Test
    public void testRenewalWithDifferentAuthorities() throws Exception {
        assertNodesReconnectAfterRotationAndRestart(new TestCertificateAuthority("peerca"));
    }

    /** An expired certificate can be replaced with a valid chain from another authority. */
    @Test
    public void testExpiredCertificateRenewed() throws Exception {
        long now = System.currentTimeMillis();
        String authorityName = "otherca";

        TestCertificateAuthority other = new TestCertificateAuthority(authorityName);

        Issuer issuer = new Issuer(valid(now - 2 * HOUR, now - HOUR), () -> other.keyStoreWithPrivateKey(now, now + HOUR));

        SslContextProvider p = new SslContextProvider(issuer);

        p.addTransport(COMMUNICATION);

        issuer.trust = other.trustStore();

        assertNotNull(p.renew(p.context()));
        assertEquals("CN=" + authorityName, certificate(p).getIssuerX500Principal().getName());
    }

    /** A renewal logs the certificate it installed even if a manual reload replaces it before the log is written. */
    @Test
    public void testRenewalLogsAppliedCertificate() throws Exception {
        long now = System.currentTimeMillis();
        long lifetime = HOUR;
        long window = (long)(lifetime * DFLT_RENEW_BEFORE_FRACTION);
        long timeLeft = 3 * window / 4;
        long notAfter = now + timeLeft;
        String renewedName = "renewed";
        String manualName = "manual";

        Issuer issuer = new Issuer(valid(notAfter - lifetime, notAfter),
            () -> ca.keyStoreWithPrivateKey(renewedName, now, now + HOUR),
            () -> ca.keyStoreWithPrivateKey(manualName, now, now + 2 * HOUR));

        SslContextProvider p = new SslContextProvider(issuer) {
            @Override SslBundle renew(SSLContext expected) throws IgniteCheckedException {
                SslBundle renewed = super.renew(expected);

                if (renewed != null)
                    super.reload();

                return renewed;
            }
        };

        p.addTransport(COMMUNICATION);

        ScheduledThreadPoolExecutor exec = new ScheduledThreadPoolExecutor(1);

        try {
            p.startRenewal(exec, log.getLogger(SslRenewal.class));

            assertTrue(waitForCondition(() -> automaticRenewals("transports=" + COMMUNICATION) == 1, 10_000));
            assertEquals("CN=" + manualName, certificate(p).getSubjectX500Principal().getName());
            assertEquals(1, logged(Level.INFO,
                "TLS certificates reloaded [transports=" + COMMUNICATION + ", alias=" + renewedName + ", subject=CN=" + renewedName + ','));
        }
        finally {
            exec.shutdownNow();

            assertTrue(exec.awaitTermination(10, TimeUnit.SECONDS));
        }
    }

    /** A certificate that is not valid yet must not be put in use. */
    @Test
    public void testRenewalNotValidYetRejected() {
        long now = System.currentTimeMillis();

        SslContextProvider p = new SslContextProvider(new Issuer(fresh(HOUR), valid(now + 10 * MINUTE, now + 2 * HOUR)));

        assertRenewalRejected(p, "The new certificate chain is not valid now");
    }

    /** A renewal planned before a reload must not ask for a certificate or replace the one the reload has put in use. */
    @Test
    public void testRenewalPlannedBeforeReloadSuperseded() throws Exception {
        KeyStore inUse = ca.keyStoreWithPrivateKey();

        Issuer issuer = new Issuer(() -> inUse);

        SslContextProvider p = new SslContextProvider(issuer);

        SSLContext planned = p.context();

        assertNull(p.renew(planned));
        assertEquals(1, p.renewalFailures());

        p.reload();

        SSLContext reloaded = p.context();
        int callsAfterReload = issuer.calls.size();

        assertNotSame(planned, reloaded);

        assertNull(p.renew(planned));
        assertEquals(1, p.renewalFailures());
        assertSame(reloaded, p.context());
        assertEquals("The superseded renewal must not ask for another certificate", callsAfterReload, issuer.calls.size());
    }

    /** A reload during renewal planning prevents the outdated attempt from calling the factory or replacing the new context. */
    @Test
    public void testReloadDuringRenewalPlanning() throws Exception {
        long now = System.currentTimeMillis();
        long lifetime = HOUR;
        long window = (long)(lifetime * DFLT_RENEW_BEFORE_FRACTION);
        long timeLeft = 3 * window / 4;
        long notAfter = now + timeLeft;

        Issuer issuer = new Issuer(valid(notAfter - lifetime, notAfter), fresh(2 * HOUR), fresh(3 * HOUR));

        CountDownLatch planRead = new CountDownLatch(1);
        CountDownLatch continuePlanning = new CountDownLatch(1);
        CountDownLatch reloaded = new CountDownLatch(1);
        CountDownLatch allowReplan = new CountDownLatch(1);
        CountDownLatch attemptStarted = new CountDownLatch(1);

        AtomicBoolean firstPlan = new AtomicBoolean(true);
        AtomicReference<Thread> reloadThread = new AtomicReference<>();

        SslContextProvider p = new SslContextProvider(issuer) {
            @Override public ReloadOutcome reloadOutcome() {
                ReloadOutcome outcome = super.reloadOutcome();

                if (firstPlan.getAndSet(false)) {
                    planRead.countDown();

                    U.awaitQuiet(continuePlanning);
                }

                return outcome;
            }

            @Override SslBundle renew(SSLContext expected) throws IgniteCheckedException {
                attemptStarted.countDown();

                return super.renew(expected);
            }
        };

        ScheduledThreadPoolExecutor exec = new ScheduledThreadPoolExecutor(1) {
            @Override public ScheduledFuture<?> schedule(Runnable task, long delay, TimeUnit unit) {
                if (Thread.currentThread() == reloadThread.get()) {
                    reloaded.countDown();

                    U.awaitQuiet(allowReplan);
                }

                return super.schedule(task, delay, unit);
            }
        };
        IgniteInternalFuture<?> reload = null;

        try {
            p.startRenewal(exec, log);

            assertTrue(planRead.await(10, TimeUnit.SECONDS));

            reload = GridTestUtils.runAsync(() -> {
                reloadThread.set(Thread.currentThread());

                p.reload();

                return null;
            });

            assertTrue(reloaded.await(10, TimeUnit.SECONDS));

            SSLContext inUse = p.context();

            // Let the old plan start its attempt before the reload queues a new plan.
            continuePlanning.countDown();

            assertTrue(attemptStarted.await(10, TimeUnit.SECONDS));

            allowReplan.countDown();

            reload.get(10_000);
            exec.submit(() -> {}).get(10, TimeUnit.SECONDS);

            assertEquals("Only the initial load and the manual reload may call the factory", 2, issuer.calls.size());
            assertSame(inUse, p.context());
            assertTrue("The next attempt must follow the new certificate", p.nextRenewalTime() > now + HOUR);
        }
        finally {
            continuePlanning.countDown();
            allowReplan.countDown();

            exec.shutdownNow();

            if (reload != null)
                reload.get(10_000);

            assertTrue(exec.awaitTermination(10, TimeUnit.SECONDS));
        }
    }

    /** A successful reload by the command must cancel the planned retry and plan the next renewal by the new certificate. */
    @Test
    public void testReloadByCommandReplans() throws Exception {
        long now = System.currentTimeMillis();
        long lifetime = HOUR;
        long window = (long)(lifetime * DFLT_RENEW_BEFORE_FRACTION);
        long timeLeft = 3 * window / 4;
        long notAfter = now + timeLeft;

        pauses(MINUTE, MINUTE);

        Issuer issuer = new Issuer(valid(notAfter - lifetime, notAfter), failure(), fresh(2 * HOUR), fresh(HOUR));

        IgniteEx g = startNode(issuer);

        assertTrue(waitForCondition(() -> logged(Level.WARN, ISSUER_DOWN) == 1, 30_000));

        long retry = nextRenewalTime(g);

        assertTrue("A retry must be planned after the pause",
            retry >= provider(g).reloadOutcome().failureTime() + MINUTE - CLOCK_SLACK);

        reload(g);

        long due = dueTime(g);

        assertTrue(waitForCondition(() -> nextRenewalTime(g) == due, 10_000));

        assertTrue("The next renewal must follow the new certificate", due > now + HOUR);

        ScheduledThreadPoolExecutor exec = GridTestUtils.getFieldValue(g.context().sslContexts(), "renewalExec", "delegate");

        assertTrue("The cancelled retry must not stay planned", exec.getQueue().stream().map(t -> (RunnableScheduledFuture<?>)t)
            .filter(f -> !f.isCancelled()).allMatch(f -> f.getDelay(TimeUnit.MILLISECONDS) > HOUR));
    }

    /** Renewals must run in an operation context of their own, not in the one of whoever ran a reload before them. */
    @Test
    public void testReloadContextNotCarriedIntoRenewals() throws Exception {
        long now = System.currentTimeMillis();
        long lifetime = HOUR;
        long window = (long)(lifetime * DFLT_RENEW_BEFORE_FRACTION);
        long timeLeft = 3 * window / 4;
        long notAfter = now + timeLeft;
        String operator = "operator";

        Issuer issuer = new Issuer(fresh(HOUR), valid(notAfter - lifetime, notAfter), fresh(HOUR));

        IgniteEx g = startNode(issuer);

        try (Scope ignored = OperationContext.set(OPERATOR, operator)) {
            provider(g).reload();
        }

        assertTrue(waitForCondition(() -> automaticRenewals(NODE_TRANSPORTS) == 1, 30_000));

        assertEquals(operator, issuer.calls.get(1).operator);
        assertNull("The renewal must not run as the operator", issuer.calls.get(2).operator);
    }

    /**
     * A failed renewal must be retried until it succeeds. Each pause must double, from the shortest to the longest one. While more
     * than half of the window is left, each failure must be logged as a warning. The success must clear the count of failures.
     */
    @Test
    public void testFailedRenewalRetried() throws Exception {
        long now = System.currentTimeMillis();
        long lifetime = HOUR;
        long window = (long)(lifetime * DFLT_RENEW_BEFORE_FRACTION);
        long timeLeft = 3 * window / 4;
        long notAfter = now + timeLeft;
        long minPause = 100;
        long maxPause = 4 * minPause;

        Issuer issuer = new Issuer(valid(notAfter - lifetime, notAfter),
            failure(), failure(), failure(), failure(), failure(), failure(), fresh(HOUR));

        pauses(minPause, maxPause);

        IgniteEx g = startNode(issuer);

        assertTrue(waitForCondition(() -> automaticRenewals("transports=" + COMMUNICATION) == 1, 30_000));

        long[] pauses = {minPause, 2 * minPause, maxPause, maxPause, maxPause};

        for (int i = 0; i < pauses.length; i++) {
            long pause = issuer.calls.get(i + 2).time - issuer.calls.get(i + 1).time;

            assertTrue("Pause " + (i + 1) + " must last at least " + pauses[i] + " ms: " + pause, pause >= pauses[i] - CLOCK_SLACK);
        }

        LogEvent fifth = events(Level.WARN, ISSUER_DOWN).get(4);

        assertTrue("The retry must stay within the maximum pause plus jitter", plannedPause(fifth) <= maxPause + maxPause / 2);

        assertEquals(8, issuer.calls.size());
        assertEquals(6, logged(Level.WARN, "initiator=automatic renewal, reason=" + ISSUER_DOWN));
        assertEquals(0, logged(Level.ERROR, ISSUER_DOWN));
        assertEquals(0, metrics(g).<IntMetric>findMetric("ConsecutiveRenewalFailures").value());
        assertTrue(chainNotAfter(g) > now + 30 * MINUTE);
    }

    /** A failure must be an error once the next attempt would come only after expiry, even with more than half of the window left. */
    @Test
    public void testFailureBeforeExpiringRetryLoggedAsError() throws Exception {
        long now = System.currentTimeMillis();
        long notBefore = now - HOUR;
        long timeLeft = 2 * MINUTE;
        long notAfter = now + timeLeft;
        long window = timeLeft + timeLeft / 2;
        long retryPause = 2 * timeLeft;

        Issuer issuer = new Issuer(valid(notBefore, notAfter), failure());

        issuer.setRenewBeforeFraction((double)window / (notAfter - notBefore));
        pauses(retryPause, retryPause);

        startNode(issuer);

        assertTrue(waitForCondition(() -> logged(Level.ERROR, "initiator=automatic renewal, reason=" + ISSUER_DOWN) == 1, 30_000));
    }

    /** A certificate due for renewal as soon as it is issued must not make the node renew more often than allowed. */
    @Test
    public void testRenewalsNoMoreOftenThanMinPause() throws Exception {
        long minPause = 300;
        long lifetime = HOUR;
        long window = (long)(lifetime * DFLT_RENEW_BEFORE_FRACTION);
        long timeLeft = 3 * window / 4;
        AtomicInteger issued = new AtomicInteger();

        Callable<KeyStore> dueOnIssue = () -> {
            // A second later each time: notAfter is rounded down to a second, and a renewal that does not move it is refused.
            long notAfter = System.currentTimeMillis() + timeLeft + issued.incrementAndGet() * SECOND;

            return ca.keyStoreWithPrivateKey(notAfter - lifetime, notAfter);
        };

        Issuer issuer = new Issuer(dueOnIssue);

        pauses(minPause, minPause);

        startNode(issuer);

        assertTrue(waitForCondition(() -> automaticRenewals("transports=" + COMMUNICATION) >= 4, 30_000));
        assertTrue("Every attempt must renew the certificate",
            appender.events().stream().noneMatch(e -> e.getLevel().isMoreSpecificThan(Level.WARN)));

        for (int i = 2; i < 5; i++) {
            long pause = issuer.calls.get(i).time - issuer.calls.get(i - 1).time;

            assertTrue("Renewals must be at least " + minPause + " ms apart: " + pause, pause >= minPause - CLOCK_SLACK);
        }
    }

    /** A {@code renewBeforeFraction} out of range must be refused at once. */
    @Test
    public void testInvalidSettingsRefused() {
        SslContextFactory factory = new SslContextFactory();

        assertThrowsWithCause(() -> factory.setRenewBeforeFraction(1), IllegalArgumentException.class);
        assertThrowsWithCause(() -> factory.setRenewBeforeFraction(0), IllegalArgumentException.class);
    }

    /** The client connector with a factory of its own must be renewed on its own. */
    @Test
    public void testClientConnectorRenewed() throws Exception {
        long now = System.currentTimeMillis();
        long lifetime = HOUR;
        long window = (long)(lifetime * DFLT_RENEW_BEFORE_FRACTION);
        long timeLeft = 3 * window / 4;
        long notAfter = now + timeLeft;

        Issuer issuer = new Issuer(valid(notAfter - lifetime, notAfter), fresh(HOUR));

        IgniteEx g = startClientConnectorOn(issuer);

        assertTrue(waitForCondition(() -> automaticRenewals("transports=" + CLIENT_CONNECTOR) == 1, 30_000));

        SslContextProvider p = provider(g, CLIENT_CONNECTOR);

        long renewedExpiry = SslCertificates.chainNotAfter(certificateChain(p));

        assertTrue(renewedExpiry > now + 30 * MINUTE);
        assertTrue(waitForCondition(() -> p.nextRenewalTime() > now + 30 * MINUTE, 10_000));

        assertEquals("New connections must get the renewed certificate", renewedExpiry,
            servedCertificate(probe(), g.context().clientListener().port()).getNotAfter().getTime());
    }

    /** Renewal must be off unless enabled: the node must not ask the factory again, plan a renewal or run the renewal thread. */
    @Test
    public void testRenewalOffByDefault() throws Exception {
        assertFalse(new SslContextFactory().isRenewalEnabled());

        long now = System.currentTimeMillis();
        long lifetime = HOUR;
        long window = (long)(lifetime * DFLT_RENEW_BEFORE_FRACTION);
        long timeLeft = 3 * window / 4;
        long notAfter = now + timeLeft;

        Issuer issuer = new Issuer(valid(notAfter - lifetime, notAfter));

        issuer.setRenewalEnabled(false);

        IgniteEx g = startNode(issuer);

        assertEquals("A certificate in the window must stay", 1, issuer.calls.size());
        assertEquals(0, nextRenewalTime(g));
        assertFalse(renewalThreadAlive(g.name()));
        assertTrue(appender.events().isEmpty());
    }

    /** The node sums failures once per factory, and a recovery clears only that factory's contribution. */
    @Test
    public void testRenewalFailuresMetric() throws Exception {
        try (IgniteEx g = startGrid(0)) {
            assertEquals(0, metrics(g).<IntMetric>findMetric("ConsecutiveRenewalFailures").value());
        }

        long now = System.currentTimeMillis();

        KeyStore inUse = ca.keyStoreWithPrivateKey(now - HOUR, now + HOUR);

        Issuer nodeIssuer = new Issuer(() -> inUse, () -> inUse, fresh(2 * HOUR));
        Issuer clientIssuer = new Issuer(() -> inUse, () -> inUse, () -> inUse, fresh(2 * HOUR));

        nodeIssuer.setRenewalEnabled(false);
        clientIssuer.setRenewalEnabled(false);

        IgniteEx g = startGrid(0, cfg -> {
            cfg.setSslContextFactory(nodeIssuer);
            cfg.setClientConnectorConfiguration(new ClientConnectorConfiguration().setSslEnabled(true).setSslClientAuth(false)
                .setUseIgniteSslContextFactory(false).setSslContextFactory(clientIssuer));
        });

        SslContextProvider node = provider(g);
        SslContextProvider client = provider(g, CLIENT_CONNECTOR);

        assertSame(node, provider(g, DISCOVERY));

        for (ReadOnlyMetricRegistry reg : g.context().metric())
            assertFalse("Transport aliases must not be registered: " + reg.name(), reg.name().startsWith("ssl."));

        IntMetric failures = metrics(g).findMetric("ConsecutiveRenewalFailures");

        assertEquals(0, failures.value());

        assertNull(node.renew(node.context()));
        assertEquals(1, failures.value());

        assertNull(client.renew(client.context()));
        assertNull(client.renew(client.context()));
        assertEquals(3, failures.value());

        assertNotNull(node.renew(node.context()));
        assertEquals(2, failures.value());

        assertNotNull(client.renew(client.context()));
        assertEquals(0, failures.value());
    }

    /**
     * When the factory returns the current certificate, renewal retries with increasing pauses, counts each unsuccessful attempt
     * and logs one warning without a stack trace. Manual reload resets the pause and allows a new warning.
     * Only the warning after reload must name all transports: the first may be logged before discovery is registered.
     */
    @Test
    public void testWaitsForNewerCertificate() throws Exception {
        long now = System.currentTimeMillis();
        long lifetime = HOUR;
        long window = (long)(lifetime * DFLT_RENEW_BEFORE_FRACTION);
        long timeLeft = 3 * window / 4;
        long notAfter = now + timeLeft;
        long minPause = 100;
        long fourthPause = minPause * 2 * 2 * 2;

        pauses(minPause, 10 * minPause);

        KeyStore inUse = ca.keyStoreWithPrivateKey(notAfter - lifetime, notAfter);

        Issuer issuer = new Issuer(() -> inUse);

        IgniteEx g = startNode(issuer);

        assertTrue(waitForCondition(() -> provider(g).renewalFailures() >= 5, 30_000));

        long grown = issuer.calls.get(5).time - issuer.calls.get(4).time;

        assertTrue("The fifth attempt must follow three doublings of the initial pause: " + grown,
            grown >= fourthPause - CLOCK_SLACK);

        assertEquals(1, logged(Level.WARN, WAITING));
        assertEquals(0, logged(Level.ERROR, WAITING));
        assertTrue("The wait must be logged without a stack trace", appender.events().stream().allMatch(e -> e.getThrown() == null));

        ReadOnlyMetricRegistry reg = metrics(g);

        assertTrue(reg.<IntMetric>findMetric("ConsecutiveRenewalFailures").value() >= 5);
        assertNull(provider(g).reloadOutcome().failureReason());

        Iterator<Metric> metrics = reg.iterator();

        assertEquals("ssl.ConsecutiveRenewalFailures", metrics.next().name());
        assertFalse("Only the renewal problem counter must be exposed", metrics.hasNext());

        reload(g);

        assertTrue(waitForCondition(() -> logged(Level.WARN, WAITING) == 2, 30_000));

        LogEvent afterReload = events(Level.WARN, WAITING).get(1);

        assertContains(log, afterReload.getMessage().getFormattedMessage(), WAITING + " [" + NODE_TRANSPORTS);
        assertTrue("The pause must reset to the initial pause plus jitter", plannedPause(afterReload) <= minPause + minPause / 2);
    }

    /**
     * When no newer certificate is available, log an error once when less than half of the renewal window remains and once at
     * expiry. Further attempts must not repeat these messages.
     */
    @Test
    public void testWaitTurningLateLoggedAsErrorAtOnce() throws Exception {
        long lifetime = 5 * MINUTE;
        long timeLeft = 20 * SECOND;
        long window = timeLeft + 2 * SECOND;
        AtomicReference<KeyStore> inUse = new AtomicReference<>();

        // Issued on the first request, so that the time left does not depend on how long the node takes to start.
        Issuer issuer = new Issuer(() -> {
            if (inUse.get() == null) {
                long notAfter = System.currentTimeMillis() + timeLeft;

                inUse.set(ca.keyStoreWithPrivateKey(notAfter - lifetime, notAfter));
            }

            return inUse.get();
        });

        issuer.setRenewBeforeFraction((double)window / lifetime);

        startNode(issuer);

        assertTrue(waitForCondition(() -> logged(Level.ERROR, WAITING + " and expire soon") == 1, 30_000));

        int calls = issuer.calls.size();

        assertTrue(waitForCondition(() -> issuer.calls.size() >= calls + 2, 30_000));

        assertEquals(1, logged(Level.WARN, WAITING));
        assertEquals(1, logged(Level.ERROR, WAITING));

        assertTrue(waitForCondition(() -> logged(Level.ERROR, WAITING + ", though they have expired") == 1, 30_000));

        int expiredCalls = issuer.calls.size();

        assertTrue(waitForCondition(() -> issuer.calls.size() >= expiredCalls + 2, 30_000));

        assertEquals(1, logged(Level.WARN, WAITING));
        assertEquals(2, logged(Level.ERROR, WAITING));
    }

    /** A node that stops in the middle of a renewal attempt must interrupt it without recording or logging a failure. */
    @Test
    public void testStopDuringRenewalLogsNoFailure() throws Exception {
        long now = System.currentTimeMillis();
        long lifetime = HOUR;
        long window = (long)(lifetime * DFLT_RENEW_BEFORE_FRACTION);
        long timeLeft = 3 * window / 4;
        long notAfter = now + timeLeft;

        CountDownLatch entered = new CountDownLatch(1);

        Issuer issuer = new Issuer(fresh(HOUR), valid(notAfter - lifetime, notAfter), () -> {
            entered.countDown();

            Thread.sleep(Long.MAX_VALUE);

            return null;
        });

        IgniteEx g = startNode(issuer);
        SslContextProvider p = provider(g);

        p.reload();

        SslContextProvider.ReloadOutcome outcome = p.reloadOutcome();

        assertTrue(outcome.successTime() > 0);
        assertTrue(entered.await(30, TimeUnit.SECONDS));

        stopGrid(0);

        assertEquals(0, p.renewalFailures());
        assertEquals(outcome, p.reloadOutcome());
        assertTrue(appender.events().stream().noneMatch(e -> e.getLevel().isMoreSpecificThan(Level.WARN)));
    }

    /** A loader returning after interruption must not replace the context or change recorded reload and renewal results. */
    @Test
    public void testInterruptedRenewalReturnPreservesState() throws Exception {
        long now = System.currentTimeMillis();
        KeyStore original = ca.keyStoreWithPrivateKey("original", now - HOUR, now + HOUR);
        KeyStore replacement = ca.keyStoreWithPrivateKey("replacement", now - MINUTE, now + 2 * HOUR);

        for (KeyStore candidate : List.of(original, replacement)) {
            Issuer issuer = new Issuer(() -> original, () -> original, () -> original, failure(), () -> {
                Thread.currentThread().interrupt();

                return candidate;
            });
            SslContextProvider p = new SslContextProvider(issuer);

            p.reload();
            assertNull(p.renew(p.context()));
            GridTestUtils.assertThrows(log, p::reload, IgniteException.class, ISSUER_DOWN);

            SSLContext inUse = p.context();
            Map<String, List<X509Certificate>> chains = p.certificateChains();
            SslContextProvider.ReloadOutcome outcome = p.reloadOutcome();
            int failures = p.renewalFailures();

            assertTrue(outcome.successTime() > 0);
            assertEquals(1, outcome.failures());
            assertEquals(1, failures);

            IgniteInterruptedCheckedException err = null;
            boolean interrupted;

            try {
                p.renew(inUse);
            }
            catch (IgniteInterruptedCheckedException e) {
                err = e;
            }
            finally {
                interrupted = Thread.interrupted();
            }

            assertTrue(interrupted);
            assertSame(inUse, p.context());
            assertEquals(chains, p.certificateChains());
            assertEquals(outcome, p.reloadOutcome());
            assertEquals(failures, p.renewalFailures());
            assertNotNull(err);
        }
    }

    /** Cached and expired unchanged chains stay in use and count as unsuccessful renewal attempts. */
    @Test
    public void testSameCertificatesUnchanged() throws Exception {
        long now = System.currentTimeMillis();

        SslBundle cached = TestCertificateAuthority.bundle(ca.keyStoreWithPrivateKey(), ca.trustStore());

        SslContextProvider p = new SslContextProvider(new Issuer(fresh(HOUR)) {
            @Override public SslBundle createSslBundle() {
                return cached;
            }
        });

        assertNull(p.renew(p.context()));
        assertEquals(1, p.renewalFailures());

        assertNull(p.renew(p.context()));
        assertEquals(2, p.renewalFailures());
        assertEquals(0, p.reloadOutcome().failures());

        KeyStore expired = ca.keyStoreWithPrivateKey(now - 2 * HOUR, now - HOUR);

        SslContextProvider expiredProvider = new SslContextProvider(new Issuer(() -> expired));

        SSLContext expiredCtx = expiredProvider.context();

        assertNull(expiredProvider.renew(expiredCtx));
        assertSame(expiredCtx, expiredProvider.context());
        assertEquals(1, expiredProvider.renewalFailures());
    }

    /** New metadata cannot make a reused SSL context serve a replacement certificate. */
    @Test
    public void testChangedMetadataCannotRenewCachedContext() throws Exception {
        long now = System.currentTimeMillis();
        SslBundle original = TestCertificateAuthority.bundle(ca.keyStoreWithPrivateKey(now - HOUR, now + HOUR), ca.trustStore());
        SslBundle replacement = TestCertificateAuthority.bundle(ca.keyStoreWithPrivateKey(now - HOUR, now + 2 * HOUR), ca.trustStore());
        AtomicReference<SslBundle> supplied = new AtomicReference<>(original);

        SslContextProvider p = new SslContextProvider(new Issuer(fresh(HOUR)) {
            @Override public SslBundle createSslBundle() {
                return supplied.get();
            }
        });

        supplied.set(new SslBundle(original.context(), replacement.certificateChains()));

        assertRenewalRejected(p, "The SSL context factory returns the context in use");
    }

    /** Returning the same certificate and throwing both count until a renewal extends the chain's lifetime. */
    @Test
    public void testUnsuccessfulRenewalsCounted() throws Exception {
        long now = System.currentTimeMillis();

        KeyStore inUse = ca.keyStoreWithPrivateKey(now - HOUR, now + HOUR);

        SslContextProvider p = new SslContextProvider(new Issuer(() -> inUse, () -> inUse, failure(), () -> inUse, fresh(2 * HOUR)));

        assertNull(p.renew(p.context()));
        assertEquals(1, p.renewalFailures());

        GridTestUtils.assertThrows(log, () -> p.renew(p.context()), IgniteException.class, ISSUER_DOWN);

        assertEquals(2, p.renewalFailures());
        assertNull(p.renew(p.context()));
        assertEquals(3, p.renewalFailures());
        assertEquals(1, p.reloadOutcome().failures());

        assertNotNull(p.renew(p.context()));
        assertEquals(0, p.renewalFailures());
    }

    /** Manual reloads neither count as renewal attempts nor clear their failures unless the chain expires later. */
    @Test
    public void testReloadClearsRenewalFailuresOnlyWithLaterExpiry() throws Exception {
        long now = System.currentTimeMillis();
        long notBefore = now - HOUR;
        long notAfter = now + HOUR;
        String alias = "node";

        KeyStore inUse = ca.keyStoreWithPrivateKey(alias, notBefore, notAfter);
        AtomicReference<Callable<KeyStore>> keySupplier = new AtomicReference<>(() -> inUse);
        Issuer issuer = new Issuer(() -> keySupplier.get().call());

        SslContextProvider p = new SslContextProvider(issuer);

        assertNull(p.renew(p.context()));
        assertEquals(1, p.renewalFailures());

        // A failed manual reload is not an automatic renewal attempt.
        keySupplier.set(failure());

        GridTestUtils.assertThrows(log, p::reload, IgniteException.class, ISSUER_DOWN);

        assertEquals(1, p.renewalFailures());

        // Reloading the same certificate clears the reload error, but not the renewal failures.
        keySupplier.set(() -> inUse);

        p.reload();

        assertEquals(1, p.renewalFailures());
        assertNull(p.reloadOutcome().failureReason());

        TestCertificateAuthority other = new TestCertificateAuthority("otherca");

        issuer.trust = TestCertificateAuthority.trustStore(ca, other);

        // Updating only the trust store does not renew the certificate.
        p.reload();

        assertEquals(1, p.renewalFailures());

        // A different certificate with the same expiry still does not extend the chain's lifetime.
        KeyStore sameExpiry = ca.keyStoreWithPrivateKey(alias, notBefore, notAfter);

        keySupplier.set(() -> sameExpiry);

        p.reload();

        assertFalse(inUse.getCertificate(alias).equals(certificate(p)));
        assertEquals(1, p.renewalFailures());

        // Only the final certificate extends the chain's lifetime.
        keySupplier.set(() -> ca.keyStoreWithPrivateKey(notBefore, notAfter + HOUR));

        p.reload();

        assertEquals(0, p.renewalFailures());
    }

    /** Extending only the leaf does not clear failures when the authority still expires first. */
    @Test
    public void testLaterLeafExpiryDoesNotClearRenewalFailures() throws Exception {
        long now = System.currentTimeMillis() / SECOND * SECOND;
        long notBefore = now - HOUR;
        long authorityExpiry = now + HOUR;
        long leafExpiry = authorityExpiry + HOUR;
        long laterLeafExpiry = leafExpiry + HOUR;

        ca = new TestCertificateAuthority("renewalca", notBefore - HOUR, authorityExpiry);

        KeyStore inUse = ca.keyStoreWithPrivateKey(notBefore, leafExpiry);

        SslContextProvider p = new SslContextProvider(new Issuer(() -> inUse, () -> inUse, valid(notBefore, laterLeafExpiry)));

        assertEquals(authorityExpiry, SslCertificates.chainNotAfter(certificateChain(p)));

        assertNull(p.renew(p.context()));

        p.reload();

        assertEquals(laterLeafExpiry, certificate(p).getNotAfter().getTime());
        assertEquals(authorityExpiry, SslCertificates.chainNotAfter(certificateChain(p)));
        assertEquals(1, p.renewalFailures());
    }

    /** The file-based factory with renewal enabled must put in use the key store replaced on disk, with no command. */
    @Test
    public void testReplacedKeyStoreFileRenewed() throws Exception {
        long now = System.currentTimeMillis();
        long lifetime = HOUR;
        long window = (long)(lifetime * DFLT_RENEW_BEFORE_FRACTION);
        long timeLeft = 3 * window / 4;
        long notAfter = now + timeLeft;

        Path keyStore = Files.createTempFile("ignite-ssl-renewal-", ".jks");

        try {
            TestCertificateAuthority.save(ca.keyStoreWithPrivateKey(notAfter - lifetime, notAfter), keyStore);

            SslContextFactory factory = new SslContextFactory();

            factory.setKeyStoreFilePath(keyStore.toString());
            factory.setKeyStorePassword(TestCertificateAuthority.PWD);
            factory.setKeyStoreType("JKS");
            factory.setTrustManagers(TestCertificateAuthority.trustManagers(ca.trustStore()));
            factory.setRenewalEnabled(true);

            IgniteEx g = startNode(factory);

            assertTrue(waitForCondition(() -> logged(Level.WARN, WAITING) == 1, 30_000));

            TestCertificateAuthority.save(ca.keyStoreWithPrivateKey(now, now + HOUR), keyStore);

            assertTrue(waitForCondition(() -> automaticRenewals(NODE_TRANSPORTS) == 1, 30_000));
            assertTrue(chainNotAfter(g) > now + 30 * MINUTE);
        }
        finally {
            Files.delete(keyStore);
        }
    }

    /** Automatic renewal without certificate metadata must stop the node from starting. */
    @Test
    public void testUnknownCertificateRefusedAtStart() {
        Issuer issuer = new Issuer(fresh(HOUR));

        issuer.metadata = false;

        GridTestUtils.assertThrowsAnyCause(log, () -> startClientConnectorOn(issuer), IgniteException.class,
            "The SSL context factory must provide a nonempty certificate chain for every private key");
    }

    /** Automatic renewal cannot start when the loaded store contains no private key. */
    @Test
    public void testKeyStoreWithoutKeyRefusedAtStart() {
        Issuer issuer = new Issuer(SslRenewalTest::noKey);

        GridTestUtils.assertThrowsAnyCause(log, () -> startClientConnectorOn(issuer), IgniteException.class,
            "The new key material has no private key, so the node would present no certificate");
    }

    /** Renewal rejects a store without a private key and retains the context and chain in use. */
    @Test
    public void testKeyStoreWithoutKeyNotRenewed() {
        SslContextProvider p = new SslContextProvider(new Issuer(fresh(HOUR), SslRenewalTest::noKey));

        assertRenewalRejected(p, "The new key material has no private key, so the node would present no certificate");
    }

    /** With renewal disabled, missing certificate metadata must not schedule renewal or produce renewal log messages. */
    @Test
    public void testUnknownCertificateWithoutRenewal() throws Exception {
        Issuer issuer = new Issuer(fresh(HOUR));

        issuer.metadata = false;
        issuer.setRenewalEnabled(false);

        IgniteEx g = startClientConnectorOn(issuer);

        SslContextProvider p = provider(g, CLIENT_CONNECTOR);

        assertNull(p.certificateChains());
        assertEquals(0, p.nextRenewalTime());
        assertContains(log, status(g), "certificate metadata is unavailable");
        assertContains(log, reload(g), ": reloaded " + CLIENT_CONNECTOR);
        assertTrue(appender.events().isEmpty());
    }

    /** Known aliases with a missing secondary chain cannot start or replace an automatically renewed context. */
    @Test
    public void testMissingSecondaryChainRefused() throws Exception {
        String completeAlias = "complete-key";
        String incompleteAlias = "key-without-chain";
        AtomicBoolean missing = new AtomicBoolean();
        KeyStore keys = ca.keyStoreWithPrivateKey(completeAlias);

        addKey(keys, ca.keyStoreWithPrivateKey(incompleteAlias), incompleteAlias);

        Issuer issuer = new Issuer(() -> keys) {
            @Override public SslBundle createSslBundle() {
                SslBundle loaded = super.createSslBundle();

                return missing.get() ? new SslBundle(loaded.context(),
                    Map.of(completeAlias, loaded.certificateChains().get(completeAlias), incompleteAlias, List.of())) : loaded;
            }
        };
        SslContextProvider p = new SslContextProvider(issuer);

        missing.set(true);

        String reason = "The private key has no X.509 certificate chain; remove the key or provide its X.509 certificate chain " +
            "[alias=" + incompleteAlias + ']';

        assertRenewalRejected(p, reason);

        SslContextProvider incomplete = new SslContextProvider(issuer);
        ScheduledThreadPoolExecutor exec = new ScheduledThreadPoolExecutor(1);

        try {
            GridTestUtils.assertThrows(log, () -> {
                incomplete.startRenewal(exec, log);

                return null;
            }, IgniteException.class, reason);

            assertEquals(0, incomplete.nextRenewalTime());
        }
        finally {
            exec.shutdownNow();

            assertTrue(exec.awaitTermination(10, TimeUnit.SECONDS));
        }
    }

    /** Renewal settings are fixed at registration; changing the factory must not let reload lose the chain used by renewal. */
    @Test
    public void testReloadCannotLoseMetadataWithRenewal() {
        Issuer issuer = new Issuer(fresh(HOUR));
        SslContextProvider p = new SslContextProvider(issuer);

        issuer.setRenewalEnabled(false);
        issuer.metadata = false;

        SSLContext inUse = p.context();
        Map<String, List<X509Certificate>> chains = p.certificateChains();
        String reason = "The new SSL context must provide a nonempty certificate chain for every private key to renew automatically";

        assertNotNull(chains);

        GridTestUtils.assertThrows(log, () -> {
            p.reload();

            return null;
        }, IgniteCheckedException.class, reason);

        assertSame(inUse, p.context());
        assertEquals(chains, p.certificateChains());

        assertRenewalRejected(p, reason);
    }

    /** Copies one private key and its chain into the target store. */
    private static void addKey(KeyStore target, KeyStore source, String alias) throws Exception {
        target.setKeyEntry(alias, source.getKey(alias, TestCertificateAuthority.PWD), TestCertificateAuthority.PWD,
            source.getCertificateChain(alias));
    }

    /** @return Key store with no private key. */
    private static KeyStore noKey() throws Exception {
        KeyStore noKey = KeyStore.getInstance(KeyStore.getDefaultType());

        noKey.load(null, null);

        return noKey;
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
     * @param factory SSL context factory of the node.
     * @return Started node.
     */
    private IgniteEx startNode(AbstractSslContextFactory factory) throws Exception {
        return startNode(0, factory);
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
     * @param renewal Whether the node renews automatically.
     * @return Configured issuer.
     */
    private Issuer issuer(Callable<KeyStore> source, KeyStore trust, boolean renewal) {
        Issuer issuer = new Issuer(source);

        issuer.trust = trust;
        issuer.setRenewalEnabled(renewal);

        return issuer;
    }

    /**
     * Rotates one node's certificate, then restarts each node to check that they load their current certificates and reconnect.
     *
     * @param peerCa Authority of the peer whose certificate stays unchanged.
     */
    private void assertNodesReconnectAfterRotationAndRestart(TestCertificateAuthority peerCa) throws Exception {
        long now = System.currentTimeMillis();
        long lifetime = HOUR;
        long window = (long)(lifetime * DFLT_RENEW_BEFORE_FRACTION);
        long timeLeft = 3 * window / 4;
        long notAfter = now + timeLeft;

        AtomicReference<KeyStore> keys = new AtomicReference<>(ca.keyStoreWithPrivateKey("node0", notAfter - lifetime, notAfter));
        KeyStore peerKeys = peerCa.keyStoreWithPrivateKey("node1", now - MINUTE, now + HOUR);
        Issuer issuer = issuer(keys::get, peerCa.trustStore(), true);
        Issuer peerIssuer = issuer(() -> peerKeys, ca.trustStore(), false);

        IgniteEx g0 = startNode(0, issuer);
        IgniteEx g1 = startNode(1, peerIssuer);

        X509Certificate peerCert = certificate(provider(g1));

        assertFalse(certificate(provider(g0)).equals(peerCert));
        assertComputeWorks(g0, g1);

        String renewedAlias = "node0-new";
        KeyStore replacement = ca.keyStoreWithPrivateKey(renewedAlias, now, now + 2 * HOUR);
        X509Certificate renewed = (X509Certificate)replacement.getCertificate(renewedAlias);

        keys.set(replacement);

        assertTrue(waitForCondition(() -> renewed.equals(certificate(provider(g0))), 30_000));

        assertEquals(renewed, certificate(provider(g0)));
        assertEquals(peerCert, certificate(provider(g1)));
        assertEquals(0, provider(g1).reloadOutcome().successTime());
        assertEquals(renewed, servedCertificate(peerIssuer.createSslBundle().context(), discoveryPort(g0)));
        assertEquals(peerCert, servedCertificate(issuer.createSslBundle().context(), discoveryPort(g1)));

        assertComputeWorks(g0, g1);

        stopGrid(1);

        g1 = startNode(1, issuer(() -> peerKeys, ca.trustStore(), false));

        assertEquals(renewed, certificate(provider(g0)));
        assertEquals(peerCert, certificate(provider(g1)));
        assertComputeWorks(g0, g1);

        stopGrid(0);

        IgniteEx restarted = startNode(0, issuer(keys::get, peerCa.trustStore(), true));

        assertEquals(renewed, certificate(provider(restarted)));
        assertEquals(renewed, servedCertificate(peerIssuer.createSslBundle().context(), discoveryPort(restarted)));
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
     * @param notBefore Time the certificate becomes valid.
     * @param notAfter Time it expires.
     * @return Step that issues a certificate valid for that time.
     */
    private Callable<KeyStore> valid(long notBefore, long notAfter) {
        return () -> ca.keyStoreWithPrivateKey(notBefore, notAfter);
    }

    /**
     * @param lifetime Lifetime of the certificate.
     * @return Step that issues a certificate valid from the moment it is issued.
     */
    private Callable<KeyStore> fresh(long lifetime) {
        return () -> {
            long now = System.currentTimeMillis();

            return ca.keyStoreWithPrivateKey(now, now + lifetime);
        };
    }

    /** @return Step that simulates an unreachable issuer. */
    private static Callable<KeyStore> failure() {
        return () -> {
            throw new IgniteException(ISSUER_DOWN);
        };
    }

    /** @return Context to connect to the nodes with; a new one each time, so that no session is resumed with an old certificate. */
    private SSLContext probe() throws Exception {
        return TestCertificateAuthority.context(ca.keyStoreWithPrivateKey(), ca.trustStore());
    }

    /**
     * @param min Pause after the first unsuccessful renewal attempt, in milliseconds.
     * @param max Longest pause, in milliseconds.
     */
    private static void pauses(long min, long max) {
        GridTestUtils.setFieldValue(SslRenewal.class, "minPause", min);
        GridTestUtils.setFieldValue(SslRenewal.class, "maxPause", max);
    }

    /**
     * @param p Provider.
     * @param reason Reason the renewal must be rejected for.
     */
    private static void assertRenewalRejected(SslContextProvider p, String reason) {
        SSLContext inUse = p.context();
        Map<String, List<X509Certificate>> chains = p.certificateChains();
        int failures = p.renewalFailures();

        GridTestUtils.assertThrows(log, () -> p.renew(inUse), IgniteCheckedException.class, reason);

        assertSame(inUse, p.context());
        assertEquals(chains, p.certificateChains());
        assertEquals(failures + 1, p.renewalFailures());
    }

    /**
     * @param level Level.
     * @param text Text the message contains.
     * @return Number of renewal messages containing the text at the given level.
     */
    private long logged(Level level, String text) {
        return events(level, text).size();
    }

    /**
     * @param level Level.
     * @param text Text the message contains.
     * @return Renewal messages containing the text at the given level, in log order.
     */
    private List<LogEvent> events(Level level, String text) {
        return appender.events().stream().filter(e -> e.getLevel() == level && e.getMessage().getFormattedMessage().contains(text))
            .collect(Collectors.toList());
    }

    /**
     * @param transports Transports as the log names them.
     * @return How many times the renewals put new certificates in use.
     */
    private long automaticRenewals(String transports) {
        return logged(Level.INFO, "TLS certificates reloaded [" + transports);
    }

    /**
     * @param e Event logged by an unsuccessful renewal attempt.
     * @return Time from the event to the next attempt it planned, in milliseconds.
     */
    private static long plannedPause(LogEvent e) {
        String msg = e.getMessage().getFormattedMessage();
        int from = msg.indexOf("nextRenewal=") + "nextRenewal=".length();

        return Instant.parse(msg.substring(from, msg.indexOf(']', from))).toEpochMilli() - e.getTimeMillis();
    }

    /**
     * @param g Node.
     * @return Start of the renewal window, calculated with the default renewal fraction.
     */
    private static long dueTime(IgniteEx g) {
        long notBefore = certificate(provider(g)).getNotBefore().getTime();
        long notAfter = chainNotAfter(g);

        return notAfter - (long)((notAfter - notBefore) * DFLT_RENEW_BEFORE_FRACTION);
    }

    /** */
    private static long nextRenewalTime(IgniteEx g) {
        return provider(g).nextRenewalTime();
    }

    /** */
    private static long chainNotAfter(IgniteEx g) {
        return SslCertificates.chainNotAfter(certificateChain(provider(g)));
    }

    /** @return Sole chain used by a single-key test factory. */
    private static List<X509Certificate> certificateChain(SslContextProvider provider) {
        Map<String, List<X509Certificate>> chains = provider.certificateChains();

        assertNotNull(chains);
        assertEquals(1, chains.size());

        return chains.values().iterator().next();
    }

    /** @return Leaf of the sole chain used by a single-key test factory. */
    private static X509Certificate certificate(SslContextProvider provider) {
        return certificateChain(provider).get(0);
    }

    /**
     * @param g Node.
     * @return SSL metrics of the node.
     */
    private static ReadOnlyMetricRegistry metrics(IgniteEx g) {
        for (ReadOnlyMetricRegistry reg : g.context().metric()) {
            if (reg.name().equals("ssl"))
                return reg;
        }

        throw new AssertionError("SSL metrics are not registered");
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

    /**
     * @param name Node name.
     * @return Whether a renewal thread of the node is alive.
     */
    private static boolean renewalThreadAlive(String name) {
        for (Thread t : Thread.getAllStackTraces().keySet()) {
            if (t.isAlive() && t.getName().startsWith("ssl-renewal") && t.getName().contains(name))
                return true;
        }

        return false;
    }

    /** One request to an issuer. */
    private static class Call {
        /** Time the request arrived, in milliseconds since the epoch. */
        private final long time = System.currentTimeMillis();

        /** Operation context attribute standing for the operator, as the request saw it. */
        private final @Nullable String operator = OperationContext.get(OPERATOR);
    }

    /** Factory that answers each request the way the test scripted it, the last step repeated for the rest. */
    private class Issuer extends AbstractSslContextFactory {
        /** */
        @Serial
        private static final long serialVersionUID = 0L;

        /** Answers to the requests in order, the last one repeated for the rest. */
        private final List<Callable<KeyStore>> steps;

        /** Requests so far. */
        private final List<Call> calls = new CopyOnWriteArrayList<>();

        /** Trust store for new contexts, or {@code null} to trust only the default test authority. */
        private volatile KeyStore trust;

        /** Whether this factory supplies certificate metadata. */
        private boolean metadata = true;

        /** @param steps Answers to the requests in order, the last one repeated for the rest. */
        @SafeVarargs
        private Issuer(Callable<KeyStore>... steps) {
            this.steps = List.of(steps);

            setRenewalEnabled(true);
        }

        /** {@inheritDoc} */
        @Override protected void checkParameters() {
            // No-op.
        }

        /** {@inheritDoc} */
        @Override public SslBundle createSslBundle() {
            SslBundle bundle = super.createSslBundle();

            return metadata ? bundle : new SslBundle(bundle.context(), null);
        }

        /** {@inheritDoc} */
        @Override protected KeyMaterial loadKeyMaterial() {
            Callable<KeyStore> step = steps.get(Math.min(calls.size(), steps.size() - 1));

            calls.add(new Call());

            try {
                return new KeyMaterial(step.call(), TestCertificateAuthority.PWD, KeyManagerFactory.getDefaultAlgorithm());
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
