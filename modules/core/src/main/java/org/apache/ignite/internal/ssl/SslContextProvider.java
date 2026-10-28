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

import java.security.cert.X509Certificate;
import java.time.Instant;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.ConcurrentSkipListSet;
import java.util.concurrent.ScheduledExecutorService;
import javax.cache.configuration.Factory;
import javax.net.ssl.SSLContext;
import org.apache.ignite.IgniteCheckedException;
import org.apache.ignite.IgniteException;
import org.apache.ignite.IgniteInterruptedException;
import org.apache.ignite.IgniteLogger;
import org.apache.ignite.internal.IgniteInterruptedCheckedException;
import org.apache.ignite.internal.util.typedef.X;
import org.apache.ignite.ssl.AbstractSslContextFactory;
import org.apache.ignite.ssl.SslBundle;
import org.jetbrains.annotations.Nullable;

import static org.apache.ignite.internal.ssl.SslCertificates.chainNotAfter;
import static org.apache.ignite.internal.ssl.SslCertificates.describe;

/** Owns one factory's context, reloads and automatic renewal on this node; transports using that factory share its context. */
public class SslContextProvider {
    /** */
    private final Factory<SSLContext> factory;

    /** */
    private final Set<String> transports = new ConcurrentSkipListSet<>();

    /** Context and certificate metadata in use. */
    private volatile SslBundle bundle;

    /** Stable context handed to every transport using this factory. */
    private final SSLContext sharedCtx;

    /** Renewal window configured at registration, or {@code 0} when automatic renewal is disabled. */
    private final double renewBeforeFraction;

    /** Automatic renewal, attached before this provider is registered. */
    private @Nullable SslRenewal renewal;

    /** Snapshot of the last successful reload and subsequent failures. */
    private volatile ReloadOutcome outcome = new ReloadOutcome(0, 0, null, 0);

    /** Failed automatic attempts since the earliest expiry across all chains was advanced. */
    private volatile int renewalFailures;

    /** @param factory Factory to build the context with. */
    SslContextProvider(Factory<SSLContext> factory) {
        this.factory = factory;

        bundle = createBundle();
        bundle.context().createSSLEngine();

        renewBeforeFraction = factory instanceof AbstractSslContextFactory f && f.isRenewalEnabled() ? f.getRenewBeforeFraction() : 0;

        sharedCtx = new CurrentSslContext(this::context);
    }

    /** @return Factory the context is built with. */
    Factory<SSLContext> factory() {
        return factory;
    }

    /** @return Context to open the next connection with. */
    SSLContext context() {
        return bundle.context();
    }

    /** @return Context and certificate metadata from the same load. */
    SslBundle bundle() {
        return bundle;
    }

    /** @return Stable context shared by every transport configured with this factory. */
    SSLContext sharedContext() {
        return sharedCtx;
    }

    /** @param transport Transport the context is handed to. */
    void addTransport(String transport) {
        transports.add(transport);
    }

    /** @return Comma-separated transport names used in command output and node logs. */
    public String transports() {
        return String.join(", ", transports);
    }

    /** @return Chains by key alias, or {@code null} when the factory supplies no metadata. */
    public @Nullable Map<String, List<X509Certificate>> certificateChains() {
        return bundle.certificateChains();
    }

    /** @return A new bundle, with unknown certificate metadata for factories that only return a context. */
    private SslBundle createBundle() {
        return factory instanceof AbstractSslContextFactory f ? f.createSslBundle() : new SslBundle(factory.create(), null);
    }

    /**
     * @param exec Renewal thread of the node.
     * @param log Renewal logger.
     */
    void startRenewal(ScheduledExecutorService exec, IgniteLogger log) {
        if (renewBeforeFraction == 0)
            return;

        if (renewalChain(bundle) == null) {
            throw new IgniteException("The SSL context factory must provide at least one X.509 certificate chain " +
                "to renew automatically [transports=" + transports() + ']');
        }

        renewal = new SslRenewal(this, renewBeforeFraction, exec, log);
        renewal.replan();
    }

    /**
     * Builds and installs a new context for new connections, recording success or failure. Rejects material known to have no
     * X.509 certificate chains. Every supplied certificate must be within its validity period.
     * Certificate metadata is required when automatic renewal is enabled.
     * The administrator must ensure that peers trust the new certificates and can connect with the new context.
     *
     * @return Context and certificate metadata installed by this reload.
     * @throws IgniteCheckedException If the new context fails a check or the factory returns the context in use. On any failure,
     *      including a factory exception, the current context is retained.
     */
    public synchronized SslBundle reload() throws IgniteCheckedException {
        try {
            SslBundle rebuilt = build();

            if (rebuilt.context() == bundle.context())
                throw new IgniteCheckedException("The SSL context factory returns the context in use, so the node gets no new " +
                    "certificates from it");

            check(rebuilt, renewBeforeFraction > 0);

            putInUse(rebuilt);
        }
        catch (Throwable e) {
            onFailure(e);

            throw e;
        }

        onSuccess();

        return bundle;
    }

    /**
     * Installs a new bundle only if the earliest expiry across all its chains is later than the current earliest expiry.
     * Returning the current chains counts as an unsuccessful attempt and leaves the bundle unchanged. An interrupted attempt
     * changes nothing and does not count as unsuccessful.
     *
     * @param expected Context the renewal was planned for.
     * @return Installed bundle, or {@code null} if its chains are unchanged or the planned context had already been replaced.
     * @throws IgniteCheckedException If certificate metadata is unknown, the bundle fails the checks of {@link #reload()},
     *      or the earliest expiry does not advance, or if the thread is interrupted by the time the factory returns;
     *      the interrupt flag then stays set.
     */
    synchronized @Nullable SslBundle renew(SSLContext expected) throws IgniteCheckedException {
        if (bundle.context() != expected)
            return null;

        try {
            SslBundle rebuilt = build();

            if (Thread.currentThread().isInterrupted())
                throw new IgniteInterruptedCheckedException("TLS certificate renewal was interrupted");

            Map<String, List<X509Certificate>> next = rebuilt.certificateChains();

            if (next != null && next.equals(bundle.certificateChains())) {
                renewalFailures++;

                return null;
            }

            if (rebuilt.context() == bundle.context())
                throw new IgniteCheckedException("The SSL context factory returns the context in use, so the node gets no new " +
                    "certificates from it");

            check(rebuilt, true);

            List<X509Certificate> cur = renewalChain(bundle);
            long nextExpiry = chainNotAfter(renewalChain(rebuilt));

            if (cur != null && nextExpiry <= chainNotAfter(cur)) {
                throw new IgniteCheckedException("The new certificate chains expire no later than the ones in use; if a certificate " +
                    "authority expires first, renew it [chainNotAfter=" + Instant.ofEpochMilli(nextExpiry) +
                    ", inUseChainNotAfter=" + Instant.ofEpochMilli(chainNotAfter(cur)) + ']');
            }

            putInUse(rebuilt);
        }
        catch (Throwable e) {
            if (!Thread.currentThread().isInterrupted() &&
                !X.hasCause(e, InterruptedException.class, IgniteInterruptedException.class, IgniteInterruptedCheckedException.class)) {
                renewalFailures++;

                onFailure(e);
            }

            throw e;
        }

        onSuccess();

        return bundle;
    }

    /** @param rebuilt Bundle that passed the checks. */
    private void putInUse(SslBundle rebuilt) {
        List<X509Certificate> cur = renewalChain(bundle);
        List<X509Certificate> next = renewalChain(rebuilt);

        if (next != null && (cur == null || chainNotAfter(next) > chainNotAfter(cur)))
            renewalFailures = 0;

        bundle = rebuilt;
    }

    /**
     * Chooses the first chain to expire, using the earliest leaf validity start to break ties.
     *
     * @param bundle Context and its chains.
     * @return Chain that determines renewal, or {@code null} if certificate metadata is unknown or contains no chains.
     */
    static @Nullable List<X509Certificate> renewalChain(SslBundle bundle) {
        Map<String, List<X509Certificate>> chains = bundle.certificateChains();

        if (chains == null || chains.isEmpty())
            return null;

        List<X509Certificate> earliest = null;
        long earliestExpiry = Long.MAX_VALUE;

        for (List<X509Certificate> chain : chains.values()) {
            long expiry = chainNotAfter(chain);

            if (earliest == null || expiry < earliestExpiry ||
                expiry == earliestExpiry && chain.get(0).getNotBefore().before(earliest.get(0).getNotBefore())) {
                earliest = chain;
                earliestExpiry = expiry;
            }
        }

        return earliest;
    }

    /**
     * @return Bundle built anew, or the context in use if a custom factory caches it.
     * @throws IgniteCheckedException If the loaded material has no X.509 certificate chains.
     */
    private SslBundle build() throws IgniteCheckedException {
        SslBundle rebuilt = createBundle();
        Map<String, List<X509Certificate>> chains = rebuilt.certificateChains();

        if (chains != null && chains.isEmpty())
            throw new IgniteCheckedException("The new key material has no X.509 certificate chains, " +
                "so the node would present no certificate");

        rebuilt.context().createSSLEngine();

        return rebuilt;
    }

    /**
     * @param next Bundle loaded by the factory.
     * @param requireChains Whether at least one reported chain is required for renewal.
     * @throws IgniteCheckedException If required certificate metadata is unknown or empty, or a certificate is outside its validity period.
     */
    private void check(SslBundle next, boolean requireChains) throws IgniteCheckedException {
        Map<String, List<X509Certificate>> chains = next.certificateChains();

        if (requireChains && (chains == null || chains.isEmpty()))
            throw new IgniteCheckedException("The new SSL context must provide at least one X.509 certificate chain to renew automatically");

        if (chains == null)
            return;

        long now = System.currentTimeMillis();

        for (Map.Entry<String, List<X509Certificate>> entry : chains.entrySet()) {
            X509Certificate invalid = SslCertificates.invalidAt(entry.getValue(), now);

            if (invalid != null) {
                throw new IgniteCheckedException("The new certificate chain is not valid now [alias=" + entry.getKey() + ", " +
                    describe(invalid) + ", now=" + Instant.ofEpochMilli(now) + ']');
            }
        }
    }

    /** Records a successful reload. */
    private void onSuccess() {
        outcome = new ReloadOutcome(System.currentTimeMillis(), 0, null, 0);

        if (renewal != null)
            renewal.replan();
    }

    /** @param e Why the reload failed. */
    private void onFailure(Throwable e) {
        ReloadOutcome o = outcome;

        outcome = new ReloadOutcome(o.successTime(), System.currentTimeMillis(), SslCertificates.reason(e), o.failures() + 1);
    }

    /** @return Snapshot of the last successful reload and subsequent failures. */
    public ReloadOutcome reloadOutcome() {
        return outcome;
    }

    /** @return Failed automatic attempts since the earliest expiry across all chains was advanced, including unchanged certificates. */
    int renewalFailures() {
        return renewalFailures;
    }

    /**
     * Snapshot of the last successful reload and subsequent failures.
     *
     * @param successTime Time of the last successful reload, {@code 0} if there was none.
     * @param failureTime Time of the last failed reload since the last successful one, {@code 0} if there was none.
     * @param failureReason Reason of the last failed reload since the last successful one, {@code null} if there was none.
     * @param failures Failed reloads in a row since the last successful one.
     */
    public record ReloadOutcome(long successTime, long failureTime, @Nullable String failureReason, int failures) {
        // No-op.
    }

    /** @return Time of the next automatic renewal, {@code 0} if none is planned. */
    public long nextRenewalTime() {
        return renewal == null ? 0 : renewal.nextRenewalTime();
    }
}
