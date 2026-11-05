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

import java.security.GeneralSecurityException;
import java.security.KeyManagementException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Enumeration;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.TreeMap;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.atomic.AtomicReference;
import java.util.function.Consumer;
import java.util.function.Supplier;
import javax.cache.configuration.Factory;
import javax.net.ssl.KeyManager;
import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLException;
import javax.net.ssl.SSLParameters;
import javax.net.ssl.TrustManager;
import org.apache.ignite.IgniteException;
import org.apache.ignite.IgniteLogger;
import org.apache.ignite.internal.ssl.SslCertificates;
import org.apache.ignite.internal.ssl.SslFactoryAccess;
import org.apache.ignite.internal.ssl.SslFactoryAccess.ReloadOutcome;
import org.apache.ignite.internal.ssl.SslRenewal;
import org.apache.ignite.internal.util.typedef.internal.A;
import org.jetbrains.annotations.Nullable;

/**
 * Owns the SSL context and the certificate chains loaded with it. An initialized factory retains its material across
 * node restarts. A subclass can call {@link #init()} to replace it. Configure the factory before use.
 */
public abstract class AbstractSslContextFactory implements Factory<SSLContext> {
    /** */
    private static final long serialVersionUID = 0L;

    /** Default SSL protocol. */
    public static final String DFLT_SSL_PROTOCOL = "TLS";

    /** Default share of the certificate lifetime left when a node starts to renew it. */
    public static final double DFLT_RENEW_BEFORE_FRACTION = 0.15;

    /**
     * Gives the node access to the accepted material, reload and automatic renewal.
     * @hidden
     */
    public static final SslFactoryAccess NODE_ACCESS = new SslFactoryAccess() {
        /** {@inheritDoc} */
        @Override protected @Nullable Map<String, List<X509Certificate>> certificateChains(AbstractSslContextFactory factory) {
            return factory.certificateChains();
        }

        /** {@inheritDoc} */
        @Override protected @Nullable List<X509Certificate> renewalChain(AbstractSslContextFactory factory, SSLContext expected) {
            AcceptedContext cur = factory.accepted;

            return cur == null || cur.context() != expected ? null : SslCertificates.renewalChain(cur.chains());
        }

        /** {@inheritDoc} */
        @Override protected @Nullable Map<String, List<X509Certificate>> reload(AbstractSslContextFactory factory) {
            return factory.reload();
        }

        /** {@inheritDoc} */
        @Override protected ReloadOutcome reloadOutcome(AbstractSslContextFactory factory) {
            return factory.reloadOutcome();
        }

        /** {@inheritDoc} */
        @Override protected void startRenewal(
            AbstractSslContextFactory factory,
            ScheduledExecutorService exec,
            IgniteLogger log,
            Supplier<String> transports
        ) {
            factory.startRenewal(exec, log, transports);
        }

        /** {@inheritDoc} */
        @Override protected @Nullable Map<String, List<X509Certificate>> renew(
            AbstractSslContextFactory factory,
            SSLContext expected
        ) {
            return factory.renew(expected);
        }

        /** {@inheritDoc} */
        @Override protected int renewalFailures(AbstractSslContextFactory factory) {
            return factory.renewalFailures();
        }

        /** {@inheritDoc} */
        @Override protected long nextRenewalTime(AbstractSslContextFactory factory) {
            return factory.nextRenewalTime();
        }
    };

    /** Context and chains from the accepted load. */
    private transient volatile AcceptedContext accepted;

    /** Snapshot of the last successful reload and subsequent failures. */
    private transient volatile ReloadOutcome outcome;

    /** Automatic renewal attached by the node; the node owns its executor. */
    private transient volatile SslRenewal renewal;

    /** Executor whose attachment fixes the renewal settings until that node stops. */
    private transient ScheduledExecutorService renewalExec;

    /** Unsuccessful automatic attempts since the earliest expiry across all chains was advanced. */
    private transient volatile int renewalFailures;

    /** SSL protocol. */
    protected String proto = DFLT_SSL_PROTOCOL;

    /** Enabled cipher suites. */
    protected String[] cipherSuites;

    /** Enabled protocols. */
    protected String[] protocols;

    /** Whether automatic renewal is requested when a node attaches its renewal executor. */
    private boolean renewalEnabled;

    /** Share of the certificate lifetime left when renewal starts. */
    private double renewBeforeFraction = DFLT_RENEW_BEFORE_FRACTION;

    /**
     * Gets protocol for secure transport.
     *
     * @return SSL protocol name.
     */
    public String getProtocol() {
        return proto;
    }

    /**
     * Sets protocol for secure transport. If not specified, {@link #DFLT_SSL_PROTOCOL} will be used.
     *
     * @param proto SSL protocol name.
     */
    public void setProtocol(String proto) {
        A.notNull(proto, "proto");

        this.proto = proto;
    }

    /**
     * Sets enabled cipher suites.
     *
     * @param cipherSuites enabled cipher suites.
     */
    public void setCipherSuites(String... cipherSuites) {
        this.cipherSuites = cipherSuites;
    }

    /**
     * Gets enabled cipher suites.
     *
     * @return enabled cipher suites
     */
    public String[] getCipherSuites() {
        return cipherSuites;
    }

    /**
     * Gets enabled protocols.
     *
     * @return Enabled protocols.
     */
    public String[] getProtocols() {
        return protocols;
    }

    /**
     * Sets enabled protocols.
     *
     * @param protocols Enabled protocols.
     */
    public void setProtocols(String... protocols) {
        this.protocols = protocols;
    }

    /**
     * A node reads this setting at startup.
     *
     * @return Whether the node automatically loads replacement certificates before expiry.
     */
    public boolean isRenewalEnabled() {
        return renewalEnabled;
    }

    /**
     * Sets whether a node reloads TLS material before its certificates expire.
     * A file-based factory rereads its files. Supply replacement certificates in those files.
     * When enabled, the factory must report at least one X.509 certificate chain, or the node does not start.
     * With renewal enabled, use a separate factory instance for each running node. Disabled by default.
     * Set this before starting the node; changing it on a running node takes effect after a restart.
     *
     * @param renewalEnabled Whether renewal is enabled.
     */
    public void setRenewalEnabled(boolean renewalEnabled) {
        this.renewalEnabled = renewalEnabled;
    }

    /**
     * A node with renewal enabled reads this setting at startup and does not start unless its value is greater than
     * {@code 0} and less than {@code 1}.
     *
     * @return Share of the certificate lifetime left when renewal starts.
     */
    public double getRenewBeforeFraction() {
        return renewBeforeFraction;
    }

    /**
     * Sets the share of the certificate lifetime left when a node starts to renew the certificate. The lifetime runs from the time
     * the leaf certificate becomes valid to the earliest expiry in its chain. Among the reported chains, the one with the earliest
     * expiry determines renewal; ties use the earliest leaf validity start. The value must be greater than {@code 0} and less than
     * {@code 1}, otherwise this method throws {@link IllegalArgumentException}.
     * If not specified, {@link #DFLT_RENEW_BEFORE_FRACTION} is used.
     * Set this before starting the node; changing it on a running node takes effect after a restart.
     *
     * @param renewBeforeFraction Share of the lifetime.
     */
    public void setRenewBeforeFraction(double renewBeforeFraction) {
        A.ensure(validRenewBeforeFraction(renewBeforeFraction), "renewBeforeFraction must be greater than 0 and less than 1");

        this.renewBeforeFraction = renewBeforeFraction;
    }

    /** @return Whether the renewal window starts within the certificate lifetime. */
    private static boolean validRenewBeforeFraction(double fraction) {
        return fraction > 0 && fraction < 1;
    }

    /**
     * Creates a fresh context and reports the X.509 chains of its keys, by alias, with the leaf first.
     * An empty map means there are no such chains. If the source cannot report chains, omit the callback.
     *
     * @param reportChains Receives the chains at most once, on the calling thread before this method returns.
     * @return Fresh SSL context.
     * @throws SSLException If the context could not be created.
     */
    protected abstract SSLContext createSslContext(Consumer<Map<String, List<X509Certificate>>> reportChains) throws SSLException;

    /**
     * Creates a context from a loaded key store, using this factory's trust and TLS settings.
     * Do not modify the store while the context is in use: key managers such as PKIX read it during handshakes.
     * Load replacement material into a separate store.
     *
     * @param store Loaded key store, or {@code null} for a client without private keys.
     * @param keyPwd Password for the loaded store's private keys, or {@code null} if no password is required.
     * @param algorithm Key manager algorithm.
     * @param reportChains Receives the chains from the same store.
     * @return Fresh SSL context.
     * @throws SSLException If the store cannot be read or the context cannot be created.
     */
    protected final SSLContext createSslContext(
        @Nullable KeyStore store,
        char @Nullable [] keyPwd,
        String algorithm,
        Consumer<Map<String, List<X509Certificate>>> reportChains
    ) throws SSLException {
        A.notNull(algorithm, "algorithm");

        KeyManager[] keyMgrs;

        try {
            KeyManagerFactory factory = KeyManagerFactory.getInstance(algorithm);

            factory.init(store, keyPwd);

            keyMgrs = factory.getKeyManagers();
        }
        catch (NoSuchAlgorithmException e) {
            throw new SSLException("Unsupported key algorithm: " + algorithm + " [factory=" + this + ']', e);
        }
        catch (GeneralSecurityException e) {
            throw new SSLException("Failed to initialize Key Manager (security exception occurred) [factory=" + this + ']', e);
        }

        Map<String, List<X509Certificate>> chains = certificateChains(store);
        SSLContext ctx = createSslContext(keyMgrs);

        reportChains.accept(chains);

        return ctx;
    }

    /**
     * @param store Loaded key store, or {@code null} when there are no keys.
     * @return Nonempty X.509 chains of key entries.
     * @throws SSLException If the store cannot be read.
     */
    private static Map<String, List<X509Certificate>> certificateChains(@Nullable KeyStore store) throws SSLException {
        if (store == null)
            return Collections.emptyMap();

        try {
            Map<String, List<X509Certificate>> chains = new HashMap<>();

            for (Enumeration<String> aliases = store.aliases(); aliases.hasMoreElements(); ) {
                String alias = aliases.nextElement();

                if (!store.isKeyEntry(alias))
                    continue;

                List<X509Certificate> chain = certificateChain(store.getCertificateChain(alias));

                if (!chain.isEmpty())
                    chains.put(alias, chain);
            }

            return chains;
        }
        catch (KeyStoreException e) {
            throw new SSLException("Failed to read certificate chains from key store", e);
        }
    }

    /** @return Immutable copy of the reported chains, ordered by alias. */
    private static @Nullable Map<String, List<X509Certificate>> copyChains(@Nullable Map<String, List<X509Certificate>> chains) {
        if (chains == null)
            return null;

        Map<String, List<X509Certificate>> copy = new TreeMap<>();

        chains.forEach((alias, chain) -> {
            A.ensure(!chain.isEmpty(), "Certificate chain must not be empty [alias=" + alias + ']');

            copy.put(alias, List.copyOf(chain));
        });

        return Collections.unmodifiableMap(copy);
    }

    /**
     * @param certs Chain from the store, if present.
     * @return X.509 chain, or an empty list if it is absent or contains another certificate type.
     */
    private static List<X509Certificate> certificateChain(@Nullable Certificate[] certs) {
        if (certs == null)
            return Collections.emptyList();

        List<X509Certificate> chain = new ArrayList<>(certs.length);

        for (Certificate cert : certs) {
            if (!(cert instanceof X509Certificate))
                return Collections.emptyList();

            chain.add((X509Certificate)cert);
        }

        return chain;
    }

    /**
     * @param keyMgrs Key managers for the loaded material.
     * @return Initialized context.
     * @throws SSLException If trust managers or the context cannot be created.
     */
    private SSLContext createSslContext(KeyManager[] keyMgrs) throws SSLException {
        TrustManager[] trustMgrs = createTrustManagers();

        try {
            SSLContext ctx = SSLContext.getInstance(proto);

            if (cipherSuites != null || protocols != null) {
                SSLParameters sslParameters = new SSLParameters();

                if (cipherSuites != null)
                    sslParameters.setCipherSuites(cipherSuites);

                if (protocols != null)
                    sslParameters.setProtocols(protocols);

                ctx = new SSLContextWrapper(ctx, sslParameters);
            }

            ctx.init(keyMgrs, trustMgrs, null);

            return ctx;
        }
        catch (NoSuchAlgorithmException e) {
            throw new SSLException("Unsupported SSL protocol: " + proto, e);
        }
        catch (KeyManagementException e) {
            throw new SSLException("Failed to initialized SSL context.", e);
        }
    }

    /**
     * @param param Value.
     * @param name Name.
     * @throws SSLException If {@code null}.
     */
    protected void checkNullParameter(Object param, String name) throws SSLException {
        if (param == null)
            throw new SSLException("Failed to initialize SSL context (parameter cannot be null): " + name);
    }

    /**
     * @return Created Trust Managers.
     * @throws SSLException If Trust Managers could not be created.
     */
    protected abstract TrustManager[] createTrustManagers() throws SSLException;

    /**
     * Loads fresh material and checks that the configured protocols and cipher suites can be applied before publishing
     * the context and its metadata. Calls run one at a time. A failed initialization leaves the previous material in use.
     *
     * <p>
     * The first load, including a retry after failure, accepts material with no certificate chains or with certificates outside their
     * validity period. After a successful load, calls reject the context already in use, an empty chain map, or an expired
     * or not-yet-valid certificate in any chain. Check peer trust with a new connection.
     * While a running node automatically renews this factory, a replacement must report at least one certificate chain.
     * Each successful replacement schedules the next renewal.
     *
     * @throws IgniteException If the material cannot be loaded, the context cannot be created or a replacement is rejected.
     * @throws IllegalArgumentException If the JVM does not recognize a name in {@link #setProtocols} or {@link #setCipherSuites}.
     * @throws UnsupportedOperationException If the context does not support stream sockets.
     */
    protected final void init() {
        reload();
    }

    /** @return Chains accepted by this load, or {@code null} if the source did not provide them. */
    private synchronized @Nullable Map<String, List<X509Certificate>> reload() {
        boolean replacing = accepted != null;

        try {
            Map<String, List<X509Certificate>> accepted = load(false);

            if (replacing)
                onSuccess();

            return accepted;
        }
        catch (Throwable e) {
            if (replacing)
                onFailure(e);

            throw e;
        }
    }

    /**
     * Attaches the node's automatic renewal executor. The current renewal settings apply until that executor stops.
     * Repeated attachment to the same running node changes nothing. A factory with renewal enabled cannot serve two running
     * nodes with separate renewal executors; configure a separate factory instance on each node. After a node stops, its
     * factory can attach to a new executor, using the settings configured for that restart.
     *
     * @param exec Renewal executor owned and stopped by the node.
     * @param log Renewal logger.
     * @param transports Names of the transports currently using this factory, evaluated when logging.
     * @throws IgniteException If another running node uses this factory and either node enables renewal, or if renewal is
     *      enabled and the window is invalid, initialization fails or the factory reports no X.509 chain.
     */
    private synchronized void startRenewal(ScheduledExecutorService exec, IgniteLogger log, Supplier<String> transports) {
        boolean enabled = isRenewalEnabled();

        if (renewalExec != null && !renewalExec.isShutdown()) {
            if (renewalExec != exec && (renewal != null || enabled))
                throw new IgniteException("The SSL context factory is already used by another running node; " +
                    "configure a separate factory instance on each node");

            return;
        }

        renewal = null;
        renewalExec = null;

        if (enabled) {
            double fraction = getRenewBeforeFraction();

            if (!validRenewBeforeFraction(fraction)) {
                throw new IgniteException("renewBeforeFraction must be greater than 0 and less than 1 " +
                    "[value=" + fraction + ']');
            }

            if (SslCertificates.renewalChain(certificateChains()) == null) {
                throw new IgniteException("The SSL context factory must provide at least one X.509 certificate chain " +
                    "to renew automatically [transports=" + transports.get() + ']');
            }

            renewal = new SslRenewal(this, fraction, exec, log, transports);
        }

        renewalExec = exec;

        if (renewal != null)
            renewal.replan();
    }

    /**
     * Installs replacement material only if its earliest chain expiry is later than the current earliest expiry.
     * Unchanged chains count as an unsuccessful renewal without recording a reload failure. If the node stops the executor
     * during the load, the factory retains its material and failure counts.
     *
     * @param expected Context in use when the renewal was planned.
     * @return Installed chains, or {@code null} if the attempt was superseded, stopped or found unchanged chains.
     * @throws IgniteException If the replacement cannot be loaded, fails initialization checks, has no certificate metadata
     *      or does not advance the earliest expiry across all chains.
     */
    private synchronized @Nullable Map<String, List<X509Certificate>> renew(SSLContext expected) {
        if (accepted == null || accepted.context() != expected)
            return null;

        Map<String, List<X509Certificate>> accepted;

        try {
            accepted = load(true);
        }
        catch (Throwable e) {
            if (!renewalStopped()) {
                renewalFailures++;

                onFailure(e);
            }

            throw e;
        }

        if (accepted != null)
            onSuccess();

        return accepted;
    }

    /** @return Whether the node stopped its renewal executor. */
    private boolean renewalStopped() {
        return renewalExec != null && renewalExec.isShutdown();
    }

    /** @return Unsuccessful automatic attempts since the earliest expiry across all chains was advanced. */
    private int renewalFailures() {
        return renewalFailures;
    }

    /** @return Time of the next automatic renewal, {@code 0} if none is planned or the node has stopped. */
    private long nextRenewalTime() {
        SslRenewal cur = renewal;

        return cur == null ? 0 : cur.nextRenewalTime();
    }

    /**
     * Loads, checks and publishes a candidate while the caller holds the factory monitor.
     *
     * @param automatic Whether the attempt must advance the earliest chain expiry.
     * @return Accepted chains, or {@code null} if unavailable or an automatic attempt did not install a replacement.
     */
    private @Nullable Map<String, List<X509Certificate>> load(boolean automatic) {
        AtomicReference<Map<String, List<X509Certificate>>> loaded = new AtomicReference<>();
        SSLContext next;

        try {
            next = createSslContext(reported -> loaded.set(copyChains(reported)));

            A.notNull(next, "ctx");

            next.createSSLEngine();
            next.getSocketFactory();
        }
        catch (SSLException e) {
            throw new IgniteException(e);
        }

        if (automatic && renewalStopped())
            return null;

        Map<String, List<X509Certificate>> nextChains = loaded.get();
        AcceptedContext cur = accepted;
        Map<String, List<X509Certificate>> curChains = cur == null ? null : cur.chains();
        List<X509Certificate> curChain = SslCertificates.renewalChain(curChains);
        List<X509Certificate> nextChain = SslCertificates.renewalChain(nextChains);

        if (cur != null) {
            if (nextChains != null && nextChains.isEmpty()) {
                throw new IgniteException("The new key material has no X.509 certificate chains, " +
                    "so the node would present no certificate");
            }

            if (automatic && nextChains != null && nextChains.equals(curChains)) {
                renewalFailures++;

                return null;
            }

            checkReplacement(next, nextChains, automatic || renewal != null && !renewalStopped());

            if (automatic && curChain != null) {
                long nextExpiry = SslCertificates.chainNotAfter(nextChain);
                long curExpiry = SslCertificates.chainNotAfter(curChain);

                if (nextExpiry <= curExpiry) {
                    throw new IgniteException("The new certificate chains expire no later than the ones in use. " +
                        "Every replacement chain must outlast the current earliest expiry [chainNotAfter=" +
                        Instant.ofEpochMilli(nextExpiry) + ", inUseChainNotAfter=" + Instant.ofEpochMilli(curExpiry) + ']');
                }
            }
        }

        if (nextChain != null && (curChain == null ||
            SslCertificates.chainNotAfter(nextChain) > SslCertificates.chainNotAfter(curChain)))
            renewalFailures = 0;

        accepted = new AcceptedContext(next, nextChains);

        return nextChains;
    }

    /**
     * @param next Replacement to check before it is published.
     * @param nextChains Chains loaded with the replacement.
     * @param requireChains Whether certificate metadata must remain available for automatic renewal.
     * @throws IgniteException If the context is already in use, required metadata is missing or a certificate is invalid.
     */
    private void checkReplacement(
        SSLContext next,
        @Nullable Map<String, List<X509Certificate>> nextChains,
        boolean requireChains
    ) {
        if (next == accepted.context()) {
            throw new IgniteException("The SSL context factory returned the context already in use. " +
                "Build a fresh SSLContext on each load to apply new certificates.");
        }

        if (requireChains && nextChains == null) {
            throw new IgniteException("The replacement must provide at least one X.509 certificate chain " +
                "to renew automatically");
        }

        if (nextChains == null)
            return;

        long now = System.currentTimeMillis();

        for (Map.Entry<String, List<X509Certificate>> entry : nextChains.entrySet()) {
            X509Certificate invalid = SslCertificates.invalidAt(entry.getValue(), now);

            if (invalid != null) {
                throw new IgniteException("The new certificate chain is not valid now [alias=" + entry.getKey() + ", " +
                    SslCertificates.describe(invalid) + ", now=" + Instant.ofEpochMilli(now) + ']');
            }
        }
    }

    /** Records a successful replacement and plans renewal from the new material. */
    private void onSuccess() {
        outcome = new ReloadOutcome(System.currentTimeMillis(), 0, null, 0);

        if (renewal != null)
            renewal.replan();
    }

    /** @param e Why replacement failed. */
    private void onFailure(Throwable e) {
        ReloadOutcome previous = reloadOutcome();

        outcome = new ReloadOutcome(previous.successTime(), System.currentTimeMillis(),
            SslCertificates.reason(e), previous.failures() + 1);
    }

    /** @return Snapshot of the last successful reload and subsequent failures; zero times before any reload. */
    private ReloadOutcome reloadOutcome() {
        ReloadOutcome res = outcome;

        return res == null ? new ReloadOutcome(0, 0, null, 0) : res;
    }

    /**
     * Returns the chains of the accepted context, initializing the factory on first use.
     *
     * @return Immutable chains by alias, or {@code null} if the source does not provide them.
     */
    protected final @Nullable Map<String, List<X509Certificate>> certificateChains() {
        return acceptedContext().chains();
    }

    /** @return Accepted material, loading it on first use. */
    private AcceptedContext acceptedContext() {
        AcceptedContext cur = accepted;

        if (cur == null) {
            synchronized (this) {
                cur = accepted;

                if (cur == null) {
                    init();

                    cur = accepted;
                }
            }
        }

        return cur;
    }

    /**
     * Returns the accepted context, initializing the factory on first use. While a replacement loads, callers receive
     * the current context without waiting. Call this method again after a successful replacement to obtain the new context.
     * Previously returned contexts, engines and sockets retain their original material. Do not reinitialize the context directly.
     *
     * @return Currently accepted context.
     * @throws IgniteException If the first initialization fails to load the material or create the context.
     * @throws IllegalArgumentException If the JVM does not recognize a configured protocol or cipher suite name.
     * @throws UnsupportedOperationException If the context does not support stream sockets.
     */
    @Override public final SSLContext create() {
        return acceptedContext().context();
    }

    /** Context and certificate metadata published together. */
    private record AcceptedContext(SSLContext context, @Nullable Map<String, List<X509Certificate>> chains) {
        // No-op.
    }
}
