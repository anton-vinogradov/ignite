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
import javax.cache.configuration.Factory;
import javax.net.ssl.SSLContext;
import org.apache.ignite.IgniteCheckedException;
import org.apache.ignite.ssl.AbstractSslContextFactory;
import org.apache.ignite.ssl.SslBundle;
import org.jetbrains.annotations.Nullable;

import static org.apache.ignite.internal.ssl.SslCertificates.describe;

/** Owns one factory's context and reloads on this node; transports using that factory share its context. */
public class SslContextProvider {
    /** */
    private final Factory<SSLContext> factory;

    /** */
    private final Set<String> transports = new ConcurrentSkipListSet<>();

    /** Context and certificate metadata in use. */
    private volatile SslBundle bundle;

    /** Stable context handed to every transport using this factory. */
    private final SSLContext sharedCtx;

    /** Snapshot of the last successful reload and subsequent failures. */
    private volatile ReloadOutcome outcome = new ReloadOutcome(0, 0, null, 0);

    /** @param factory Factory to build the context with. */
    SslContextProvider(Factory<SSLContext> factory) {
        this.factory = factory;

        bundle = createBundle();
        bundle.context().createSSLEngine();

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

    /** @return Chains by private-key alias, or {@code null} when the factory supplies no metadata. */
    public @Nullable Map<String, List<X509Certificate>> certificateChains() {
        return bundle.certificateChains();
    }

    /** @return A new bundle, with unknown certificate metadata for factories that only return a context. */
    private SslBundle createBundle() {
        return factory instanceof AbstractSslContextFactory f ? f.createSslBundle() : new SslBundle(factory.create(), null);
    }

    /**
     * Builds and installs a new context for new connections, recording success or failure. Rejects key material that reports no
     * private-key entries or contains a private key without an X.509 certificate chain. Every supplied certificate must be within its
     * validity period.
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

            check(rebuilt.certificateChains());

            bundle = rebuilt;
        }
        catch (Throwable e) {
            onFailure(e);

            throw e;
        }

        onSuccess();

        return bundle;
    }

    /**
     * @return Bundle built anew, or the context in use if a custom factory caches it.
     * @throws IgniteCheckedException If the loaded material reports no private-key entries or a key has no X.509 certificate chain.
     */
    private SslBundle build() throws IgniteCheckedException {
        SslBundle rebuilt = createBundle();

        checkKeyMaterial(rebuilt.certificateChains());

        rebuilt.context().createSSLEngine();

        return rebuilt;
    }

    /**
     * @param chains Chains by private-key alias, {@code null} if the factory supplies no metadata.
     * @throws IgniteCheckedException If no private-key entries are reported or a key has no X.509 certificate chain.
     */
    private static void checkKeyMaterial(@Nullable Map<String, List<X509Certificate>> chains) throws IgniteCheckedException {
        if (chains == null)
            return;

        if (chains.isEmpty())
            throw new IgniteCheckedException("The new key material reports no private-key entries, " +
                "so the node would present no certificate");

        for (Map.Entry<String, List<X509Certificate>> entry : chains.entrySet()) {
            if (entry.getValue().isEmpty()) {
                throw new IgniteCheckedException("The private key has no X.509 certificate chain; remove the key or provide its " +
                    "X.509 certificate chain [alias=" + entry.getKey() + ']');
            }
        }
    }

    /**
     * @param next Chains loaded with the new context, {@code null} if they are unknown.
     * @throws IgniteCheckedException If a certificate is outside its validity period.
     */
    private void check(@Nullable Map<String, List<X509Certificate>> next) throws IgniteCheckedException {
        if (next == null)
            return;

        long now = System.currentTimeMillis();

        for (Map.Entry<String, List<X509Certificate>> entry : next.entrySet()) {
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
}
