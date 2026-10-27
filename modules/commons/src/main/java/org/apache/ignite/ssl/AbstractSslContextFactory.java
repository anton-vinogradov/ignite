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

import java.security.KeyManagementException;
import java.security.NoSuchAlgorithmException;
import java.util.concurrent.atomic.AtomicReference;
import javax.cache.configuration.Factory;
import javax.net.ssl.KeyManager;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLException;
import javax.net.ssl.SSLParameters;
import javax.net.ssl.TrustManager;
import org.apache.ignite.IgniteException;
import org.apache.ignite.internal.util.typedef.internal.A;
import org.jetbrains.annotations.Nullable;

/**
 * Base SSL context factory that caches the result of the first successful {@link #create()} call.
 * Use {@link #createSslBundle()} to load another context and its certificate chains without changing the cached context.
 */
public abstract class AbstractSslContextFactory implements Factory<SSLContext> {
    /** */
    private static final long serialVersionUID = 0L;

    /** Default SSL protocol. */
    public static final String DFLT_SSL_PROTOCOL = "TLS";

    /** Default share of the certificate lifetime left when a node starts to renew it. */
    public static final double DFLT_RENEW_BEFORE_FRACTION = 0.15;

    /** SSL protocol. */
    protected String proto = DFLT_SSL_PROTOCOL;

    /** Enabled cipher suites. */
    protected String[] cipherSuites;

    /** Enabled protocols. */
    protected String[] protocols;

    /**
     * Cached instance used by the legacy {@link #create()} method.
     *
     * @deprecated Hold the result of {@link #createSslBundle()} outside the factory.
     */
    @Deprecated
    protected final AtomicReference<SSLContext> sslCtx = new AtomicReference<>();

    /** Whether a node builds its SSL context again before the certificate expires, to pick up a new certificate. */
    private boolean renewalEnabled;

    /** Share of the certificate lifetime left when a node starts to renew it. */
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

    /** @return Whether a node builds its SSL context again before the certificate expires, to pick up a new certificate. */
    public boolean isRenewalEnabled() {
        return renewalEnabled;
    }

    /**
     * Sets whether a node calls {@link #createSslBundle()} before the certificates expire to pick up replacements.
     * A file-based factory rereads its files. It does not replace them.
     * When enabled, the factory must provide a nonempty X.509 chain for every private key or the node does not start. Disabled by default.
     * Set this before starting the node; changing it on a running node takes effect after a restart.
     *
     * @param renewalEnabled Whether renewal is enabled.
     */
    public void setRenewalEnabled(boolean renewalEnabled) {
        this.renewalEnabled = renewalEnabled;
    }

    /** @return Share of the certificate lifetime left when a node starts to renew the certificate. */
    public double getRenewBeforeFraction() {
        return renewBeforeFraction;
    }

    /**
     * Sets the share of the certificate lifetime left when a node starts to renew the certificate. The lifetime runs from the time
     * the leaf certificate becomes valid to the earliest expiry in its chain. For several private keys, the chain with the earliest
     * expiry determines renewal; ties use the earliest leaf validity start. The value must be greater than {@code 0} and less than
     * {@code 1}, otherwise this method throws {@link IllegalArgumentException}.
     * If not specified, {@link #DFLT_RENEW_BEFORE_FRACTION} is used.
     * Set this before starting the node; changing it on a running node takes effect after a restart.
     *
     * @param renewBeforeFraction Share of the lifetime.
     */
    public void setRenewBeforeFraction(double renewBeforeFraction) {
        A.ensure(renewBeforeFraction > 0 && renewBeforeFraction < 1, "renewBeforeFraction must be greater than 0 and less than 1");

        this.renewBeforeFraction = renewBeforeFraction;
    }

    /**
     * Builds a fresh context and its certificate metadata without calling {@link #create()} or changing its cached context.
     * Subclasses must override this method. Those that load a key store can call {@link #createSslBundle(KeyMaterial)} to
     * include its certificate chains.
     * <p>
     * The node uses this method at startup, for {@code control.sh --ssl reload} and for automatic renewal when a custom factory
     * overrides it.
     * Older subclasses keep the {@link #create()} path. Calls for the same factory on a node never overlap. A factory that
     * fetches certificates remotely must bound each request and respond to thread interruption.
     *
     * @return Fresh context and the certificate metadata available to this factory.
     * @throws UnsupportedOperationException If the subclass does not implement bundle creation.
     * @throws IgniteException If the context could not be created.
     */
    public SslBundle createSslBundle() {
        throw new UnsupportedOperationException("Subclass must override createSslBundle()");
    }

    /**
     * Builds a fresh context from one loaded store. The caller must check its parameters before loading the material.
     *
     * @param material Loaded key store, key password and manager algorithm.
     * @return Context and certificate chains from that material.
     * @throws SSLException If key managers, certificate metadata or the context cannot be created.
     */
    protected SslBundle createSslBundle(KeyMaterial material) throws SSLException {
        return new SslBundle(createSslContext(material.keyManagers()), material.certificateChains());
    }

    /**
     * @param keyMgrs Key managers, or {@code null} to use the provider's defaults.
     * @return Initialized context.
     * @throws SSLException If trust managers or the context cannot be created.
     */
    private SSLContext createSslContext(@Nullable KeyManager[] keyMgrs) throws SSLException {
        TrustManager[] trustMgrs = createTrustManagers();

        try {
            SSLContext ctx = SSLContext.getInstance(proto);

            SSLParameters sslParameters = null;

            if (cipherSuites != null || protocols != null) {
                sslParameters = new SSLParameters();

                if (cipherSuites != null)
                    sslParameters.setCipherSuites(cipherSuites);

                if (protocols != null)
                    sslParameters.setProtocols(protocols);
            }

            if (sslParameters != null)
                ctx = new SSLContextWrapper(ctx, sslParameters);

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
     * Checks that all required parameters are set.
     *
     * @throws SSLException If any of required parameters is missing.
     */
    protected abstract void checkParameters() throws SSLException;

    /**
     * Creates key managers without certificate metadata.
     *
     * @return Created key managers.
     * @throws SSLException If this method is not overridden or key managers cannot be created.
     * @deprecated Override {@link #createSslBundle()} to return a context with its certificate chains.
     */
    @Deprecated
    protected KeyManager[] createKeyManagers() throws SSLException {
        throw new SSLException("Subclass must override createSslBundle() or createKeyManagers()");
    }

    /**
     * @return Created Trust Managers.
     * @throws SSLException If Trust Managers could not be created.
     */
    protected abstract TrustManager[] createTrustManagers() throws SSLException;

    /**
     * Returns the cached context, building it through the subclass's bundle method or its legacy key-manager hook.
     *
     * @return Cached context.
     * @deprecated Use {@link #createSslBundle()} and keep the context in the component that uses it.
     */
    @Deprecated
    @Override public SSLContext create() {
        SSLContext ctx = sslCtx.get();

        if (ctx == null) {
            try {
                if (getClass().getMethod("createSslBundle").getDeclaringClass() == AbstractSslContextFactory.class) {
                    checkParameters();

                    ctx = createSslContext(createKeyManagers());
                }
                else
                    ctx = createSslBundle().context();
            }
            catch (NoSuchMethodException | SSLException e) {
                throw new IgniteException(e);
            }

            if (!sslCtx.compareAndSet(null, ctx))
                ctx = sslCtx.get();
        }

        return ctx;
    }
}
