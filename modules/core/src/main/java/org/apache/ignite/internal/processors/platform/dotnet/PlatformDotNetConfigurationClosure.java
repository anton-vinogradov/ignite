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

package org.apache.ignite.internal.processors.platform.dotnet;

import org.apache.ignite.IgniteCheckedException;
import org.apache.ignite.IgniteException;
import org.apache.ignite.binary.BinaryIdMapper;
import org.apache.ignite.binary.BinaryBasicIdMapper;
import org.apache.ignite.binary.BinaryNameMapper;
import org.apache.ignite.binary.BinaryBasicNameMapper;
import org.apache.ignite.configuration.BinaryConfiguration;
import org.apache.ignite.configuration.IgniteConfiguration;
import org.apache.ignite.configuration.PlatformConfiguration;
import org.apache.ignite.internal.MarshallerContextImpl;
import org.apache.ignite.internal.binary.BinaryNoopMetadataHandler;
import org.apache.ignite.internal.binary.BinaryRawWriterEx;
import org.apache.ignite.internal.binary.GridBinaryMarshaller;
import org.apache.ignite.internal.binary.BinaryContext;
import org.apache.ignite.internal.processors.platform.PlatformAbstractConfigurationClosure;
import org.apache.ignite.internal.processors.platform.lifecycle.PlatformLifecycleBean;
import org.apache.ignite.internal.processors.platform.memory.PlatformInputStream;
import org.apache.ignite.internal.processors.platform.memory.PlatformMemory;
import org.apache.ignite.internal.processors.platform.memory.PlatformMemoryManagerImpl;
import org.apache.ignite.internal.processors.platform.memory.PlatformOutputStream;
import org.apache.ignite.internal.processors.platform.utils.PlatformUtils;
import org.apache.ignite.internal.util.typedef.internal.U;
import org.apache.ignite.lifecycle.LifecycleBean;
import org.apache.ignite.logger.NullLogger;
import org.apache.ignite.marshaller.Marshaller;
import org.apache.ignite.platform.dotnet.PlatformDotNetConfiguration;
import org.apache.ignite.internal.binary.BinaryMarshaller;
import org.apache.ignite.platform.dotnet.PlatformDotNetLifecycleBean;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

/**
 * Closure to apply dot net configuration.
 */
@SuppressWarnings({"UnusedDeclaration"})
public class PlatformDotNetConfigurationClosure extends PlatformAbstractConfigurationClosure {
    /** */
    private static final long serialVersionUID = 0L;

    /** Configuration. */
    private IgniteConfiguration cfg;

    /** Memory manager. */
    private PlatformMemoryManagerImpl memMgr;

    /**
     * Constructor.
     *
     * @param envPtr Environment pointer.
     */
    public PlatformDotNetConfigurationClosure(long envPtr) {
        super(envPtr);
    }

    /** {@inheritDoc} */
    @SuppressWarnings("deprecation")
    @Override protected void apply0(IgniteConfiguration igniteCfg) {
        // 3. Validate and copy Interop configuration setting environment pointer along the way.
        PlatformConfiguration interopCfg = igniteCfg.getPlatformConfiguration();

        if (interopCfg != null && !(interopCfg instanceof PlatformDotNetConfiguration))
            throw new IgniteException("Illegal platform configuration (must be of type " +
                PlatformDotNetConfiguration.class.getName() + "): " + interopCfg.getClass().getName());

        PlatformDotNetConfiguration dotNetCfg = interopCfg != null ? (PlatformDotNetConfiguration)interopCfg : null;

        if (dotNetCfg == null)
            dotNetCfg = new PlatformDotNetConfiguration();

        memMgr = new PlatformMemoryManagerImpl(gate, 1024);

        PlatformDotNetConfigurationEx dotNetCfg0 = new PlatformDotNetConfigurationEx(dotNetCfg, gate, memMgr);

        igniteCfg.setPlatformConfiguration(dotNetCfg0);

        // Check marshaller.
        Marshaller marsh = igniteCfg.getMarshaller();

        if (marsh == null) {
            igniteCfg.setMarshaller(new BinaryMarshaller());

            dotNetCfg0.warnings(Collections.singleton("Marshaller is automatically set to " +
                BinaryMarshaller.class.getName() + " (other nodes must have the same marshaller type)."));
        }
        else if (!(marsh instanceof BinaryMarshaller))
            throw new IgniteException("Unsupported marshaller (only " + BinaryMarshaller.class.getName() +
                " can be used when running Apache Ignite.NET): " + marsh.getClass().getName());

        BinaryConfiguration bCfg = igniteCfg.getBinaryConfiguration();

        if (bCfg == null) {
            bCfg = new BinaryConfiguration();

            bCfg.setCompactFooter(false);
            bCfg.setNameMapper(new BinaryBasicNameMapper(true));
            bCfg.setIdMapper(new BinaryBasicIdMapper(true));

            igniteCfg.setBinaryConfiguration(bCfg);

            dotNetCfg0.warnings(Collections.singleton("Binary configuration is automatically initiated, " +
                "note that binary name mapper is set to " + bCfg.getNameMapper()
                + " and binary ID mapper is set to " + bCfg.getIdMapper()
                + " (other nodes must have the same binary name and ID mapper types)."));
        }
        else {
            BinaryNameMapper nameMapper = bCfg.getNameMapper();

            if (nameMapper == null) {
                bCfg.setNameMapper(new BinaryBasicNameMapper(true));

                dotNetCfg0.warnings(Collections.singleton("Binary name mapper is automatically set to " +
                    bCfg.getNameMapper()
                    + " (other nodes must have the same binary name mapper type)."));
            }

            BinaryIdMapper idMapper = bCfg.getIdMapper();

            if (idMapper == null) {
                bCfg.setIdMapper(new BinaryBasicIdMapper(true));

                dotNetCfg0.warnings(Collections.singleton("Binary ID mapper is automatically set to " +
                    bCfg.getIdMapper()
                    + " (other nodes must have the same binary ID mapper type)."));
            }
        }

        if (bCfg.isCompactFooter())
            throw new IgniteException("Unsupported " + BinaryMarshaller.class.getName() +
                " \"compactFooter\" flag: must be false when running Apache Ignite.NET.");

        // Set Ignite home so that marshaller context works.
        String ggHome = igniteCfg.getIgniteHome();

        if (ggHome == null)
            ggHome = U.getIgniteHome();
        else
            // If user provided IGNITE_HOME - set it as a system property.
            U.setIgniteHome(ggHome);

        try {
            U.setWorkDirectory(igniteCfg.getWorkDirectory(), ggHome);
        }
        catch (IgniteCheckedException e) {
            throw U.convertException(e);
        }

        // 4. Callback to .Net.
        prepare(igniteCfg, dotNetCfg0);
    }

    /**
     * Prepare .Net size.
     *
     * @param igniteCfg Ignite configuration.
     * @param interopCfg Interop configuration.
     */
    @SuppressWarnings("ConstantConditions")
    private void prepare(IgniteConfiguration igniteCfg, PlatformDotNetConfigurationEx interopCfg) {
        this.cfg = igniteCfg;

        try (PlatformMemory outMem = memMgr.allocate()) {
            try (PlatformMemory inMem = memMgr.allocate()) {
                PlatformOutputStream out = outMem.output();

                BinaryRawWriterEx writer = marshaller().writer(out);

                PlatformUtils.writeDotNetConfiguration(writer, interopCfg.unwrap());

                List<PlatformDotNetLifecycleBean> beans = beans(igniteCfg);

                writer.writeInt(beans.size());

                for (PlatformDotNetLifecycleBean bean : beans) {
                    writer.writeString(bean.getTypeName());
                    writer.writeMap(bean.getProperties());
                }

                out.synchronize();

                gate.extensionCallbackInLongLongOutLong(
                    PlatformUtils.OP_PREPARE_DOT_NET, outMem.pointer(), inMem.pointer());

                processPrepareResult(inMem.input());
            }
        }
    }

    /**
     * Process prepare result.
     *
     * @param in Input stream.
     */
    private void processPrepareResult(PlatformInputStream in) {
        assert cfg != null;

        List<PlatformDotNetLifecycleBean> beans = beans(cfg);
        List<PlatformLifecycleBean> newBeans = new ArrayList<>();

        int len = in.readInt();

        for (int i = 0; i < len; i++) {
            if (i < beans.size())
                // Existing bean.
                beans.get(i).initialize(gate, in.readLong());
            else
                // This bean is defined in .Net.
                newBeans.add(new PlatformLifecycleBean(gate, in.readLong()));
        }

        if (!newBeans.isEmpty()) {
            LifecycleBean[] newBeans0 = newBeans.toArray(new LifecycleBean[newBeans.size()]);

            // New beans were added. Let's append them to the tail of the rest configured lifecycle beans.
            LifecycleBean[] oldBeans = cfg.getLifecycleBeans();

            if (oldBeans == null)
                cfg.setLifecycleBeans(newBeans0);
            else {
                LifecycleBean[] mergedBeans = new LifecycleBean[oldBeans.length + newBeans.size()];

                System.arraycopy(oldBeans, 0, mergedBeans, 0, oldBeans.length);
                System.arraycopy(newBeans0, 0, mergedBeans, oldBeans.length, newBeans0.length);

                cfg.setLifecycleBeans(mergedBeans);
            }
        }
    }

    /**
     * Find .Net lifecycle beans in configuration.
     *
     * @param cfg Configuration.
     * @return Beans.
     */
    private static List<PlatformDotNetLifecycleBean> beans(IgniteConfiguration cfg) {
        List<PlatformDotNetLifecycleBean> res = new ArrayList<>();

        if (cfg.getLifecycleBeans() != null) {
            for (LifecycleBean bean : cfg.getLifecycleBeans()) {
                if (bean instanceof PlatformDotNetLifecycleBean)
                    res.add((PlatformDotNetLifecycleBean)bean);
            }
        }

        return res;
    }

    /**
     * Create binary marshaller.
     *
     * @return Marshaller.
     */
    @SuppressWarnings("deprecation")
    private static GridBinaryMarshaller marshaller() {
        try {
            BinaryContext ctx =
                new BinaryContext(BinaryNoopMetadataHandler.instance(), new IgniteConfiguration(), new NullLogger());

            BinaryMarshaller marsh = new BinaryMarshaller();

            marsh.setContext(new MarshallerContextImpl(null));

            ctx.configure(marsh, new IgniteConfiguration());

            return new GridBinaryMarshaller(ctx);
        }
        catch (IgniteCheckedException e) {
            throw U.convertException(e);
        }
    }
}
