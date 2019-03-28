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

package org.apache.ignite.internal.processors.cache.consistency;

import java.util.ArrayList;
import java.util.Collection;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.ThreadLocalRandom;
import java.util.function.Consumer;
import javax.cache.CacheException;
import org.apache.ignite.Ignite;
import org.apache.ignite.IgniteCache;
import org.apache.ignite.cache.CacheEntry;
import org.apache.ignite.configuration.CacheConfiguration;
import org.apache.ignite.configuration.IgniteConfiguration;
import org.apache.ignite.internal.IgniteEx;
import org.apache.ignite.internal.processors.affinity.AffinityTopologyVersion;
import org.apache.ignite.internal.processors.cache.CacheObjectImpl;
import org.apache.ignite.internal.processors.cache.GridCacheAdapter;
import org.apache.ignite.internal.processors.cache.GridCacheEntryEx;
import org.apache.ignite.internal.processors.cache.IgniteInternalCache;
import org.apache.ignite.internal.processors.cache.version.GridCacheVersionManager;
import org.apache.ignite.internal.processors.dr.GridDrType;
import org.apache.ignite.internal.util.typedef.G;
import org.apache.ignite.testframework.junits.common.GridCommonAbstractTest;

import static org.apache.ignite.cache.CacheAtomicityMode.TRANSACTIONAL;
import static org.apache.ignite.cache.CacheMode.PARTITIONED;
import static org.apache.ignite.cache.CacheWriteSynchronizationMode.FULL_SYNC;

/**
 *
 */
public abstract class AbstractCacheConsistencyTest extends GridCommonAbstractTest {
    /**
     *
     */
    protected static final Consumer<ConsistencyRecoveryData> GET_CHECK_AND_FIX = (data) -> {
        IgniteCache<Integer, Integer> cache = data.cache;
        Set<Integer> keys = data.data.keySet();
        Boolean raw = data.raw;

        assert keys.size() == 1;

        for (Map.Entry<Integer, InconsistencyValuesMapping> entry : data.data.entrySet()) { // Once.
            try {
                Integer key = entry.getKey();
                Integer latest = entry.getValue().latest;

                Integer res = raw ?
                    cache.withConsistency().getEntry(key).getValue() :
                    cache.withConsistency().get(key);

                assertEquals(latest, res);
            }
            catch (CacheException e) {
                fail("Should not happen." + e);
            }
        }
    };

    /**
     *
     */
    protected static final Consumer<ConsistencyRecoveryData> GETALL_CHECK_AND_FIX = (data) -> {
        IgniteCache<Integer, Integer> cache = data.cache;
        Set<Integer> keys = data.data.keySet();
        Boolean raw = data.raw;

        assert !keys.isEmpty();

        try {
            if (raw) {
                Collection<CacheEntry<Integer, Integer>> res = cache.withConsistency().getEntries(keys);

                for (CacheEntry<Integer, Integer> entry : res)
                    assertEquals(data.data.get(entry.getKey()).latest, entry.getValue());
            }
            else {
                Map<Integer, Integer> res = cache.withConsistency().getAll(keys);

                for (Map.Entry<Integer, Integer> entry : res.entrySet())
                    assertEquals(data.data.get(entry.getKey()).latest, entry.getValue());
            }
        }
        catch (CacheException e) {
            fail("Should not happen." + e);
        }
    };

    /**
     *
     */
    protected static final Consumer<ConsistencyRecoveryData> GET_NULL = (data) -> {
        IgniteCache<Integer, Integer> cache = data.cache;
        Set<Integer> keys = data.data.keySet();
        Boolean raw = data.raw;

        assert keys.size() == 1;

        for (Map.Entry<Integer, InconsistencyValuesMapping> entry : data.data.entrySet()) { // Once.
            try {
                Integer key = entry.getKey() * -1; // Negative.

                Object res = raw ?
                    cache.withConsistency().getEntry(key) :
                    cache.withConsistency().get(key);

                assertEquals(null, res);
            }
            catch (CacheException e) {
                fail("Should not happen." + e);
            }
        }
    };

    /**
     *
     */
    protected static final Consumer<ConsistencyRecoveryData> ENSURE_FIXED = (data) -> {
        IgniteCache<Integer, Integer> cache = data.cache;
        Boolean raw = data.raw;

        for (Map.Entry<Integer, InconsistencyValuesMapping> entry : data.data.entrySet()) {
            try {
                Integer key = entry.getKey();
                Integer latest = entry.getValue().latest;

                Integer res = raw ?
                    cache.getEntry(key).getValue() :
                    cache.get(key);

                assertEquals(latest, res);
            }
            catch (CacheException e) {
                fail("Should not happen." + e);
            }
        }
    };

    /** Key. */
    protected static int iterableKey;

    /** Is client flag. */
    protected boolean client;

    /** Backups count. */
    protected Integer backupsCount() {
        return 3;
    }

    /** {@inheritDoc} */
    @Override protected void beforeTestsStarted() throws Exception {
        super.beforeTestsStarted();

        startGrids(7);

        grid(0).getOrCreateCache(cacheConfiguration());

        client = true;

        startGrid(G.allGrids().size() + 1);
        startGrid(G.allGrids().size() + 1);

        awaitPartitionMapExchange();
    }

    /** {@inheritDoc} */
    @Override protected void afterTestsStopped() throws Exception {
        super.afterTestsStopped();

        log.info("Checked " + iterableKey + " keys");

        stopAllGrids();
    }

    /**
     *
     */
    protected CacheConfiguration<Integer, Integer> cacheConfiguration() {
        CacheConfiguration<Integer, Integer> cfg = new CacheConfiguration<>(DEFAULT_CACHE_NAME);

        cfg.setWriteSynchronizationMode(FULL_SYNC);
        cfg.setCacheMode(PARTITIONED);
        cfg.setAtomicityMode(TRANSACTIONAL);
        cfg.setBackups(backupsCount());

        return cfg;
    }

    /** {@inheritDoc} */
    @Override protected IgniteConfiguration getConfiguration(String igniteInstanceName) throws Exception {
        IgniteConfiguration cfg = super.getConfiguration(igniteInstanceName);

        cfg.setClientMode(client);

        return cfg;
    }

    /**
     *
     */
    protected void prepareAndCheck(
        Ignite initiator,
        Integer cnt,
        boolean raw,
        Consumer<ConsistencyRecoveryData> c)
        throws Exception {
        IgniteCache<Integer, Integer> cache = initiator.getOrCreateCache(DEFAULT_CACHE_NAME);

        for (int i = 0; i < 10; i++) {
            Map<Integer, InconsistencyValuesMapping> results = new HashMap<>();

            for (int j = 0; j < cnt; j++) {
                InconsistencyValuesMapping res = setDifferentValuesForSameKey(++iterableKey);

                results.put(iterableKey, res);
            }

            for (Ignite node : G.allGrids()) {
                Map<Integer, Integer> all =
                    node.<Integer, Integer>getOrCreateCache(DEFAULT_CACHE_NAME).getAll(results.keySet());

                for (Map.Entry<Integer, Integer> entry : all.entrySet()) {
                    Integer key = entry.getKey();
                    Integer val = entry.getValue();

                    Integer exp = results.get(key).mapping.get(node); // Should read from itself (backup or primary).

                    if (exp == null)
                        exp = results.get(key).primary; // Should read from primary (not a partition owner).

                    assertEquals(exp, val);
                }
            }

            c.accept(new ConsistencyRecoveryData(cache, results, raw));
        }
    }

    /**
     *
     */
    private InconsistencyValuesMapping setDifferentValuesForSameKey(
        int key) throws Exception {
        List<Ignite> nodes = new ArrayList<>();
        Map<Ignite, Integer> mapping = new HashMap<>();

        boolean reverse = ThreadLocalRandom.current().nextBoolean();

        Ignite primary = primaryNode(key, DEFAULT_CACHE_NAME);

        if (reverse) {
            nodes.addAll(backupNodes(key, DEFAULT_CACHE_NAME));
            nodes.add(primary);
        }
        else {
            nodes.add(primary);
            nodes.addAll(backupNodes(key, DEFAULT_CACHE_NAME));
        }

        boolean random = ThreadLocalRandom.current().nextBoolean();

        if (random) {
            Map<Integer, Ignite> nodes0 = new HashMap<>();

            for (Ignite node : nodes) {
                while (true) {
                    int idx = ThreadLocalRandom.current().nextInt(nodes.size());

                    if (nodes0.get(idx) == null) {
                        nodes0.put(idx, node);

                        break;
                    }
                }
            }

            nodes = new ArrayList<>();

            for (int i = 0; i < nodes0.size(); i++)
                nodes.add(nodes0.get(i));
        }

        GridCacheVersionManager mgr =
            ((GridCacheAdapter)(grid(1)).cachex(DEFAULT_CACHE_NAME).cache()).context().shared().versions();

        int val = 0;
        int primVal = -1;

        for (Ignite node : nodes) {
            IgniteInternalCache cache = ((IgniteEx)node).cachex(DEFAULT_CACHE_NAME);

            GridCacheAdapter adapter = ((GridCacheAdapter)cache.cache());

            GridCacheEntryEx entry = adapter.entryEx(key);

            boolean init = entry.initialValue(
                new CacheObjectImpl(++val, null), // Incremental value.
                mgr.next(), // Incremental version.
                0,
                0,
                false,
                AffinityTopologyVersion.NONE,
                GridDrType.DR_NONE,
                false);

            assertTrue("iterableKey " + key + " already inited", init);

            mapping.put(node, val);

            if (node.equals(primary))
                primVal = val;
        }

        assertEquals(nodes.size(), new HashSet<>(mapping.values()).size()); // Each node have unique value.

        assert primVal != -1;

        return new InconsistencyValuesMapping(mapping, primVal, val);
    }

    /**
     *
     */
    protected static final class ConsistencyRecoveryData {
        /** Initiator's cache. */
        IgniteCache<Integer, Integer> cache;

        /** Generated data across topology per key mapping. */
        Map<Integer, InconsistencyValuesMapping> data;

        /** Raw read flag. True means required GetEntry() instead of get(). */
        Boolean raw;

        /**
         *
         */
        public ConsistencyRecoveryData(
            IgniteCache<Integer, Integer> cache,
            Map<Integer, InconsistencyValuesMapping> data,
            Boolean raw) {
            this.cache = cache;
            this.data = new HashMap<>(data);
            this.raw = raw;
        }
    }

    /**
     *
     */
    protected static final class InconsistencyValuesMapping {
        /** Value per node. */
        Map<Ignite, Integer> mapping;

        /** Primary node's value. */
        Integer primary;

        /** Latest value across the topology. */
        Integer latest;

        /**
         *
         */
        public InconsistencyValuesMapping(Map<Ignite, Integer> mapping, Integer primary, Integer latest) {
            this.mapping = new HashMap<>(mapping);
            this.primary = primary;
            this.latest = latest;
        }
    }
}