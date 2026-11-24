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

package org.apache.ignite.internal.processors.cache.distributed;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import org.apache.ignite.cache.PartitionLossPolicy;
import org.apache.ignite.configuration.CacheConfiguration;
import org.apache.ignite.configuration.IgniteConfiguration;
import org.apache.ignite.events.DiscoveryEvent;
import org.apache.ignite.internal.IgniteEx;
import org.apache.ignite.internal.TestRecordingCommunicationSpi;
import org.apache.ignite.internal.processors.affinity.AffinityTopologyVersion;
import org.apache.ignite.internal.processors.cache.GridCachePartitionExchangeManager;
import org.apache.ignite.internal.processors.cache.distributed.dht.preloader.GridDhtPartitionsExchangeFuture;
import org.apache.ignite.internal.processors.cache.distributed.dht.preloader.GridDhtPartitionsFullMessage;
import org.apache.ignite.internal.util.typedef.internal.CU;
import org.apache.ignite.testframework.junits.common.GridCommonAbstractTest;
import org.apache.ignite.util.AttributeNodeFilter;
import org.junit.Test;

import static org.apache.ignite.cache.PartitionLossPolicy.IGNORE;
import static org.apache.ignite.cache.PartitionLossPolicy.READ_WRITE_SAFE;
import static org.apache.ignite.testframework.GridTestUtils.mergeExchangeWaitVersion;

/**
 * Checks that the other nodes learn the state of a lost partition from its new owner. A server leaves with the only
 * copies of some partitions. At the end of the exchange the new owners own them under the IGNORE policy or mark them
 * LOST under the safe policies. Only the owners write this state into their rows of the partition map.
 */
public class PartitionStateFromOwnerTest extends GridCommonAbstractTest {
    /** */
    private static final String CACHE = "cache";

    /** Attribute of the nodes that keep the cache's data. */
    private static final String DATA_ATTR = "data";

    /** Index of the server outside the cache's node filter. */
    private static final int NO_DATA = 4;

    /** Partition loss policy of the cache. */
    private PartitionLossPolicy plc;

    /** Whether to exercise delayed refreshes for a named cache group. */
    private boolean mergedExchange;

    /** {@inheritDoc} */
    @Override protected IgniteConfiguration getConfiguration(String igniteInstanceName) throws Exception {
        boolean data = !igniteInstanceName.equals(getTestIgniteInstanceName(NO_DATA));

        IgniteConfiguration cfg = super.getConfiguration(igniteInstanceName)
            .setUserAttributes(Collections.singletonMap(DATA_ATTR, data));

        if (mergedExchange)
            cfg.setCommunicationSpi(new TestRecordingCommunicationSpi());

        // A node with the cache in its configuration starts it on join, even outside the node filter.
        return data ? cfg.setCacheConfiguration(new CacheConfiguration<Integer, Integer>(CACHE)
            .setBackups(0)
            .setGroupName(mergedExchange ? "group" : null)
            .setPartitionLossPolicy(plc)
            .setNodeFilter(new AttributeNodeFilter(DATA_ATTR, true))) : cfg;
    }

    /** {@inheritDoc} */
    @Override protected void afterTest() throws Exception {
        stopAllGrids();

        super.afterTest();
    }

    /**
     * @throws Exception If failed.
     */
    @Test
    public void testLostPartitionOwned() throws Exception {
        checkServerLeft(IGNORE, 3);
    }

    /**
     * @throws Exception If failed.
     */
    @Test
    public void testLostPartitionMarkedLost() throws Exception {
        checkServerLeft(READ_WRITE_SAFE, 3);
    }

    /**
     * The coordinator is the only new owner, so only the client learns the state from another node.
     *
     * @throws Exception If failed.
     */
    @Test
    public void testLostPartitionOwnedByCoordinator() throws Exception {
        checkServerLeft(IGNORE, 2);
    }

    /**
     * Two servers leave in one merged exchange, and the coordinator becomes the only new owner. A server outside the
     * node filter receives a previous refresh and the owner's new map before its exchange completes. It then starts
     * the cache and copies the map it kept without the cache.
     *
     * @throws Exception If failed.
     */
    @Test
    public void testLostPartitionOwnedInMergedExchange() throws Exception {
        plc = IGNORE;
        mergedExchange = true;

        IgniteEx crd = startGrids(3);
        startClientGrid(3);
        IgniteEx noData = startGrid(NO_DATA);

        awaitPartitionMapExchange(true, true, null);

        assertNull(noData.cachex(CACHE));

        AffinityTopologyVersion resVer = new AffinityTopologyVersion(crd.cluster().topologyVersion() + 2, 0);
        List<DiscoveryEvent> merged = new ArrayList<>();

        GridCachePartitionExchangeManager<?, ?> exch = crd.context().cache().context().exchange();
        int grpId = crd.cachex(CACHE).context().groupId();

        // Take the map a background refresh would send before the departures.
        GridDhtPartitionsFullMessage before = exch.createPartitionsFullMessage(null, null, null, null,
            crd.context().cache().cacheGroups());
        before.topologyVersion(exch.readyAffinityVersion());

        TestRecordingCommunicationSpi spi = TestRecordingCommunicationSpi.spi(crd);

        spi.blockMessages(GridDhtPartitionsFullMessage.class, noData.name());

        spi.record((node, msg) -> {
            if (!node.equals(noData.localNode()) || !(msg instanceof GridDhtPartitionsFullMessage))
                return false;

            GridDhtPartitionsFullMessage full = (GridDhtPartitionsFullMessage)msg;

            // Only the user cache loses owners. A background refresh also includes the utility cache.
            return full.exchangeId() == null && full.containsGroup(grpId)
                && !full.containsGroup(CU.UTILITY_CACHE_GROUP_ID);
        });

        mergeExchangeWaitVersion(crd, resVer.topologyVersion(), merged);

        stopGrid(getTestIgniteInstanceName(2), true, false);
        stopGrid(getTestIgniteInstanceName(1), true, false);

        exch.affinityReadyFuture(resVer).get(getTestTimeout());

        assertEquals(1, merged.size());

        List<Object> updates = spi.recordedMessages(true);

        assertEquals(1, updates.size());

        GridDhtPartitionsFullMessage ownerUpdate = (GridDhtPartitionsFullMessage)updates.get(0);

        assertEquals(resVer, ownerUpdate.topologyVersion());

        // Deliver both refreshes to the pending exchange before releasing its reply. Other resends could mask a lost update.
        GridDhtPartitionsExchangeFuture pending = noData.context().cache().context().exchange().lastTopologyFuture();

        assertTrue(pending.addOrMergeDelayedFullMessage(crd.localNode(), before));
        assertTrue(pending.addOrMergeDelayedFullMessage(crd.localNode(), ownerUpdate));

        spi.stopBlock(true, m -> ((GridDhtPartitionsFullMessage)m.ioMessage().message()).exchangeId() != null, false, true);

        awaitPartitionMapsMatchLocalStates(CACHE);

        noData.cache(CACHE);

        awaitPartitionMapsMatchLocalStates(CACHE);
    }

    /**
     * Starts the servers and a client, then stops the last server.
     *
     * @param plc Partition loss policy.
     * @param srvs Number of servers.
     * @throws Exception If failed.
     */
    private void checkServerLeft(PartitionLossPolicy plc, int srvs) throws Exception {
        this.plc = plc;

        startGrids(srvs);
        startClientGrid(srvs);

        // A map resent after a late eviction would carry the new states and hide a missing send.
        awaitPartitionMapExchange(true, true, null);

        stopGrid(srvs - 1);

        awaitPartitionMapsMatchLocalStates(CACHE);
    }
}
