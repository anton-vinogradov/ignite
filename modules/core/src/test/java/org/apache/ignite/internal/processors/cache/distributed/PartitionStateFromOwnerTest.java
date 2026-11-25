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

import java.util.Collections;
import java.util.UUID;
import java.util.concurrent.BlockingQueue;
import java.util.concurrent.LinkedBlockingQueue;
import java.util.concurrent.TimeUnit;
import org.apache.ignite.cache.PartitionLossPolicy;
import org.apache.ignite.configuration.CacheConfiguration;
import org.apache.ignite.configuration.IgniteConfiguration;
import org.apache.ignite.events.CacheEvent;
import org.apache.ignite.internal.IgniteEx;
import org.apache.ignite.internal.IgniteInternalFuture;
import org.apache.ignite.internal.TestRecordingCommunicationSpi;
import org.apache.ignite.internal.processors.affinity.AffinityTopologyVersion;
import org.apache.ignite.internal.processors.cache.CacheGroupContext;
import org.apache.ignite.internal.processors.cache.distributed.dht.preloader.GridDhtPartitionsExchangeFuture;
import org.apache.ignite.internal.processors.cache.distributed.dht.preloader.GridDhtPartitionsFullMessage;
import org.apache.ignite.internal.util.future.GridFutureAdapter;
import org.apache.ignite.testframework.GridTestUtils;
import org.apache.ignite.testframework.junits.common.GridCommonAbstractTest;
import org.apache.ignite.transactions.Transaction;
import org.apache.ignite.util.AttributeNodeFilter;
import org.junit.Test;

import static org.apache.ignite.cache.CacheAtomicityMode.TRANSACTIONAL;
import static org.apache.ignite.cache.PartitionLossPolicy.IGNORE;
import static org.apache.ignite.cache.PartitionLossPolicy.READ_WRITE_SAFE;
import static org.apache.ignite.events.EventType.EVT_CACHE_STARTED;
import static org.apache.ignite.internal.GridTopic.TOPIC_CACHE;
import static org.apache.ignite.internal.processors.cache.GridCacheIoManager.COMMON_MESSAGE_HANDLER_ID;
import static org.apache.ignite.testframework.GridTestUtils.waitForCondition;
import static org.apache.ignite.transactions.TransactionConcurrency.PESSIMISTIC;
import static org.apache.ignite.transactions.TransactionIsolation.REPEATABLE_READ;

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

    /** {@inheritDoc} */
    @Override protected IgniteConfiguration getConfiguration(String igniteInstanceName) throws Exception {
        boolean data = !igniteInstanceName.equals(getTestIgniteInstanceName(NO_DATA));

        IgniteConfiguration cfg = super.getConfiguration(igniteInstanceName)
            .setCommunicationSpi(new TestRecordingCommunicationSpi())
            .setUserAttributes(Collections.singletonMap(DATA_ATTR, data));

        if (!data)
            return cfg;

        // A node with the cache in its configuration starts it on join, even outside the node filter.
        return cfg.setCacheConfiguration(new CacheConfiguration<Integer, Integer>(CACHE)
            .setBackups(0)
            .setAtomicityMode(TRANSACTIONAL)
            .setPartitionLossPolicy(plc)
            .setNodeFilter(new AttributeNodeFilter(DATA_ATTR, true)));
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
     * Two servers stop while a client transaction is open, so they leave in one merged exchange, and the coordinator
     * becomes the only new owner. A server outside the node filter defers the maps it gets during the exchange: the
     * coordinator's refresh with the initial version and its send at the end of the exchange with the result version.
     * Then it starts the cache and copies the partition map it kept without the cache.
     *
     * @throws Exception If failed.
     */
    @Test
    public void testLostPartitionOwnedInMergedExchange() throws Exception {
        plc = IGNORE;

        IgniteEx crd = startGrids(3);
        IgniteEx cln = startClientGrid(3);
        IgniteEx noData = startGrid(NO_DATA);

        awaitPartitionMapExchange(true, true, null);

        CacheGroupContext grp = crd.cachex(CACHE).context().group();

        // Hold the exchange reply and background refreshes. Only the two single-group maps may reach this server.
        TestRecordingCommunicationSpi spi = TestRecordingCommunicationSpi.spi(crd);
        UUID observerId = noData.localNode().id();
        spi.blockMessages((node, msg) -> node.id().equals(observerId)
            && msg instanceof GridDhtPartitionsFullMessage full && !isSingleGroupRefresh(full, grp.groupId()));

        BlockingQueue<AffinityTopologyVersion> received = new LinkedBlockingQueue<>();
        UUID crdId = crd.localNode().id();
        noData.context().io().addMessageListener(TOPIC_CACHE, (nodeId, msg, plc) -> {
            if (crdId.equals(nodeId) && msg instanceof GridDhtPartitionsFullMessage full
                && isSingleGroupRefresh(full, grp.groupId()))
                received.add(full.topologyVersion());
        });

        var crdExch = crd.context().cache().context().exchange();
        var observerExch = noData.context().cache().context().exchange();
        AffinityTopologyVersion firstLeave = new AffinityTopologyVersion(crd.cluster().topologyVersion() + 1);
        AffinityTopologyVersion bothLeft = new AffinityTopologyVersion(firstLeave.topologyVersion() + 1);
        Integer key = primaryKey(crd.cache(CACHE));
        long timeout = getPartitionMapExchangeTimeout();

        try (Transaction tx = cln.transactions().txStart(PESSIMISTIC, REPEATABLE_READ)) {
            cln.cache(CACHE).put(key, key);

            stopGrid(getTestIgniteInstanceName(2), true, false);
            stopGrid(getTestIgniteInstanceName(1), true, false);

            noData.context().discovery().topologyFuture(bothLeft.topologyVersion()).get(timeout);
            assertTrue("The servers did not start the exchange for the first departure", waitForCondition(() ->
                crdExch.lastTopologyFuture().initialVersion().equals(firstLeave)
                    && observerExch.lastTopologyFuture().initialVersion().equals(firstLeave), timeout));

            // The transaction holds the exchange while the coordinator sends a refresh with its initial version.
            crdExch.refreshPartitions(Collections.singleton(grp));
            assertEquals(firstLeave, received.poll(timeout, TimeUnit.MILLISECONDS));

            tx.commit();
        }

        assertEquals(bothLeft, received.poll(timeout, TimeUnit.MILLISECONDS));

        spi.stopBlock(true, m -> ((GridDhtPartitionsFullMessage)m.ioMessage().message()).exchangeId() != null, false, true);

        awaitPartitionMapsMatchLocalStates(CACHE);

        GridDhtPartitionsExchangeFuture exchFut = crdExch.lastFinishedFuture();
        assertEquals(firstLeave, exchFut.initialVersion());
        assertEquals(bothLeft, exchFut.topologyVersion());

        noData.cache(CACHE);

        awaitPartitionMapsMatchLocalStates(CACHE);
    }

    /** A cache opened outside its node filter must see an owner update that arrived during startup. */
    @Test
    public void testOwnerUpdateDuringCacheStart() throws Exception {
        plc = IGNORE;

        IgniteEx crd = startGrids(2);
        IgniteEx observer = startGrid(NO_DATA);
        GridDhtPartitionsFullMessage update = holdOwnerUpdateOnServerLeft(crd, observer);

        observer.events().enableLocal(EVT_CACHE_STARTED);
        observer.events().localListen((CacheEvent evt) -> {
            if (!CACHE.equals(evt.cacheName()))
                return true;

            // The group is published. Its DHT topology still needs the map kept before the cache opened.
            observer.context().cache().context().io()
                .cacheHandler(COMMON_MESSAGE_HANDLER_ID, GridDhtPartitionsFullMessage.class)
                .apply(crd.localNode().id(), update);

            return false;
        }, EVT_CACHE_STARTED);

        observer.cache(CACHE);

        awaitPartitionMapsMatchLocalStates(CACHE);
    }

    /** An owner update accepted before a client joins must survive the exchange for that join. */
    @Test
    public void testOwnerUpdateDuringClientJoin() throws Exception {
        plc = IGNORE;

        IgniteEx crd = startGrids(2);
        IgniteEx observer = startGrid(NO_DATA);
        observer.cache(CACHE);

        UUID crdId = crd.localNode().id();
        String otherCache = "unopened";
        crd.getOrCreateCache(new CacheConfiguration<>(otherCache).setNodeFilter(node -> node.id().equals(crdId)));

        GridDhtPartitionsFullMessage update = holdOwnerUpdateOnServerLeft(crd, observer);

        var exch = observer.context().cache().context().exchange();
        var top = observer.cachex(CACHE).context().topology();
        var otherTop = exch.clientTopologyIfExists(crd.cachex(otherCache).context().groupId());

        assertNotNull(otherTop);

        IgniteInternalFuture<?> join;

        // The exchange updates DHT topologies before client topologies. Hold it between updating the
        // cache's topology version and marking that version ready.
        otherTop.readLock();

        try {
            join = GridTestUtils.runAsync(() -> startClientGrid(3));

            assertTrue(waitForCondition(() -> top.readyTopologyVersion().before(top.lastTopologyChangeVersion()),
                getTestTimeout()));

            // Resume a refresh whose receiver checked the previous exchange before the client joined.
            exch.processFullPartitionUpdate(crd.localNode(), update);
        }
        finally {
            otherTop.readUnlock();
        }

        join.get(getTestTimeout());

        awaitPartitionMapsMatchLocalStates(CACHE);
    }

    /** Holds the coordinator's owner update and later resends so they cannot repair the observer's map. */
    private GridDhtPartitionsFullMessage holdOwnerUpdateOnServerLeft(IgniteEx crd, IgniteEx observer) throws Exception {
        awaitPartitionMapExchange(true, true, null);

        AffinityTopologyVersion leftVer = new AffinityTopologyVersion(crd.cluster().topologyVersion() + 1);
        UUID observerId = observer.localNode().id();
        int grpId = crd.cachex(CACHE).context().groupId();
        GridFutureAdapter<GridDhtPartitionsFullMessage> ownerUpdate = new GridFutureAdapter<>();

        TestRecordingCommunicationSpi.spi(crd).blockMessages((node, msg) -> {
            if (!node.id().equals(observerId) || !(msg instanceof GridDhtPartitionsFullMessage full)
                || full.exchangeId() != null)
                return false;

            if (isSingleGroupRefresh(full, grpId) && leftVer.equals(full.topologyVersion()))
                ownerUpdate.onDone(full);

            return true;
        });

        stopGrid(1);

        observer.context().cache().context().exchange().affinityReadyFuture(leftVer).get(getTestTimeout());

        return ownerUpdate.get(getTestTimeout());
    }

    /** A periodic refresh also includes the utility cache. */
    private static boolean isSingleGroupRefresh(GridDhtPartitionsFullMessage full, int grpId) {
        return full.exchangeId() == null && full.partitions().size() == 1 && full.containsGroup(grpId);
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
