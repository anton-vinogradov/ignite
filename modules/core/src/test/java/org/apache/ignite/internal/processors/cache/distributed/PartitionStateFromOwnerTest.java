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
import java.util.List;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;
import java.util.function.Predicate;
import org.apache.ignite.cache.PartitionLossPolicy;
import org.apache.ignite.configuration.CacheConfiguration;
import org.apache.ignite.configuration.IgniteConfiguration;
import org.apache.ignite.events.DiscoveryEvent;
import org.apache.ignite.internal.IgniteEx;
import org.apache.ignite.internal.TestRecordingCommunicationSpi;
import org.apache.ignite.internal.processors.affinity.AffinityTopologyVersion;
import org.apache.ignite.internal.processors.cache.GridCachePartitionExchangeManager;
import org.apache.ignite.internal.processors.cache.distributed.dht.preloader.GridDhtPartitionsFullMessage;
import org.apache.ignite.internal.util.typedef.internal.CU;
import org.apache.ignite.testframework.junits.common.GridCommonAbstractTest;
import org.junit.Test;

import static org.apache.ignite.cache.PartitionLossPolicy.IGNORE;
import static org.apache.ignite.cache.PartitionLossPolicy.READ_WRITE_SAFE;
import static org.apache.ignite.internal.GridTopic.TOPIC_CACHE;
import static org.apache.ignite.testframework.GridTestUtils.mergeExchangeWaitVersion;
import static org.apache.ignite.testframework.GridTestUtils.waitForCondition;

/**
 * Checks that the other nodes learn the state of a lost partition from its new owner. A server leaves with the only
 * copies of some partitions. At the end of the exchange the new owners own them under the IGNORE policy or mark them
 * LOST under the safe policies. Only the owners write this state into their rows of the partition map.
 */
public class PartitionStateFromOwnerTest extends GridCommonAbstractTest {
    /** */
    private static final String CACHE = "cache";

    /** Partition loss policy of the cache. */
    private PartitionLossPolicy plc;

    /** {@inheritDoc} */
    @Override protected IgniteConfiguration getConfiguration(String igniteInstanceName) throws Exception {
        return super.getConfiguration(igniteInstanceName)
            .setCommunicationSpi(new TestRecordingCommunicationSpi())
            .setCacheConfiguration(new CacheConfiguration<Integer, Integer>(CACHE)
                .setGroupName("group")
                .setBackups(0)
                .setPartitionLossPolicy(plc));
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
        checkServerLeft(IGNORE);
    }

    /**
     * @throws Exception If failed.
     */
    @Test
    public void testLostPartitionMarkedLost() throws Exception {
        checkServerLeft(READ_WRITE_SAFE);
    }

    /**
     * A client buffers an old map and the coordinator's new owner map during the exchange for two server departures.
     *
     * @throws Exception If failed.
     */
    @Test
    public void testLostPartitionOwnedByCoordinator() throws Exception {
        plc = IGNORE;

        IgniteEx crd = startGrids(3);
        IgniteEx client = startClientGrid(3, (IgniteConfiguration cfg) -> cfg.setCacheConfiguration());

        awaitPartitionMapExchange(true, true, null);
        assertNull(client.cachex(CACHE));

        GridCachePartitionExchangeManager<?, ?> exch = crd.context().cache().context().exchange();
        AffinityTopologyVersion oldVer = exch.readyAffinityVersion();
        AffinityTopologyVersion resVer = new AffinityTopologyVersion(oldVer.topologyVersion() + 2, 0);
        TestRecordingCommunicationSpi spi = TestRecordingCommunicationSpi.spi(crd);
        CountDownLatch ownerReceived = new CountDownLatch(1);

        spi.blockMessages((node, msg) -> node.equals(client.localNode()) && msg instanceof GridDhtPartitionsFullMessage
            && (((GridDhtPartitionsFullMessage)msg).exchangeId() == null || ownerReceived.getCount() != 0));
        exch.refreshPartitions();

        List<DiscoveryEvent> merged = new ArrayList<>();

        mergeExchangeWaitVersion(crd, resVer.topologyVersion(), merged);

        stopGrid(getTestIgniteInstanceName(2), true, false);
        stopGrid(getTestIgniteInstanceName(1), true, false);

        exch.affinityReadyFuture(resVer).get(getTestTimeout());
        assertEquals(1, merged.size());

        GridCachePartitionExchangeManager<?, ?> clientExch = client.context().cache().context().exchange();

        assertTrue(waitForCondition(() -> clientExch.lastTopologyFuture().initialVersion().compareTo(oldVer) > 0
            && !clientExch.lastTopologyFuture().isDone(), getPartitionMapExchangeTimeout()));

        CountDownLatch oldReceived = new CountDownLatch(1);

        client.context().io().addMessageListener(TOPIC_CACHE, (node, msg, plc) -> {
            if (msg instanceof GridDhtPartitionsFullMessage) {
                GridDhtPartitionsFullMessage full = (GridDhtPartitionsFullMessage)msg;

                if (full.exchangeId() == null) {
                    if (oldVer.equals(full.topologyVersion()))
                        oldReceived.countDown();
                    else if (!full.containsGroup(CU.UTILITY_CACHE_GROUP_ID))
                        ownerReceived.countDown();
                }
            }
        });

        // Deliver both refreshes before the exchange reply. Hold background refreshes, which include the utility cache.
        releaseMaps(spi, msg -> msg.exchangeId() == null && oldVer.equals(msg.topologyVersion()));
        assertTrue("Client did not receive the old map",
            oldReceived.await(getPartitionMapExchangeTimeout(), TimeUnit.MILLISECONDS));

        releaseMaps(spi, msg -> msg.exchangeId() == null && !msg.containsGroup(CU.UTILITY_CACHE_GROUP_ID));
        assertTrue("Client did not receive the owner's update",
            ownerReceived.await(getPartitionMapExchangeTimeout(), TimeUnit.MILLISECONDS));

        releaseMaps(spi, msg -> msg.exchangeId() != null);

        awaitPartitionMapsMatchLocalStates(CACHE);
    }

    /** Sends matching full maps to the client and keeps all other maps blocked. */
    private static void releaseMaps(TestRecordingCommunicationSpi spi, Predicate<GridDhtPartitionsFullMessage> match) {
        spi.stopBlock(true, m -> match.test((GridDhtPartitionsFullMessage)m.ioMessage().message()), false, true);
    }

    /**
     * Starts the servers and a client, then stops the last server.
     *
     * @param plc Partition loss policy.
     * @throws Exception If failed.
     */
    private void checkServerLeft(PartitionLossPolicy plc) throws Exception {
        this.plc = plc;

        startGrids(3);
        startClientGrid(3);

        // A map resent after a late eviction would carry the new states and hide a missing send.
        awaitPartitionMapExchange(true, true, null);

        stopGrid(2);

        awaitPartitionMapsMatchLocalStates(CACHE);
    }
}
