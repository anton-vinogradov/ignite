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

import java.util.List;
import java.util.concurrent.CountDownLatch;
import org.apache.ignite.Ignite;
import org.apache.ignite.IgniteCache;
import org.apache.ignite.cluster.ClusterNode;
import org.apache.ignite.internal.IgniteEx;
import org.apache.ignite.internal.IgniteInternalFuture;
import org.apache.ignite.internal.IgnitionEx;
import org.apache.ignite.internal.NodeStoppingException;
import org.apache.ignite.internal.TestRecordingCommunicationSpi;
import org.apache.ignite.internal.processors.cache.distributed.dht.GridDhtTxPrepareRequest;
import org.apache.ignite.internal.processors.cache.transactions.TransactionProxyImpl;
import org.apache.ignite.internal.util.typedef.G;
import org.apache.ignite.lang.IgniteBiPredicate;
import org.apache.ignite.plugin.extensions.communication.Message;
import org.apache.ignite.transactions.Transaction;
import org.junit.Test;

/**
 *
 */
public class GridExchangeFreeCellularSwitchTxCountersTest extends GridExchangeFreeCellularSwitchAbstractTest {
    /**
     *
     */
    @Test
    public void testPartitionCountersSynchronizationOnPmeFreeSwitch() throws Exception {
        int nodes = 6;

        startGridsMultiThreaded(nodes);

        CellularCluster cluster = resolveCellularCluster(nodes, TransactionCoordinatorNode.FAILED);

        Ignite orig = cluster.orig;
        Ignite failed = cluster.failed;
        List<Ignite> brokenCellNodes = cluster.brokenCellNodes;

        List<Integer> keys;
        List<Integer> putKeys;
        List<Integer> partialPreparedKeys1;
        List<Integer> preparedKeys;
        List<Integer> partialPreparedKeys2;

        int part = -1;

        do {
            keys = partitionKeys(failed.getOrCreateCache(PART_CACHE_NAME), ++part, 40, 0);
        }
        while (!(failed.equals(primaryNode(keys.get(0), PART_CACHE_NAME))));

        putKeys = keys.subList(0, 10);
        partialPreparedKeys1 = keys.subList(10, 20);
        preparedKeys = keys.subList(20, 30);
        partialPreparedKeys2 = keys.subList(30, 40);

        IgniteCache<Integer, Integer> failedCache = failed.getOrCreateCache(PART_CACHE_NAME);

        // Regular put.
        for (Integer key : putKeys)
            failedCache.put(key, key);

        // Partial prepare #1.
        CountDownLatch prepMsgLatch1 = new CountDownLatch(brokenCellNodes.size() /*one per node*/);

        blockPrepareMessages(brokenCellNodes.get(0), prepMsgLatch1);

        IgniteInternalFuture<?> hangedPrepFut1 = partialPrepare(partialPreparedKeys1, failed);

        prepMsgLatch1.await();

        stopBlockingPrepareMessages();

        // Regular prepare.
        CountDownLatch nodeFailedLatch = new CountDownLatch(1);

        IgniteInternalFuture<?> prepFut = prepare(preparedKeys, orig, nodeFailedLatch);

        // Partial prepare #2.
        CountDownLatch prepMsgLatch2 = new CountDownLatch(brokenCellNodes.size() /*one per node*/);

        blockPrepareMessages(brokenCellNodes.get(0), prepMsgLatch2);

        IgniteInternalFuture<?> hangedPrepFut2 = partialPrepare(partialPreparedKeys2, failed);

        prepMsgLatch2.await();

        stopBlockingPrepareMessages();

        assertCountersAsExpected(part, false, PART_CACHE_NAME, 10, -1 /*ignored*/);

        failed.close(); // Stopping node.

        nodeFailedLatch.countDown();

        hangedPrepFut1.get();
        prepFut.get();
        hangedPrepFut2.get();

        waitForTopology(nodes - 1);

        awaitPartitionMapExchange();

//        for (Ignite ignite : G.allGrids()) {
//            IgniteCache<Integer, Integer> cache = ignite.getOrCreateCache(PART_CACHE_NAME);
//
//            for (Integer key : putKeys)
//                assertEquals(key, cache.get(key));
//
//            for (Integer key : partialPreparedKeys1)
//                assertEquals(null, cache.get(key));
//
//            for (Integer key : preparedKeys)
//                assertEquals(key, cache.get(key));
//
//            for (Integer key : partialPreparedKeys2)
//                assertEquals(null, cache.get(key));
//        }

        Throwable th = null;

        for (int i = 0; i < 100; i++)
            try {
                assertPartitionsSame(idleVerify(brokenCellNodes.get(0), PART_CACHE_NAME));
            }
            catch (Throwable t) {
                log.error("Happen " + i, t);

                th = t;
            }

        assertCountersAsExpected(part, true, PART_CACHE_NAME, 30, 30);

        if (th != null)
            throw new RuntimeException(th);
    }

    /**
     *
     */
    private IgniteInternalFuture<?> prepare(List<Integer> keys, Ignite node, CountDownLatch nodeFailedLatch) throws Exception {
        CountDownLatch initLatch = new CountDownLatch(1);

        IgniteInternalFuture<?> fut = multithreadedAsync(() -> {
            try {
                IgniteCache<Integer, Integer> cache = node.getOrCreateCache(PART_CACHE_NAME);

                Transaction tx = node.transactions().txStart();

                for (Integer key : keys)
                    cache.put(key, key);

                ((TransactionProxyImpl<?, ?>)tx).tx().prepare(true);

                initLatch.countDown();

                nodeFailedLatch.await();
            }
            catch (Exception e) {
                fail("Should not happen [exception=" + e + "]");
            }
        }, 1);

        initLatch.await();

        return fut;
    }

    /**
     *
     */
    private IgniteInternalFuture<?> partialPrepare(List<Integer> keys, Ignite node) throws Exception {
        IgniteInternalFuture<?> fut = multithreadedAsync(() -> {
            try {
                IgniteCache<Integer, Integer> cache = node.getOrCreateCache(PART_CACHE_NAME);

                Transaction tx = node.transactions().txStart();

                for (Integer key : keys)
                    cache.put(key, key);

                ((TransactionProxyImpl<?, ?>)tx).tx().prepare(true);

                fail("Should hang before this line since one prepare message is blocked.");
            }
            catch (NodeStoppingException ignored) {
                // No-op.
            }
            catch (Exception e) {
                fail("Should not happen [exception=" + e + "]");
            }
        }, 1);

        return fut;
    }

    /**
     *
     */
    protected void blockPrepareMessages(Ignite igniteTo, CountDownLatch prepMsgLatch) {
        for (Ignite ignite : G.allGrids()) {
            TestRecordingCommunicationSpi spi =
                (TestRecordingCommunicationSpi)ignite.configuration().getCommunicationSpi();

            spi.blockMessages(new IgniteBiPredicate<ClusterNode, Message>() {
                @Override public boolean apply(ClusterNode node, Message msg) {
                    if (msg instanceof GridDhtTxPrepareRequest) {
                        IgniteEx to = IgnitionEx.gridxx(node.id());

                        assert prepMsgLatch.getCount() > 0;

                        prepMsgLatch.countDown();

                        return to.equals(igniteTo);
                    }

                    return false;
                }
            });
        }
    }

    /**
     *
     */
    protected void stopBlockingPrepareMessages() {
        for (Ignite ignite : G.allGrids()) {
            TestRecordingCommunicationSpi spi =
                (TestRecordingCommunicationSpi)ignite.configuration().getCommunicationSpi();

            spi.stopBlock(false, blockedMsg -> true);
        }
    }
}
