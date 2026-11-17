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

import org.apache.ignite.cache.PartitionLossPolicy;
import org.apache.ignite.configuration.CacheConfiguration;
import org.apache.ignite.configuration.IgniteConfiguration;
import org.apache.ignite.testframework.junits.common.GridCommonAbstractTest;
import org.junit.Test;

import static org.apache.ignite.cache.PartitionLossPolicy.IGNORE;
import static org.apache.ignite.cache.PartitionLossPolicy.READ_WRITE_SAFE;
import static org.apache.ignite.internal.processors.cache.distributed.dht.topology.GridDhtPartitionState.LOST;

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
            .setCacheConfiguration(new CacheConfiguration<Integer, Integer>(CACHE)
                .setBackups(0)
                .setPartitionLossPolicy(plc));
    }

    /** {@inheritDoc} */
    @Override protected void afterTest() throws Exception {
        stopAllGrids();

        super.afterTest();
    }

    /**
     * Given three servers, a client and a cache without backups under the IGNORE policy.
     * When a server leaves with the only copies of its partitions, and the other servers own them.
     * Then the partition map of every node shows these partitions as OWNING on their new owners.
     *
     * @throws Exception If failed.
     */
    @Test
    public void testLostPartitionOwned() throws Exception {
        checkServerLeft(IGNORE, 3);
    }

    /**
     * Given three servers, a client and a cache without backups under the READ_WRITE_SAFE policy.
     * When a server leaves with the only copies of its partitions, and the other servers mark them LOST.
     * Then the partition map of every node shows these partitions as LOST on the servers that hold them.
     *
     * @throws Exception If failed.
     */
    @Test
    public void testLostPartitionMarkedLost() throws Exception {
        checkServerLeft(READ_WRITE_SAFE, 3);
    }

    /**
     * Given three servers, a client and a cache without backups under the READ_WRITE_SAFE policy, and a server that
     * left with the only copies of its partitions.
     * When the server comes back and gets its lost partitions as LOST.
     * Then the partition map of every node shows these partitions as LOST on the returned server.
     *
     * @throws Exception If failed.
     */
    @Test
    public void testServerReturnsWhileLost() throws Exception {
        checkServerLeft(READ_WRITE_SAFE, 3);

        startGrid(2);

        assertTrue("The returned server holds no lost partitions",
            grid(2).cachex(CACHE).context().topology().localPartitions().stream().anyMatch(p -> p.state() == LOST));

        awaitPartitionMapsMatchLocalStates(CACHE);
    }

    /**
     * Given the coordinator, another server, a client and a cache without backups under the IGNORE policy.
     * When the other server leaves, and the coordinator owns all its partitions.
     * Then the partition map of every node shows these partitions as OWNING on the coordinator. Only the client learns
     * this state from another node.
     *
     * @throws Exception If failed.
     */
    @Test
    public void testLostPartitionOwnedByCoordinator() throws Exception {
        checkServerLeft(IGNORE, 2);
    }

    /**
     * Gives a cluster where the last server has left with the only copies of its partitions, and the partition map of
     * every node matches the servers' local states. Starts the servers and a client, waits until the partitions that
     * moved while the servers joined are evicted, then stops the last server.
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
