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
import java.util.List;
import org.apache.ignite.Ignite;
import org.apache.ignite.internal.util.typedef.G;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.Parameterized;

/**
 *
 */
@RunWith(Parameterized.class)
public class ImplicitTransactionalCacheConsistencyTest extends AbstractCacheConsistencyTest {
    /** Test parameters. */
    @Parameterized.Parameters(name = "getEntry={0}, async={1}")
    public static Collection parameters() {
        List<Object[]> res = new ArrayList<>();

        for (boolean raw : new boolean[] {false, true}) {
            for (boolean async : new boolean[] {false, true})
                res.add(new Object[] {raw, async});
        }

        return res;
    }

    /** GetEntry or just get. */
    @Parameterized.Parameter
    public boolean raw;

    /** Async. */
    @Parameterized.Parameter(1)
    public boolean async;

    /**
     *
     */
    @Test
    public void test() throws Exception {
        for (Ignite node : G.allGrids()) {
            testGet(node);
            testGetAllVariations(node);
            testGetNull(node);
        }
    }

    /**
     *
     */
    private void testGet(Ignite initiator) throws Exception {
        prepareAndCheck(
            initiator,
            1,
            raw,
            async,
            (ReadRepairData data) -> {
                GET_CHECK_AND_FIX.accept(data);
                ENSURE_FIXED.accept(data);
            });
    }

    /**
     *
     */
    private void testGetAllVariations(Ignite initiator) throws Exception {
        testGetAll(initiator, 1); // 1 (all keys available at primary)
        testGetAll(initiator, 2); // less than backups
        testGetAll(initiator, 3); // equals to backups
        testGetAll(initiator, 4); // equals to backups + primary
        testGetAll(initiator, 10); // more than backups
    }

    /**
     *
     */
    private void testGetAll(Ignite initiator, Integer amount) throws Exception {
        prepareAndCheck(
            initiator,
            amount,
            raw,
            async,
            (ReadRepairData data) -> {
                GETALL_CHECK_AND_FIX.accept(data);
                ENSURE_FIXED.accept(data);
            });
    }

    /**
     *
     */
    private void testGetNull(Ignite initiator) throws Exception {
        prepareAndCheck(
            initiator,
            1,
            raw,
            async,
            (ReadRepairData data) -> {
                GET_NULL.accept(data); // first attempt.
                GET_NULL.accept(data); // second attempt (checks first attempt causes no changes/fixes/etc).
            });
    }
}
