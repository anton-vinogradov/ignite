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

package org.apache.ignite.util;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardCopyOption;
import java.time.Instant;
import java.util.List;
import java.util.Map;
import java.util.regex.Pattern;
import java.util.stream.Collectors;
import javax.cache.configuration.Factory;
import javax.net.ssl.SSLContext;
import org.apache.ignite.internal.IgniteEx;
import org.apache.ignite.internal.management.api.NoArg;
import org.apache.ignite.internal.management.ssl.SslReloadCommand;
import org.apache.ignite.ssl.SslContextFactory;
import org.apache.ignite.testframework.GridTestUtils;
import org.junit.Assume;
import org.junit.Test;

import static org.apache.ignite.internal.commandline.CommandHandler.EXIT_CODE_OK;
import static org.apache.ignite.internal.commandline.CommandHandler.EXIT_CODE_UNEXPECTED_ERROR;
import static org.apache.ignite.ssl.SslTestUtils.node;
import static org.apache.ignite.testframework.GridTestUtils.assertContains;
import static org.apache.ignite.testframework.GridTestUtils.assertNotContains;

/**
 * {@code --ssl reload} and {@code --ssl status} through control.sh. Only the CLI handler runs the test: it connects to a node over
 * the client connector TLS that the command reloads, while the JMX handler calls the node in process and would only repeat
 * SslContextReloadTest.
 */
public class GridCommandHandlerSslReloadTest extends GridCommandHandlerAbstractTest {
    /** Key store the nodes run on; replaced on disk to rotate the certificate. */
    private Path keyStore;

    /** {@inheritDoc} */
    @Override protected boolean sslEnabled() {
        return true;
    }

    /** {@inheritDoc} */
    @Override protected Factory<SSLContext> sslFactory() {
        SslContextFactory factory = new SslContextFactory();

        factory.setKeyStoreFilePath(keyStore.toString());
        factory.setKeyStorePassword(GridTestUtils.keyStorePassword().toCharArray());
        factory.setTrustManagers(SslContextFactory.getDisabledTrustManager());

        return factory;
    }

    /** {@inheritDoc} */
    @Override protected void beforeTest() throws Exception {
        Assume.assumeTrue(cliCommandHandler());

        keyStore = Files.createTempFile("ignite-cli-ssl-reload-", ".jks");

        place("node01", keyStore);

        super.beforeTest();

        injectTestSystemOut();
    }

    /** {@inheritDoc} */
    @Override protected void afterTest() throws Exception {
        stopAllGrids();

        super.afterTest();

        if (keyStore != null)
            Files.deleteIfExists(keyStore);
    }

    /**
     * The reload asks for confirmation. One command reloads every node, client ones included, and status shows the new
     * certificate and the time of that reload; a broken store fails the command.
     */
    @Test
    public void testReloadAndStatus() throws Exception {
        assertNotNull("The reload must ask for confirmation", new SslReloadCommand().confirmationPrompt(new NoArg()));

        IgniteEx srv0 = startGrid(0);
        IgniteEx srv1 = startGrid(1);
        IgniteEx cli = startClientGrid(CLIENT_NODE_NAME_PREFIX);

        // Transports are listed alphabetically; a client node runs no binary REST.
        Map<IgniteEx, String> transports = Map.of(
            srv0, "binary REST, client connector, communication, discovery",
            srv1, "binary REST, client connector, communication, discovery",
            cli, "client connector, communication, discovery");

        String replacement = "node02";
        String replacementSubj = "CN=" + replacement;
        String loaded = "loaded alias=" + replacement + ", subject=" + replacementSubj;

        place(replacement, keyStore);

        long start = System.currentTimeMillis();
        String reloadOutput = executeCommand(EXIT_CODE_OK, "--ssl", "reload");

        transports.forEach((g, t) -> assertContains(log, reloadOutput, node(g) + ": reloaded " + t + "; " + loaded));

        String statusOutput = executeCommand(EXIT_CODE_OK, "--ssl", "status");

        transports.forEach((g, t) -> assertContains(log, statusOutput, node(g) + ": " + t + '\n'));

        assertContains(log, statusOutput, loaded);
        assertNotContains(log, statusOutput, "subject=CN=node01");

        List<Instant> succeeded = Pattern.compile("last reload succeeded at (\\S+)").matcher(statusOutput).results()
            .map(m -> Instant.parse(m.group(1))).collect(Collectors.toList());

        assertEquals(statusOutput, transports.size(), succeeded.size());
        succeeded.forEach(t -> assertFalse(statusOutput, t.isBefore(Instant.ofEpochMilli(start))));

        Files.write(keyStore, "not a key store".getBytes());

        assertContains(log, executeCommand(EXIT_CODE_UNEXPECTED_ERROR, "--ssl", "reload"), "Failed to initialize key store");
    }

    /**
     * @param name Test store, as {@code tests.properties} names it.
     * @param dest File to replace.
     */
    private static void place(String name, Path dest) throws IOException {
        Files.copy(Path.of(GridTestUtils.keyStorePath(name)), dest, StandardCopyOption.REPLACE_EXISTING);
    }
}
