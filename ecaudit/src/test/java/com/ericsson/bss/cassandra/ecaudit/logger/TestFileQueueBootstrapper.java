/*
 * Copyright 2026 Telefonaktiebolaget LM Ericsson
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package com.ericsson.bss.cassandra.ecaudit.logger;

import java.io.File;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;

import org.junit.After;
import org.junit.Before;
import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.TemporaryFolder;
import org.slf4j.LoggerFactory;

import ch.qos.logback.classic.Level;
import ch.qos.logback.classic.Logger;
import net.openhft.chronicle.queue.impl.single.SingleChronicleQueue;

import static org.assertj.core.api.Assertions.assertThat;

public class TestFileQueueBootstrapper
{
    @Rule
    public TemporaryFolder temporaryFolder = new TemporaryFolder();

    private final Logger bootstrapperLogger = (Logger) LoggerFactory.getLogger(FileQueueBootstrapper.class);
    private Level originalLevel;

    private Path dir;

    @Before
    public void before()
    {
        originalLevel = bootstrapperLogger.getLevel();
        dir = temporaryFolder.getRoot().toPath();
    }

    @After
    public void after()
    {
        bootstrapperLogger.setLevel(originalLevel);
    }

    @Test
    public void testEmptyDirectoryIsNotBootstrapping()
    {
        FileQueueBootstrapper bootstrapper = new FileQueueBootstrapper(dir);
        bootstrapper.discoverFiles();

        assertThat(bootstrapper.isBootstrapping()).isFalse();
    }

    @Test
    public void testMissingDirectoryIsNotBootstrapping()
    {
        FileQueueBootstrapper bootstrapper = new FileQueueBootstrapper(dir.resolve("does-not-exist"));
        bootstrapper.discoverFiles();

        assertThat(bootstrapper.isBootstrapping()).isFalse();

        SizeTrackedFileQueue queue = new SizeTrackedFileQueue();
        bootstrapper.enqueueOn(queue);
        assertThat(queue.poll()).isNull();
        assertThat(queue.accumulatedFileSize()).isZero();
    }

    @Test
    public void testDiscoveredFilesAreEnqueuedInChronologicalOrder() throws IOException
    {
        File second = createFile("20190327-1232" + SingleChronicleQueue.SUFFIX, 20);
        File first = createFile("20190327-1231" + SingleChronicleQueue.SUFFIX, 10);
        File third = createFile("20190327-1233" + SingleChronicleQueue.SUFFIX, 30);
        createFile("metadata.cq4t", 5);
        Files.createDirectory(dir.resolve("subdir" + SingleChronicleQueue.SUFFIX));

        FileQueueBootstrapper bootstrapper = new FileQueueBootstrapper(dir);
        bootstrapper.discoverFiles();
        assertThat(bootstrapper.isBootstrapping()).isTrue();

        SizeTrackedFileQueue queue = new SizeTrackedFileQueue();
        bootstrapper.enqueueOn(queue);

        assertThat(queue.accumulatedFileSize()).isEqualTo(60);
        assertThat(queue.poll()).isEqualTo(first);
        assertThat(queue.poll()).isEqualTo(second);
        assertThat(queue.poll()).isEqualTo(third);
        assertThat(queue.poll()).isNull();
        assertThat(bootstrapper.isBootstrapping()).isFalse();
    }

    @Test
    public void testActiveFileIsExcluded() throws IOException
    {
        File first = createFile("20190327-1231" + SingleChronicleQueue.SUFFIX, 10);
        File active = createFile("20190327-1232" + SingleChronicleQueue.SUFFIX, 20);

        FileQueueBootstrapper bootstrapper = new FileQueueBootstrapper(dir);
        bootstrapper.discoverFiles();
        bootstrapper.excludeActiveFile(active);

        SizeTrackedFileQueue queue = new SizeTrackedFileQueue();
        bootstrapper.enqueueOn(queue);

        assertThat(queue.accumulatedFileSize()).isEqualTo(10);
        assertThat(queue.poll()).isEqualTo(first);
        assertThat(queue.poll()).isNull();
    }

    @Test
    public void testExcludeUnknownFileKeepsDiscoveredFiles() throws IOException
    {
        File first = createFile("20190327-1231" + SingleChronicleQueue.SUFFIX, 10);

        FileQueueBootstrapper bootstrapper = new FileQueueBootstrapper(dir);
        bootstrapper.discoverFiles();
        bootstrapper.excludeActiveFile(dir.resolve("20190327-1232" + SingleChronicleQueue.SUFFIX).toFile());

        assertThat(bootstrapper.isBootstrapping()).isTrue();
        SizeTrackedFileQueue queue = new SizeTrackedFileQueue();
        bootstrapper.enqueueOn(queue);
        assertThat(queue.poll()).isEqualTo(first);
    }

    @Test
    public void testDiscoverFilesWithDebugLoggingDisabled() throws IOException
    {
        bootstrapperLogger.setLevel(Level.INFO);
        File first = createFile("20190327-1231" + SingleChronicleQueue.SUFFIX, 10);

        FileQueueBootstrapper bootstrapper = new FileQueueBootstrapper(dir);
        bootstrapper.discoverFiles();

        assertThat(bootstrapper.isBootstrapping()).isTrue();
        SizeTrackedFileQueue queue = new SizeTrackedFileQueue();
        bootstrapper.enqueueOn(queue);
        assertThat(queue.poll()).isEqualTo(first);
    }

    @Test
    public void testRediscoveryReplacesPreviousFiles() throws IOException
    {
        File first = createFile("20190327-1231" + SingleChronicleQueue.SUFFIX, 10);

        FileQueueBootstrapper bootstrapper = new FileQueueBootstrapper(dir);
        bootstrapper.discoverFiles();
        assertThat(first.delete()).isTrue();
        bootstrapper.discoverFiles();

        assertThat(bootstrapper.isBootstrapping()).isFalse();
    }

    private File createFile(String name, int size) throws IOException
    {
        Path filePath = dir.resolve(name);
        Files.write(filePath, new byte[size]);
        return filePath.toFile();
    }
}
