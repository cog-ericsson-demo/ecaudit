/*
 * Copyright 2019 Telefonaktiebolaget LM Ericsson
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
package com.ericsson.bss.cassandra.ecaudit.eclog;

import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.PrintStream;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.UnknownHostException;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;
import java.util.Optional;
import java.util.function.Consumer;

import org.apache.commons.cli.ParseException;
import org.junit.After;
import org.junit.Before;
import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.TemporaryFolder;
import org.junit.runner.RunWith;

import com.ericsson.bss.cassandra.ecaudit.common.chronicle.AuditRecordWriteMarshallable;
import com.ericsson.bss.cassandra.ecaudit.common.chronicle.FieldSelector;
import com.ericsson.bss.cassandra.ecaudit.common.record.AuditRecord;
import com.ericsson.bss.cassandra.ecaudit.common.record.SimpleAuditOperation;
import com.ericsson.bss.cassandra.ecaudit.common.record.Status;
import net.openhft.chronicle.core.Jvm;
import net.openhft.chronicle.core.onoes.ExceptionHandler;
import net.openhft.chronicle.core.onoes.ThreadLocalisedExceptionHandler;
import net.openhft.chronicle.queue.ChronicleQueue;
import net.openhft.chronicle.queue.ExcerptAppender;
import net.openhft.chronicle.queue.impl.single.SingleChronicleQueueBuilder;
import org.mockito.InOrder;
import org.mockito.Mock;
import org.mockito.junit.MockitoJUnitRunner;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.inOrder;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.mockito.Mockito.when;

@RunWith(MockitoJUnitRunner.StrictStubs.class)
public class TestEcLog
{
    private static final String CONFIG_FILE = "src/test/resources/eclog.yaml";

    @Rule
    public final TemporaryFolder temporaryFolder = new TemporaryFolder();

    @Mock
    private OptionParser parser;

    @Mock
    private ToolOptions options;

    @Mock
    private Consumer<Integer> exiter;

    private PrintStream originalOut;
    private PrintStream originalErr;
    private ByteArrayOutputStream testOut;
    private ByteArrayOutputStream testErr;
    private ExceptionHandler originalWarnHandler;

    @Before
    public void before()
    {
        originalWarnHandler = chronicleWarnHandler().defaultHandler();

        originalOut = System.out;
        originalErr = System.err;
        testOut = new ByteArrayOutputStream();
        testErr = new ByteArrayOutputStream();
        System.setOut(new PrintStream(testOut));
        System.setErr(new PrintStream(testErr));
    }

    @After
    public void after()
    {
        System.setOut(originalOut);
        System.setErr(originalErr);

        chronicleWarnHandler().defaultHandler(originalWarnHandler);
    }

    @Test
    public void testWorking() throws ParseException
    {
        when(parser.parse(any(String.class))).thenReturn(options);
        ToolOptions actualOptions = EcLog.getToolOptions(new String[]{ "some/path" }, parser, exiter);
        assertThat(actualOptions).isEqualTo(options);
    }

    @Test
    public void testWorkingDoesNotPrintUsageOrExit() throws ParseException
    {
        when(parser.parse(any(String.class))).thenReturn(options);
        EcLog.getToolOptions(new String[]{ "some/path" }, parser, exiter);
        verify(parser, never()).printUsage();
        verifyNoInteractions(exiter);
    }

    @Test
    public void testAllArgumentsArePassedToParser() throws ParseException
    {
        when(parser.parse(eq("--limit"), eq("5"), eq("some/path"))).thenReturn(options);
        ToolOptions actualOptions = EcLog.getToolOptions(new String[]{ "--limit", "5", "some/path" }, parser, exiter);
        assertThat(actualOptions).isEqualTo(options);
    }

    @Test
    public void testHelp() throws ParseException
    {
        when(parser.parse(any(String.class))).thenReturn(options);
        when(options.help()).thenReturn(true);
        EcLog.getToolOptions(new String[]{ "-h" }, parser, exiter);
        verify(parser).printUsage();
        verify(exiter).accept(eq(0));
    }

    @Test
    public void testHelpPrintsUsageBeforeExitAndGivesNoOptions() throws ParseException
    {
        when(parser.parse(any(String.class))).thenReturn(options);
        when(options.help()).thenReturn(true);
        ToolOptions actualOptions = EcLog.getToolOptions(new String[]{ "-h" }, parser, exiter);
        InOrder inOrder = inOrder(parser, exiter);
        inOrder.verify(parser).printUsage();
        inOrder.verify(exiter).accept(eq(0));
        assertThat(actualOptions).isNull();
    }

    @Test
    public void testInvalidArgument() throws ParseException
    {
        when(parser.parse(any(String.class))).thenThrow(new ParseException("Invalid argument"));
        EcLog.getToolOptions(new String[]{ "--wrong" }, parser, exiter);
        verify(parser).printUsage();
        verify(exiter).accept(eq(1));
    }

    @Test
    public void testInvalidArgumentPrintsReasonAndUsageBeforeExitAndGivesNoOptions() throws ParseException
    {
        when(parser.parse(any(String.class))).thenThrow(new ParseException("Invalid argument"));
        ToolOptions actualOptions = EcLog.getToolOptions(new String[]{ "--wrong" }, parser, exiter);
        InOrder inOrder = inOrder(parser, exiter);
        inOrder.verify(parser).printUsage();
        inOrder.verify(exiter).accept(eq(1));
        assertThat(actualOptions).isNull();
        assertThat(testErr.toString()).contains("Invalid argument");
    }

    @Test
    public void testMainPrintsAllRecords() throws UnknownHostException
    {
        File logDirectory = givenLogDirectoryWithRecords(3);

        EcLog.main(new String[]{ logDirectory.getPath() });

        assertThat(printedLines()).containsExactly("1|1.2.3.4:555|5.6.7.8|john|ATTEMPT|Operation 1",
                                                   "2|1.2.3.4:555|5.6.7.8|john|ATTEMPT|Operation 2",
                                                   "3|1.2.3.4:555|5.6.7.8|john|ATTEMPT|Operation 3");
    }

    @Test
    public void testMainWithoutRecordsPrintsNothing() throws UnknownHostException
    {
        File logDirectory = givenLogDirectoryWithRecords(0);

        EcLog.main(new String[]{ logDirectory.getPath() });

        assertThat(printedLines()).isEmpty();
    }

    @Test
    public void testMainWithLimit() throws UnknownHostException
    {
        File logDirectory = givenLogDirectoryWithRecords(3);

        EcLog.main(new String[]{ "--limit", "2", logDirectory.getPath() });

        assertThat(printedLines()).containsExactly("1|1.2.3.4:555|5.6.7.8|john|ATTEMPT|Operation 1",
                                                   "2|1.2.3.4:555|5.6.7.8|john|ATTEMPT|Operation 2");
    }

    @Test
    public void testMainWithTail() throws UnknownHostException
    {
        File logDirectory = givenLogDirectoryWithRecords(3);

        EcLog.main(new String[]{ "--tail", "2", logDirectory.getPath() });

        assertThat(printedLines()).containsExactly("2|1.2.3.4:555|5.6.7.8|john|ATTEMPT|Operation 2",
                                                   "3|1.2.3.4:555|5.6.7.8|john|ATTEMPT|Operation 3");
    }

    @Test
    public void testMainWithConfig() throws UnknownHostException
    {
        File logDirectory = givenLogDirectoryWithRecords(1);

        EcLog.main(new String[]{ "--config", CONFIG_FILE, logDirectory.getPath() });

        assertThat(printedLines()).containsExactly("1970-01-01 00:00:00 UTC -> Client=1.2.3.4, Status=ATTEMPT, Operation=Operation 1");
    }

    @Test
    public void testMainMutesChronicleWarnings() throws UnknownHostException
    {
        ExceptionHandler warnHandler = mock(ExceptionHandler.class);
        chronicleWarnHandler().defaultHandler(warnHandler);
        File logDirectory = givenLogDirectoryWithRecords(1);

        EcLog.main(new String[]{ logDirectory.getPath() });
        Jvm.warn().on(TestEcLog.class, "Some warning", null);

        verify(warnHandler, never()).on(eq(TestEcLog.class), eq("Some warning"), any());
    }

    private File givenLogDirectoryWithRecords(int count) throws UnknownHostException
    {
        File logDirectory = temporaryFolder.getRoot();
        try (ChronicleQueue chronicleQueue = SingleChronicleQueueBuilder.single(logDirectory).blockSize(1024).build())
        {
            ExcerptAppender appender = chronicleQueue.acquireAppender();
            for (int i = 1; i <= count; i++)
            {
                appender.writeDocument(new AuditRecordWriteMarshallable(mockRecord(i), FieldSelector.DEFAULT_FIELDS));
            }
        }
        return logDirectory;
    }

    private static AuditRecord mockRecord(long index) throws UnknownHostException
    {
        AuditRecord auditRecord = mock(AuditRecord.class);
        when(auditRecord.getTimestamp()).thenReturn(index);
        when(auditRecord.getClientAddress()).thenReturn(new InetSocketAddress(InetAddress.getByName("1.2.3.4"), 555));
        when(auditRecord.getCoordinatorAddress()).thenReturn(InetAddress.getByName("5.6.7.8"));
        when(auditRecord.getUser()).thenReturn("john");
        when(auditRecord.getBatchId()).thenReturn(Optional.empty());
        when(auditRecord.getStatus()).thenReturn(Status.ATTEMPT);
        when(auditRecord.getOperation()).thenReturn(new SimpleAuditOperation("Operation " + index));
        when(auditRecord.getSubject()).thenReturn(Optional.empty());
        return auditRecord;
    }

    private List<String> printedLines()
    {
        String printed = testOut.toString();
        return printed.isEmpty() ? Collections.emptyList() : Arrays.asList(printed.split(System.lineSeparator()));
    }

    private static ThreadLocalisedExceptionHandler chronicleWarnHandler()
    {
        return (ThreadLocalisedExceptionHandler) Jvm.warn();
    }
}
