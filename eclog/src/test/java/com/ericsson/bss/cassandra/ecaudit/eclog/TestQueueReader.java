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

import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.UnknownHostException;
import java.util.Optional;
import java.util.UUID;

import org.junit.Before;
import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.TemporaryFolder;
import org.junit.runner.RunWith;

import com.ericsson.bss.cassandra.ecaudit.common.chronicle.AuditRecordReadMarshallable;
import com.ericsson.bss.cassandra.ecaudit.common.chronicle.AuditRecordWriteMarshallable;
import com.ericsson.bss.cassandra.ecaudit.common.chronicle.FieldSelector.Field;
import com.ericsson.bss.cassandra.ecaudit.common.record.AuditOperation;
import com.ericsson.bss.cassandra.ecaudit.common.record.AuditRecord;
import com.ericsson.bss.cassandra.ecaudit.common.record.Status;
import com.ericsson.bss.cassandra.ecaudit.common.record.StoredAuditRecord;
import com.ericsson.bss.cassandra.ecaudit.test.chronicle.RecordValues;
import net.openhft.chronicle.core.io.IORuntimeException;
import net.openhft.chronicle.queue.ChronicleQueue;
import net.openhft.chronicle.queue.ExcerptTailer;
import net.openhft.chronicle.queue.RollCycles;
import net.openhft.chronicle.queue.impl.single.SingleChronicleQueueBuilder;
import net.openhft.chronicle.wire.ReadMarshallable;
import net.openhft.chronicle.wire.ValueIn;
import net.openhft.chronicle.wire.WireIn;
import org.mockito.Mock;
import org.mockito.junit.MockitoJUnitRunner;
import org.mockito.stubbing.Answer;

import static com.ericsson.bss.cassandra.ecaudit.common.chronicle.FieldSelector.DEFAULT_FIELDS;
import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatExceptionOfType;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyLong;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

@RunWith(MockitoJUnitRunner.StrictStubs.class)
public class TestQueueReader
{
    private static final long WRITE_TIME_MS = 1_000_000_000_000L;

    @Rule
    public final TemporaryFolder temporaryFolder = new TemporaryFolder();

    @Mock
    private ChronicleQueue queue;

    @Mock
    private ExcerptTailer tailer;

    private RecordValues defaultValues;

    @Before
    public void before() throws UnknownHostException
    {
        defaultValues = RecordValues.defaultValues();

        when(queue.createTailer()).thenReturn(tailer);
        when(tailer.toEnd()).thenReturn(tailer);
        when(tailer.index()).thenReturn(0L).thenReturn(1000L);
    }

    @Test
    public void testNothingToRead()
    {
        when(tailer.readDocument(any(ReadMarshallable.class))).thenReturn(false);
        QueueReader reader = givenReader();

        assertThat(reader.hasRecordAvailable()).isFalse();
    }

    @Test
    public void testNothingToReadDirect()
    {
        when(tailer.readDocument(any(ReadMarshallable.class))).thenReturn(false);
        QueueReader reader = givenReader();

        assertThat(reader.nextRecord()).isNull();
    }

    @Test
    public void testValidSingleRecord() throws UnknownHostException
    {
        givenNextRecordIs(defaultValues);
        QueueReader reader = givenReader();

        assertThat(reader.hasRecordAvailable()).isTrue();
        StoredAuditRecord auditRecord = reader.nextRecord();
        assertRecordMatchesWire(auditRecord, defaultValues);
    }

    @Test
    public void testValidSingleTailRecord() throws UnknownHostException
    {
        givenNextRecordIs(defaultValues);
        QueueReader reader = givenReader(ToolOptions.builder().withTail(1).build());

        verify(tailer).moveToIndex(eq(999L));
        assertThat(reader.hasRecordAvailable()).isTrue();
        StoredAuditRecord auditRecord = reader.nextRecord();
        assertRecordMatchesWire(auditRecord, defaultValues);
    }

    @Test
    public void testValidSingleRecordDirect() throws UnknownHostException
    {
        givenNextRecordIs(defaultValues);
        QueueReader reader = givenReader();

        StoredAuditRecord auditRecord = reader.nextRecord();
        assertRecordMatchesWire(auditRecord, defaultValues);
    }

    @Test
    public void testValidBatchRecord() throws UnknownHostException
    {
        givenNextRecordIs(defaultValues.butWithBatchId(UUID.fromString("b23534c7-93af-497f-b00c-1edaaa335caa")));
        QueueReader reader = givenReader();

        assertThat(reader.hasRecordAvailable()).isTrue();
        StoredAuditRecord auditRecord = reader.nextRecord();
        assertRecordMatchesWire(auditRecord, defaultValues);
    }

    @Test
    public void testFailOnCorruptRecord()
    {
        givenNextRecordIs(defaultValues.butWithClientAddress(new byte[]{ 1, 2, 3 }));
        QueueReader reader = givenReader();

        assertThatExceptionOfType(IORuntimeException.class)
        .isThrownBy(reader::hasRecordAvailable)
        .withMessageContaining("Corrupt");
    }

    @Test
    public void testNoTailStartsAtBeginning()
    {
        givenReader();

        verify(tailer, never()).toEnd();
        verify(tailer, never()).moveToIndex(anyLong());
    }

    @Test
    public void testTailLargerThanQueueStartsAtFirstIndex()
    {
        givenReader(ToolOptions.builder().withTail(5000).build());

        verify(tailer).moveToIndex(eq(0L));
    }

    @Test
    public void testTailOfZeroStartsAtEnd()
    {
        givenReader(ToolOptions.builder().withTail(0).build());

        verify(tailer).moveToIndex(eq(1000L));
    }

    @Test
    public void testAvailableRecordIsReadOnlyOnce() throws UnknownHostException
    {
        givenNextRecordIs(defaultValues);
        QueueReader reader = givenReader();

        assertThat(reader.hasRecordAvailable()).isTrue();
        assertThat(reader.hasRecordAvailable()).isTrue();
        verify(tailer, times(1)).readDocument(any(ReadMarshallable.class));
        assertRecordMatchesWire(reader.nextRecord(), defaultValues);
    }

    @Test
    public void testRecordIsConsumedWhenReturned() throws UnknownHostException
    {
        Answer<Boolean> recordAnswer = givenAnswerWithRecord(defaultValues);
        when(tailer.readDocument(any(ReadMarshallable.class)))
        .thenAnswer(recordAnswer)
        .thenReturn(false);
        QueueReader reader = givenReader();

        assertRecordMatchesWire(reader.nextRecord(), defaultValues);
        assertThat(reader.hasRecordAvailable()).isFalse();
        assertThat(reader.nextRecord()).isNull();
    }

    @Test
    public void testRecordAvailableAfterEmptyRead() throws UnknownHostException
    {
        Answer<Boolean> recordAnswer = givenAnswerWithRecord(defaultValues);
        when(tailer.readDocument(any(ReadMarshallable.class)))
        .thenReturn(false)
        .thenAnswer(recordAnswer);
        QueueReader reader = givenReader();

        assertThat(reader.hasRecordAvailable()).isFalse();
        assertThat(reader.hasRecordAvailable()).isTrue();
        assertRecordMatchesWire(reader.nextRecord(), defaultValues);
    }

    @Test
    public void testReadAllRecordsFromQueueDirectory() throws UnknownHostException
    {
        givenRecordsInQueueDirectory(RollCycles.TEST_SECONDLY, 3);
        QueueReader reader = new QueueReader(givenOptionsForQueueDirectory().withRollCycle(RollCycles.TEST_SECONDLY).build());

        assertThatNextOperationsAre(reader, "operation 0", "operation 1", "operation 2");
    }

    @Test
    public void testReadFromQueueDirectoryWithDefaultRollCycle() throws UnknownHostException
    {
        givenRecordsInQueueDirectory(RollCycles.DEFAULT, 2);
        QueueReader reader = new QueueReader(givenOptionsForQueueDirectory().build());

        assertThatNextOperationsAre(reader, "operation 0", "operation 1");
    }

    @Test
    public void testReadFromEmptyQueueDirectory()
    {
        QueueReader reader = new QueueReader(givenOptionsForQueueDirectory().build());

        assertThat(reader.hasRecordAvailable()).isFalse();
        assertThat(reader.nextRecord()).isNull();
    }

    @Test
    public void testTailFromQueueDirectory() throws UnknownHostException
    {
        givenRecordsInQueueDirectory(RollCycles.TEST_SECONDLY, 5);
        QueueReader reader = new QueueReader(givenOptionsForQueueDirectory().withRollCycle(RollCycles.TEST_SECONDLY).withTail(2).build());

        assertThatNextOperationsAre(reader, "operation 3", "operation 4");
    }

    @Test
    public void testTailLargerThanQueueDirectory() throws UnknownHostException
    {
        givenRecordsInQueueDirectory(RollCycles.TEST_SECONDLY, 2);
        QueueReader reader = new QueueReader(givenOptionsForQueueDirectory().withRollCycle(RollCycles.TEST_SECONDLY).withTail(10).build());

        assertThatNextOperationsAre(reader, "operation 0", "operation 1");
    }

    @Test
    public void testReadRecordAppendedAfterReaderIsCreated() throws UnknownHostException
    {
        try (ChronicleQueue writeQueue = givenWriteQueue(RollCycles.TEST_SECONDLY))
        {
            givenRecordIsAppended(writeQueue, "operation 0");
            QueueReader reader = new QueueReader(givenOptionsForQueueDirectory().withRollCycle(RollCycles.TEST_SECONDLY).build());
            assertThatNextOperationsAre(reader, "operation 0");

            givenRecordIsAppended(writeQueue, "operation 1");

            assertThatNextOperationsAre(reader, "operation 1");
        }
    }

    private void givenNextRecordIs(RecordValues recordValues)
    {
        Answer<Boolean> recordAnswer = givenAnswerWithRecord(recordValues);
        when(tailer.readDocument(any(ReadMarshallable.class))).thenAnswer(recordAnswer);
    }

    private Answer<Boolean> givenAnswerWithRecord(RecordValues recordValues)
    {
        WireIn wireMock = mock(WireIn.class);

        ValueIn versionValueMock = mock(ValueIn.class);
        when(versionValueMock.int16()).thenReturn(recordValues.getVersion());
        when(wireMock.read(eq("version"))).thenReturn(versionValueMock);

        ValueIn typeValueMock = mock(ValueIn.class);
        when(typeValueMock.text()).thenReturn(recordValues.getType());
        when(wireMock.read(eq("type"))).thenReturn(typeValueMock);

        int fieldsBitmap = recordValues.getBatchId() != null ? DEFAULT_FIELDS.getBitmap() : DEFAULT_FIELDS.withoutField(Field.BATCH_ID).getBitmap();
        ValueIn fieldsValueMock = mock(ValueIn.class);
        when(fieldsValueMock.int32()).thenReturn(fieldsBitmap);
        when(wireMock.read(eq("fields"))).thenReturn(fieldsValueMock);

        ValueIn timestampValueMock = mock(ValueIn.class);
        when(timestampValueMock.int64()).thenReturn(recordValues.getTimestamp());
        when(wireMock.read(eq("timestamp"))).thenReturn(timestampValueMock);

        ValueIn clientIpValueMock = mock(ValueIn.class);
        when(clientIpValueMock.bytes()).thenReturn(recordValues.getClientAddress());
        when(wireMock.read(eq("client_ip"))).thenReturn(clientIpValueMock);

        ValueIn clientPortValueMock = mock(ValueIn.class);
        when(clientPortValueMock.int32()).thenReturn(recordValues.getClientPort());
        when(wireMock.read(eq("client_port"))).thenReturn(clientPortValueMock);

        ValueIn coordinatorIpValueMock = mock(ValueIn.class);
        when(coordinatorIpValueMock.bytes()).thenReturn(recordValues.getCoordinatorAddress());
        when(wireMock.read(eq("coordinator_ip"))).thenReturn(coordinatorIpValueMock);

        ValueIn userValueMock = mock(ValueIn.class);
        when(userValueMock.text()).thenReturn(recordValues.gethUser());
        when(wireMock.read(eq("user"))).thenReturn(userValueMock);

        if (recordValues.getBatchId() != null)
        {
            ValueIn batchIdValueMock = mock(ValueIn.class);
            when(batchIdValueMock.uuid()).thenReturn(recordValues.getBatchId());
            when(wireMock.read(eq("batchId"))).thenReturn(batchIdValueMock);
        }

        ValueIn statusValueMock = mock(ValueIn.class);
        when(statusValueMock.text()).thenReturn(recordValues.getStatus());
        when(wireMock.read(eq("status"))).thenReturn(statusValueMock);

        ValueIn operationValueMock = mock(ValueIn.class);
        when(operationValueMock.text()).thenReturn(recordValues.getOperation());
        when(wireMock.read(eq("operation"))).thenReturn(operationValueMock);

        return invocation -> {
            AuditRecordReadMarshallable readMarshallable = invocation.getArgument(0);
            readMarshallable.readMarshallable(wireMock);
            return true;
        };
    }

    private QueueReader givenReader()
    {
        return givenReader(ToolOptions.builder().build());
    }

    private QueueReader givenReader(ToolOptions toolOptions)
    {
        return new QueueReader(toolOptions, queue);
    }

    private ToolOptions.Builder givenOptionsForQueueDirectory()
    {
        return ToolOptions.builder().withPath(temporaryFolder.getRoot().toPath());
    }

    private ChronicleQueue givenWriteQueue(RollCycles rollCycle)
    {
        // Fixed time keeps all records in one roll cycle
        return SingleChronicleQueueBuilder.single(temporaryFolder.getRoot())
                                          .rollCycle(rollCycle)
                                          .timeProvider(() -> WRITE_TIME_MS)
                                          .blockSize(1024)
                                          .build();
    }

    private void givenRecordsInQueueDirectory(RollCycles rollCycle, int count) throws UnknownHostException
    {
        try (ChronicleQueue writeQueue = givenWriteQueue(rollCycle))
        {
            for (int i = 0; i < count; i++)
            {
                givenRecordIsAppended(writeQueue, "operation " + i);
            }
        }
    }

    private void givenRecordIsAppended(ChronicleQueue writeQueue, String operation) throws UnknownHostException
    {
        AuditOperation auditOperation = mock(AuditOperation.class);
        when(auditOperation.getOperationString()).thenReturn(operation);

        AuditRecord auditRecord = mock(AuditRecord.class);
        when(auditRecord.getTimestamp()).thenReturn(defaultValues.getTimestamp());
        when(auditRecord.getClientAddress()).thenReturn(new InetSocketAddress(InetAddress.getByAddress(defaultValues.getClientAddress()), defaultValues.getClientPort()));
        when(auditRecord.getCoordinatorAddress()).thenReturn(InetAddress.getByAddress(defaultValues.getCoordinatorAddress()));
        when(auditRecord.getUser()).thenReturn(defaultValues.gethUser());
        when(auditRecord.getBatchId()).thenReturn(Optional.empty());
        when(auditRecord.getStatus()).thenReturn(Status.valueOf(defaultValues.getStatus()));
        when(auditRecord.getOperation()).thenReturn(auditOperation);
        when(auditRecord.getSubject()).thenReturn(Optional.empty());

        writeQueue.acquireAppender().writeDocument(new AuditRecordWriteMarshallable(auditRecord, DEFAULT_FIELDS));
    }

    private void assertThatNextOperationsAre(QueueReader reader, String... expectedOperations)
    {
        for (String expectedOperation : expectedOperations)
        {
            assertThat(reader.hasRecordAvailable()).isTrue();
            assertThat(reader.nextRecord().getOperation()).contains(expectedOperation);
        }
        assertThat(reader.hasRecordAvailable()).isFalse();
    }

    private void assertRecordMatchesWire(StoredAuditRecord actualAuditRecord, RecordValues expectedValues) throws UnknownHostException
    {
        assertThat(actualAuditRecord.getTimestamp()).contains(expectedValues.getTimestamp());
        assertThat(actualAuditRecord.getClientAddress()).contains(InetAddress.getByAddress(expectedValues.getClientAddress()));
        assertThat(actualAuditRecord.getClientPort()).contains(expectedValues.getClientPort());
        assertThat(actualAuditRecord.getCoordinatorAddress()).contains(InetAddress.getByAddress(expectedValues.getCoordinatorAddress()));
        assertThat(actualAuditRecord.getUser()).contains(expectedValues.gethUser());
        if (expectedValues.getBatchId() != null)
        {
            assertThat(actualAuditRecord.getBatchId()).contains(expectedValues.getBatchId());
        }
        else
        {
            assertThat(actualAuditRecord.getBatchId()).isEmpty();
        }
        assertThat(actualAuditRecord.getStatus()).map(Enum::name).contains(expectedValues.getStatus());
        assertThat(actualAuditRecord.getOperation()).contains(expectedValues.getOperation());
        assertThat(actualAuditRecord.getNakedOperation()).isEmpty();
    }
}
