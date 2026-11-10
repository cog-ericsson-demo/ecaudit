/*
 * Copyright 2018 Telefonaktiebolaget LM Ericsson
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
package com.ericsson.bss.cassandra.ecaudit;

import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.UnknownHostException;
import java.nio.ByteBuffer;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;
import java.util.Optional;
import java.util.UUID;

import com.google.common.collect.ImmutableList;
import com.google.common.collect.ImmutableSet;

import org.junit.After;
import org.junit.AfterClass;
import org.junit.Before;
import org.junit.BeforeClass;
import org.junit.Test;
import org.junit.runner.RunWith;

import com.ericsson.bss.cassandra.ecaudit.auth.ConnectionResource;
import com.ericsson.bss.cassandra.ecaudit.common.record.AuditOperation;
import com.ericsson.bss.cassandra.ecaudit.common.record.SimpleAuditOperation;
import com.ericsson.bss.cassandra.ecaudit.common.record.Status;
import com.ericsson.bss.cassandra.ecaudit.entry.AuditEntry;
import com.ericsson.bss.cassandra.ecaudit.entry.factory.AuditEntryBuilderFactory;
import com.ericsson.bss.cassandra.ecaudit.entry.suppressor.BoundValueSuppressor;
import com.ericsson.bss.cassandra.ecaudit.facade.Auditor;
import com.ericsson.bss.cassandra.ecaudit.test.mode.ClientInitializer;

import org.apache.cassandra.auth.AuthenticatedUser;
import org.apache.cassandra.auth.DataResource;
import org.apache.cassandra.auth.Permission;
import org.apache.cassandra.config.DatabaseDescriptor;
import org.apache.cassandra.cql3.BatchQueryOptions;
import org.apache.cassandra.cql3.CQLStatement;
import org.apache.cassandra.cql3.ColumnIdentifier;
import org.apache.cassandra.cql3.ColumnSpecification;
import org.apache.cassandra.cql3.QueryOptions;
import org.apache.cassandra.cql3.statements.BatchStatement;
import org.apache.cassandra.cql3.statements.ModificationStatement;
import org.apache.cassandra.db.ConsistencyLevel;
import org.apache.cassandra.db.marshal.UTF8Type;
import org.apache.cassandra.dht.IPartitioner;
import org.apache.cassandra.exceptions.AuthenticationException;
import org.apache.cassandra.exceptions.ReadTimeoutException;
import org.apache.cassandra.service.ClientState;
import org.apache.cassandra.utils.FBUtilities;
import org.apache.cassandra.utils.MD5Digest;
import org.mockito.ArgumentCaptor;
import org.mockito.Mock;
import org.mockito.Mockito;
import org.mockito.junit.MockitoJUnitRunner;

import static java.util.Collections.singletonList;
import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatExceptionOfType;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.mockito.Mockito.verifyNoMoreInteractions;
import static org.mockito.Mockito.when;

@RunWith(MockitoJUnitRunner.StrictStubs.class)
public class TestAuditAdapter
{
    private static final long TIMESTAMP = 42L;
    private static final String USER = "user";
    private static final String CLIENT_IP = "127.0.0.1";
    private static final int CLIENT_PORT = 565;
    private static final int CLIENT_AUTH_PORT = 0;
    private static final String STATEMENT = "select * from ks.tbl";
    private static final String PREPARED_STATEMENT = "insert into ts.ks (id, value) values (?, ?)";
    private static final MD5Digest PREPARED_STATEMENT_ID = MD5Digest.compute(PREPARED_STATEMENT);
    private static final DataResource RESOURCE = DataResource.table("ks", "tbl");
    private static final ImmutableSet<Permission> PERMISSIONS = ImmutableSet.of(Permission.SELECT);
    private static final UUID BATCH_ID = UUID.randomUUID();

    @Mock
    private AuthenticatedUser mockUser;
    @Mock
    private ClientState mockState;
    @Mock
    private CQLStatement mockStatement;
    @Mock
    private QueryOptions mockOptions;
    @Mock
    private Auditor mockAuditor;
    @Mock
    private AuditEntryBuilderFactory mockAuditEntryBuilderFactory;
    @Mock
    private BatchStatement mockBatchStatement;
    @Mock
    private BatchQueryOptions mockBatchOptions;
    @Mock
    private BoundValueSuppressor mockBoundValueSuppressor;

    private InetAddress clientAddress;
    private InetSocketAddress clientSocketAddress;
    private AuditAdapter auditAdapter;

    private static IPartitioner oldPartitionerToRestore;

    @BeforeClass
    public static void beforeAll()
    {
        ClientInitializer.beforeClass();
        oldPartitionerToRestore = DatabaseDescriptor.setPartitionerUnsafe(Mockito.mock(IPartitioner.class));
    }

    @Before
    public void before() throws UnknownHostException
    {
        clientAddress = InetAddress.getByName(CLIENT_IP);
        clientSocketAddress = new InetSocketAddress(clientAddress, CLIENT_PORT);
        auditAdapter = new AuditAdapter(mockAuditor, mockAuditEntryBuilderFactory, mockBoundValueSuppressor);
        when(mockState.getUser()).thenReturn(mockUser);
        when(mockAuditor.shouldLogForStatus(any(Status.class))).thenReturn(true);
    }

    @After
    public void after()
    {
        verifyNoMoreInteractions(mockAuditor);
    }

    @AfterClass
    public static void afterAll()
    {
        DatabaseDescriptor.setPartitionerUnsafe(oldPartitionerToRestore);
        ClientInitializer.afterClass();
    }

    @Test
    public void testGetInstance()
    {
        assertThat(AuditAdapter.getInstance()).isInstanceOf(AuditAdapter.class);
    }

    @Test
    public void testSetupDelegation()
    {
        auditAdapter.setup();
        verify(mockAuditor, times(1)).setup();
    }

    @Test
    public void testProcessRegular()
    {
        // Given
        when(mockUser.getName()).thenReturn(USER);
        when(mockState.getRemoteAddress()).thenReturn(clientSocketAddress);

        AuditEntry.Builder entryBuilder = AuditEntry.newBuilder().permissions(PERMISSIONS).resource(RESOURCE);
        when(mockAuditEntryBuilderFactory.createEntryBuilder(eq(STATEMENT), eq(mockState))).thenReturn(entryBuilder);

        // When
        auditAdapter.auditRegular(STATEMENT, mockState, Status.ATTEMPT, TIMESTAMP);

        // Then
        AuditEntry entry = getAuditEntry();
        assertThat(entry.getClientAddress()).isEqualTo(clientSocketAddress);
        assertThat(entry.getCoordinatorAddress()).isEqualTo(FBUtilities.getJustBroadcastAddress());
        assertThat(entry.getOperation().getOperationString()).isEqualTo(STATEMENT);
        assertThat(entry.getUser()).isEqualTo(USER);
        assertThat(entry.getStatus()).isEqualTo(Status.ATTEMPT);
        assertThat(entry.getBatchId()).isEmpty();
        assertThat(entry.getPermissions()).isEqualTo(PERMISSIONS);
        assertThat(entry.getResource()).isEqualTo(RESOURCE);
        assertThat(entry.getTimestamp()).isEqualTo(TIMESTAMP);
    }

    @Test
    public void testProcessRegularNoLogTimeStrategy()
    {
        // Given
        when(mockAuditor.shouldLogForStatus(any(Status.class))).thenReturn(false);
        // When
        auditAdapter.auditRegular(STATEMENT, mockState, Status.ATTEMPT, TIMESTAMP);
        // Then
        verifyNoMoreInteractions(mockAuditor, mockAuditEntryBuilderFactory);
    }

    @Test
    public void testProcessPrepare()
    {
        // Given
        when(mockAuditor.shouldLogPrepareStatements()).thenReturn(true);
        when(mockUser.getName()).thenReturn(USER);
        when(mockState.getRemoteAddress()).thenReturn(clientSocketAddress);

        AuditEntry.Builder entryBuilder = AuditEntry.newBuilder().permissions(PERMISSIONS).resource(RESOURCE);
        when(mockAuditEntryBuilderFactory.createEntryBuilder(eq(PREPARED_STATEMENT), eq(mockState))).thenReturn(entryBuilder);

        // When
        auditAdapter.auditPrepare(PREPARED_STATEMENT, mockState, Status.ATTEMPT, TIMESTAMP);

        // Then
        AuditEntry entry = getAuditEntry();
        assertThat(entry.getClientAddress()).isEqualTo(clientSocketAddress);
        assertThat(entry.getCoordinatorAddress()).isEqualTo(FBUtilities.getJustBroadcastAddress());
        assertThat(entry.getOperation().getOperationString()).isEqualTo("Prepared: " + PREPARED_STATEMENT);
        assertThat(entry.getOperation().getNakedOperationString()).isEqualTo("Prepared: " + PREPARED_STATEMENT);
        assertThat(entry.getUser()).isEqualTo(USER);
        assertThat(entry.getStatus()).isEqualTo(Status.ATTEMPT);
        assertThat(entry.getBatchId()).isEmpty();
        assertThat(entry.getPermissions()).isEqualTo(PERMISSIONS);
        assertThat(entry.getResource()).isEqualTo(RESOURCE);
        assertThat(entry.getTimestamp()).isEqualTo(TIMESTAMP);
    }

    @Test
    public void testProcessPrepareFailed()
    {
        // Given
        when(mockAuditor.shouldLogPrepareStatements()).thenReturn(true);
        when(mockUser.getName()).thenReturn(USER);
        when(mockState.getRemoteAddress()).thenReturn(clientSocketAddress);

        AuditEntry.Builder entryBuilder = AuditEntry.newBuilder().permissions(PERMISSIONS).resource(RESOURCE);
        when(mockAuditEntryBuilderFactory.createEntryBuilder(eq(PREPARED_STATEMENT), eq(mockState))).thenReturn(entryBuilder);

        // When
        auditAdapter.auditPrepare(PREPARED_STATEMENT, mockState, Status.FAILED, TIMESTAMP);

        // Then
        AuditEntry entry = getAuditEntry();
        assertThat(entry.getOperation().getOperationString()).isEqualTo("Prepared: " + PREPARED_STATEMENT);
        assertThat(entry.getStatus()).isEqualTo(Status.FAILED);
        assertThat(entry.getTimestamp()).isEqualTo(TIMESTAMP);
    }

    @Test
    public void testProcessPrepareNoLogTimeStrategy()
    {
        // Given
        when(mockAuditor.shouldLogForStatus(any(Status.class))).thenReturn(false);
        // When
        auditAdapter.auditPrepare(PREPARED_STATEMENT, mockState, Status.ATTEMPT, TIMESTAMP);
        // Then
        verifyNoMoreInteractions(mockAuditor, mockAuditEntryBuilderFactory);
    }

    @Test
    public void testProcessPrepareNoLogPrepareStatements()
    {
        // Given
        when(mockAuditor.shouldLogPrepareStatements()).thenReturn(false);
        // When
        auditAdapter.auditPrepare(PREPARED_STATEMENT, mockState, Status.ATTEMPT, TIMESTAMP);
        // Then
        verifyNoMoreInteractions(mockAuditor, mockAuditEntryBuilderFactory);
    }

    @Test
    public void testProcessPrepared()
    {
        // Given
        String expectedQuery = PREPARED_STATEMENT + "['id1', 'val1']";
        List<ByteBuffer> values = createValues("id1", "val1");
        ImmutableList<ColumnSpecification> columns = createTextColumns("c1", "c2");

        when(mockUser.getName()).thenReturn(USER);
        when(mockState.getRemoteAddress()).thenReturn(clientSocketAddress);
        when(mockOptions.getValues()).thenReturn(values);
        when(mockOptions.getColumnSpecifications()).thenReturn(columns);
        when(mockOptions.hasColumnSpecifications()).thenReturn(true);

        AuditEntry.Builder entryBuilder = AuditEntry.newBuilder().permissions(PERMISSIONS).resource(RESOURCE);
        when(mockAuditEntryBuilderFactory.createEntryBuilder(eq(mockStatement))).thenReturn(entryBuilder);

        auditAdapter.auditPrepared(PREPARED_STATEMENT, mockStatement, mockState, mockOptions, Status.ATTEMPT, TIMESTAMP);

        // Then
        verifyNoMoreInteractions(mockOptions);

        AuditEntry entry = getAuditEntry();
        assertThat(entry.getClientAddress()).isEqualTo(clientSocketAddress);
        assertThat(entry.getCoordinatorAddress()).isEqualTo(FBUtilities.getJustBroadcastAddress());
        assertThat(entry.getOperation().getOperationString()).isEqualTo(expectedQuery);
        assertThat(entry.getUser()).isEqualTo(USER);
        assertThat(entry.getStatus()).isEqualByComparingTo(Status.ATTEMPT);
        assertThat(entry.getBatchId()).isEmpty();
        assertThat(entry.getPermissions()).isEqualTo(PERMISSIONS);
        assertThat(entry.getResource()).isEqualTo(RESOURCE);
        assertThat(entry.getTimestamp()).isEqualTo(TIMESTAMP);
    }

    @Test
    public void testProcessPreparedWithoutColumnSpecifications()
    {
        // Given
        when(mockUser.getName()).thenReturn(USER);
        when(mockState.getRemoteAddress()).thenReturn(clientSocketAddress);
        when(mockOptions.hasColumnSpecifications()).thenReturn(false);

        AuditEntry.Builder entryBuilder = AuditEntry.newBuilder().permissions(PERMISSIONS).resource(RESOURCE);
        when(mockAuditEntryBuilderFactory.createEntryBuilder(eq(mockStatement))).thenReturn(entryBuilder);

        // When
        auditAdapter.auditPrepared(PREPARED_STATEMENT, mockStatement, mockState, mockOptions, Status.FAILED, TIMESTAMP);

        // Then
        AuditEntry entry = getAuditEntry();
        assertThat(entry.getOperation().getOperationString()).isEqualTo(PREPARED_STATEMENT);
        assertThat(entry.getOperation().getNakedOperationString()).isEqualTo(PREPARED_STATEMENT);
        assertThat(entry.getStatus()).isEqualTo(Status.FAILED);
        verifyNoMoreInteractions(mockOptions);
        verifyNoInteractions(mockBoundValueSuppressor);
    }

    @Test
    public void testProcessPreparedWithReplacedBoundValueSuppressor()
    {
        // Given
        String expectedQuery = PREPARED_STATEMENT + "['id1', <text>]";
        List<ByteBuffer> values = createValues("id1", "val1");
        ImmutableList<ColumnSpecification> columns = createTextColumns("c1", "c2");
        BoundValueSuppressor suppressor = (column, value) -> "c2".equals(column.name.toString()) ? Optional.of("<text>") : Optional.empty();

        when(mockUser.getName()).thenReturn(USER);
        when(mockState.getRemoteAddress()).thenReturn(clientSocketAddress);
        when(mockOptions.getValues()).thenReturn(values);
        when(mockOptions.getColumnSpecifications()).thenReturn(columns);
        when(mockOptions.hasColumnSpecifications()).thenReturn(true);

        AuditEntry.Builder entryBuilder = AuditEntry.newBuilder().permissions(PERMISSIONS).resource(RESOURCE);
        when(mockAuditEntryBuilderFactory.createEntryBuilder(eq(mockStatement))).thenReturn(entryBuilder);

        // When
        auditAdapter.setBoundValueSuppressor(suppressor);
        auditAdapter.auditPrepared(PREPARED_STATEMENT, mockStatement, mockState, mockOptions, Status.ATTEMPT, TIMESTAMP);

        // Then
        AuditEntry entry = getAuditEntry();
        assertThat(entry.getOperation().getOperationString()).isEqualTo(expectedQuery);
        assertThat(entry.getOperation().getNakedOperationString()).isEqualTo(PREPARED_STATEMENT);
        verifyNoInteractions(mockBoundValueSuppressor);
    }

    @Test
    public void testProcessPreparedNoLogTimeStrategy()
    {
        // Given
        when(mockAuditor.shouldLogForStatus(any(Status.class))).thenReturn(false);
        // When
        auditAdapter.auditPrepared(PREPARED_STATEMENT, mockStatement, mockState, mockOptions, Status.ATTEMPT, TIMESTAMP);
        // Then
        verifyNoMoreInteractions(mockAuditor, mockAuditEntryBuilderFactory);
    }

    @Test
    public void testProcessBatchWithLogSummaryStrategy()
    {
        // Given
        when(mockAuditor.shouldLogFailedBatchSummary()).thenReturn(true);

        UUID expectedBatchId = UUID.randomUUID();
        String expectedQuery = String.format("Apply batch failed: %s", expectedBatchId.toString());

        when(mockUser.getName()).thenReturn(USER);
        when(mockState.getRemoteAddress()).thenReturn(clientSocketAddress);

        AuditEntry.Builder entryBuilder = AuditEntry.newBuilder().permissions(PERMISSIONS).resource(RESOURCE);
        when(mockAuditEntryBuilderFactory.createBatchEntryBuilder()).thenReturn(entryBuilder);

        // When
        auditAdapter.auditBatch(mockBatchStatement, Collections.emptyList(), expectedBatchId, mockState, mockBatchOptions, Status.FAILED, TIMESTAMP);

        // Then
        AuditEntry entry = getAuditEntry();
        assertThat(entry.getClientAddress()).isEqualTo(clientSocketAddress);
        assertThat(entry.getCoordinatorAddress()).isEqualTo(FBUtilities.getJustBroadcastAddress());
        assertThat(entry.getUser()).isEqualTo(USER);
        assertThat(entry.getBatchId()).contains(expectedBatchId);
        assertThat(entry.getStatus()).isEqualByComparingTo(Status.FAILED);
        assertThat(entry.getOperation().getOperationString()).isEqualTo(expectedQuery);
        assertThat(entry.getPermissions()).isEqualTo(PERMISSIONS);
        assertThat(entry.getResource()).isEqualTo(RESOURCE);
        assertThat(entry.getTimestamp()).isEqualTo(TIMESTAMP);
    }

    @SuppressWarnings("unchecked")
    @Test
    public void testProcessBatchRegularStatements()
    {
        // Given
        UUID expectedBatchId = UUID.randomUUID();
        List<Object> expectedQueries = Arrays.asList("query1", "query2", "query3");

        when(mockBatchOptions.getQueryOrIdList()).thenReturn(expectedQueries);
        when(mockUser.getName()).thenReturn(USER);
        when(mockState.getRemoteAddress()).thenReturn(clientSocketAddress);

        AuditEntry.Builder entryBuilder = AuditEntry.newBuilder().permissions(PERMISSIONS).resource(RESOURCE);
        when(mockAuditEntryBuilderFactory.createBatchEntryBuilder()).thenReturn(entryBuilder);

        // When
        auditAdapter.auditBatch(mockBatchStatement, Collections.emptyList(), expectedBatchId, mockState, mockBatchOptions, Status.ATTEMPT, TIMESTAMP);

        // Then
        List<AuditEntry> entries = getAuditEntries(3);
        assertThat(entries).extracting(AuditEntry::getClientAddress).containsOnly(clientSocketAddress);
        assertThat(entries).extracting(AuditEntry::getUser).containsOnly(USER);
        assertThat(entries).extracting(AuditEntry::getBatchId).containsOnly(Optional.of(expectedBatchId));
        assertThat(entries).extracting(AuditEntry::getStatus).containsOnly(Status.ATTEMPT);
        assertThat(entries).extracting(AuditEntry::getOperation).extracting(AuditOperation::getOperationString).containsExactly("query1", "query2", "query3");
        assertThat(entries).extracting(AuditEntry::getPermissions).containsOnly(PERMISSIONS);
        assertThat(entries).extracting(AuditEntry::getResource).containsOnly(RESOURCE);
        assertThat(entries).extracting(AuditEntry::getTimestamp).containsOnly(TIMESTAMP);
    }

    @Test
    public void testProcessBatchPreparedStatements()
    {
        // Given
        String expectedQuery = PREPARED_STATEMENT + "['hello', 'world']";
        List<ByteBuffer> values = createValues("hello", "world");
        ImmutableList<ColumnSpecification> columns = createTextColumns("c1", "c2");

        when(mockBatchOptions.forStatement(0)).thenReturn(mockOptions);
        when(mockOptions.getValues()).thenReturn(values);
        when(mockOptions.getColumnSpecifications()).thenReturn(columns);
        when(mockOptions.hasColumnSpecifications()).thenReturn(true);

        when(mockBatchStatement.getStatements()).thenReturn(singletonList(mock(ModificationStatement.class)));
        when(mockBatchOptions.getQueryOrIdList()).thenReturn(singletonList(PREPARED_STATEMENT_ID));
        when(mockUser.getName()).thenReturn(USER);
        when(mockState.getRemoteAddress()).thenReturn(clientSocketAddress);

        AuditEntry.Builder entryBuilder = AuditEntry.newBuilder().permissions(PERMISSIONS).resource(RESOURCE);
        when(mockAuditEntryBuilderFactory.createBatchEntryBuilder()).thenReturn(entryBuilder);

        auditAdapter.auditBatch(mockBatchStatement, Arrays.asList(PREPARED_STATEMENT), BATCH_ID, mockState, mockBatchOptions, Status.ATTEMPT, TIMESTAMP);

        // Then
        verifyNoMoreInteractions(mockOptions);
        AuditEntry entry = getAuditEntry();
        assertThat(entry.getClientAddress()).isEqualTo(clientSocketAddress);
        assertThat(entry.getCoordinatorAddress()).isEqualTo(FBUtilities.getJustBroadcastAddress());
        assertThat(entry.getUser()).isEqualTo(USER);
        assertThat(entry.getBatchId()).contains(BATCH_ID);
        assertThat(entry.getStatus()).isEqualByComparingTo(Status.ATTEMPT);
        assertThat(entry.getOperation().getOperationString()).isEqualTo(expectedQuery);
        assertThat(entry.getPermissions()).isEqualTo(PERMISSIONS);
        assertThat(entry.getResource()).isEqualTo(RESOURCE);
        assertThat(entry.getTimestamp()).isEqualTo(TIMESTAMP);
    }

    @Test
    public void testProcessBatchFailedWithoutLogSummaryStrategy()
    {
        // Given
        when(mockAuditor.shouldLogFailedBatchSummary()).thenReturn(false);

        List<Object> expectedQueries = Arrays.asList("query1", "query2");

        when(mockBatchOptions.getQueryOrIdList()).thenReturn(expectedQueries);
        when(mockUser.getName()).thenReturn(USER);
        when(mockState.getRemoteAddress()).thenReturn(clientSocketAddress);

        AuditEntry.Builder entryBuilder = AuditEntry.newBuilder().permissions(PERMISSIONS).resource(RESOURCE);
        when(mockAuditEntryBuilderFactory.createBatchEntryBuilder()).thenReturn(entryBuilder);

        // When
        auditAdapter.auditBatch(mockBatchStatement, Collections.emptyList(), BATCH_ID, mockState, mockBatchOptions, Status.FAILED, TIMESTAMP);

        // Then
        List<AuditEntry> entries = getAuditEntries(2);
        assertThat(entries).extracting(AuditEntry::getBatchId).containsOnly(Optional.of(BATCH_ID));
        assertThat(entries).extracting(AuditEntry::getStatus).containsOnly(Status.FAILED);
        assertThat(entries).extracting(AuditEntry::getOperation).extracting(AuditOperation::getOperationString).containsExactly("query1", "query2");
        assertThat(entries).extracting(AuditEntry::getTimestamp).containsOnly(TIMESTAMP);
    }

    @Test
    public void testProcessBatchSucceededIgnoresLogSummaryStrategy()
    {
        // Given
        when(mockBatchOptions.getQueryOrIdList()).thenReturn(singletonList("query1"));
        when(mockUser.getName()).thenReturn(USER);
        when(mockState.getRemoteAddress()).thenReturn(clientSocketAddress);

        AuditEntry.Builder entryBuilder = AuditEntry.newBuilder().permissions(PERMISSIONS).resource(RESOURCE);
        when(mockAuditEntryBuilderFactory.createBatchEntryBuilder()).thenReturn(entryBuilder);

        // When
        auditAdapter.auditBatch(mockBatchStatement, Collections.emptyList(), BATCH_ID, mockState, mockBatchOptions, Status.SUCCEEDED, TIMESTAMP);

        // Then
        AuditEntry entry = getAuditEntry();
        assertThat(entry.getBatchId()).contains(BATCH_ID);
        assertThat(entry.getStatus()).isEqualTo(Status.SUCCEEDED);
        assertThat(entry.getOperation().getOperationString()).isEqualTo("query1");
    }

    @Test
    public void testProcessBatchWithoutStatements()
    {
        // Given
        when(mockBatchOptions.getQueryOrIdList()).thenReturn(Collections.emptyList());
        when(mockUser.getName()).thenReturn(USER);
        when(mockState.getRemoteAddress()).thenReturn(clientSocketAddress);

        AuditEntry.Builder entryBuilder = AuditEntry.newBuilder().permissions(PERMISSIONS).resource(RESOURCE);
        when(mockAuditEntryBuilderFactory.createBatchEntryBuilder()).thenReturn(entryBuilder);

        // When
        auditAdapter.auditBatch(mockBatchStatement, Collections.emptyList(), BATCH_ID, mockState, mockBatchOptions, Status.ATTEMPT, TIMESTAMP);

        // Then
        verify(mockAuditEntryBuilderFactory, times(1)).createBatchEntryBuilder();
        verifyNoMoreInteractions(mockAuditor, mockAuditEntryBuilderFactory);
    }

    @Test
    public void testProcessBatchMixedRegularAndPreparedStatements()
    {
        // Given
        String otherPreparedStatement = "update ts.ks set value = ? where id = ?";
        ModificationStatement firstPrepared = mock(ModificationStatement.class);
        ModificationStatement secondPrepared = mock(ModificationStatement.class);
        QueryOptions firstOptions = mock(QueryOptions.class);
        QueryOptions secondOptions = mock(QueryOptions.class);

        List<Object> queryOrIds = Arrays.asList("query1", PREPARED_STATEMENT_ID, "query2", MD5Digest.compute(otherPreparedStatement));
        List<ModificationStatement> statements = Arrays.asList(mock(ModificationStatement.class), firstPrepared, mock(ModificationStatement.class), secondPrepared);

        when(mockBatchOptions.getQueryOrIdList()).thenReturn(queryOrIds);
        when(mockBatchOptions.forStatement(1)).thenReturn(firstOptions);
        when(mockBatchOptions.forStatement(3)).thenReturn(secondOptions);
        when(mockBatchStatement.getStatements()).thenReturn(statements);
        when(mockUser.getName()).thenReturn(USER);
        when(mockState.getRemoteAddress()).thenReturn(clientSocketAddress);

        AuditEntry.Builder entryBuilder = AuditEntry.newBuilder().permissions(PERMISSIONS).resource(RESOURCE);
        when(mockAuditEntryBuilderFactory.createBatchEntryBuilder()).thenReturn(entryBuilder);

        // When
        auditAdapter.auditBatch(mockBatchStatement, Arrays.asList(PREPARED_STATEMENT, otherPreparedStatement), BATCH_ID, mockState, mockBatchOptions, Status.ATTEMPT, TIMESTAMP);

        // Then
        List<AuditEntry> entries = getAuditEntries(4);
        assertThat(entries).extracting(AuditEntry::getBatchId).containsOnly(Optional.of(BATCH_ID));
        assertThat(entries).extracting(AuditEntry::getStatus).containsOnly(Status.ATTEMPT);
        assertThat(entries).extracting(AuditEntry::getOperation).extracting(AuditOperation::getOperationString)
                           .containsExactly("query1", PREPARED_STATEMENT, "query2", otherPreparedStatement);

        verify(mockAuditEntryBuilderFactory, times(1)).updateBatchEntryBuilder(eq(entryBuilder), eq("query1"), eq(mockState));
        verify(mockAuditEntryBuilderFactory, times(1)).updateBatchEntryBuilder(eq(entryBuilder), eq(firstPrepared));
        verify(mockAuditEntryBuilderFactory, times(1)).updateBatchEntryBuilder(eq(entryBuilder), eq("query2"), eq(mockState));
        verify(mockAuditEntryBuilderFactory, times(1)).updateBatchEntryBuilder(eq(entryBuilder), eq(secondPrepared));
        verify(mockAuditEntryBuilderFactory, times(1)).createBatchEntryBuilder();
        verifyNoMoreInteractions(mockAuditEntryBuilderFactory);
    }

    @Test
    public void testProcessBatchNoLogTimeStrategy()
    {
        // Given
        when(mockAuditor.shouldLogForStatus(any(Status.class))).thenReturn(false);
        // When
        auditAdapter.auditBatch(mock(BatchStatement.class), Collections.emptyList(), mock(UUID.class), mockState, mock(BatchQueryOptions.class), Status.ATTEMPT, TIMESTAMP);
        // Then
        verifyNoMoreInteractions(mockAuditor, mockAuditEntryBuilderFactory);
    }

    @Test
    public void testProcessAuth()
    {
        // Given
        String expectedOperation = "Authentication attempt";
        ConnectionResource resource = ConnectionResource.root();
        String expectedSubject = "bob-the-subject";

        AuditEntry.Builder auditBuilder = AuditEntry.newBuilder().permissions(PERMISSIONS).resource(resource);
        when(mockAuditEntryBuilderFactory.createAuthenticationEntryBuilder()).thenReturn(auditBuilder);

        // When
        auditAdapter.auditAuth(USER, clientAddress, expectedSubject, Status.ATTEMPT, TIMESTAMP);

        // Then
        AuditEntry entry = getAuditEntry();
        assertThat(entry.getClientAddress()).isEqualTo(new InetSocketAddress(clientAddress, CLIENT_AUTH_PORT));
        assertThat(entry.getCoordinatorAddress()).isEqualTo(FBUtilities.getJustBroadcastAddress());
        assertThat(entry.getUser()).isEqualTo(USER);
        assertThat(entry.getOperation().getOperationString()).isEqualTo(expectedOperation);
        assertThat(entry.getStatus()).isEqualTo(Status.ATTEMPT);
        assertThat(entry.getBatchId()).isEmpty();
        assertThat(entry.getPermissions()).isEqualTo(PERMISSIONS);
        assertThat(entry.getResource()).isEqualTo(resource);
        assertThat(entry.getTimestamp()).isEqualTo(TIMESTAMP);
        assertThat(entry.getSubject()).isEqualTo(Optional.of(expectedSubject));
    }

    @Test
    public void testProcessAuthWithoutSubject()
    {
        // Given
        ConnectionResource resource = ConnectionResource.root();

        AuditEntry.Builder auditBuilder = AuditEntry.newBuilder().permissions(PERMISSIONS).resource(resource);
        when(mockAuditEntryBuilderFactory.createAuthenticationEntryBuilder()).thenReturn(auditBuilder);

        // When
        auditAdapter.auditAuth(USER, clientAddress, Status.FAILED, TIMESTAMP);

        // Then
        AuditEntry entry = getAuditEntry();
        assertThat(entry.getClientAddress()).isEqualTo(new InetSocketAddress(clientAddress, AuditEntry.UNKNOWN_PORT));
        assertThat(entry.getCoordinatorAddress()).isEqualTo(FBUtilities.getJustBroadcastAddress());
        assertThat(entry.getUser()).isEqualTo(USER);
        assertThat(entry.getOperation().getOperationString()).isEqualTo("Authentication failed");
        assertThat(entry.getStatus()).isEqualTo(Status.FAILED);
        assertThat(entry.getBatchId()).isEmpty();
        assertThat(entry.getResource()).isEqualTo(resource);
        assertThat(entry.getTimestamp()).isEqualTo(TIMESTAMP);
        assertThat(entry.getSubject()).isEmpty();
    }

    @Test
    public void testProcessAuthNoLogTimeStrategy()
    {
        // Given
        when(mockAuditor.shouldLogForStatus(any(Status.class))).thenReturn(false);
        // When
        auditAdapter.auditAuth(USER, clientAddress, Status.ATTEMPT, TIMESTAMP);
        // Then
        verifyNoMoreInteractions(mockAuditor, mockAuditEntryBuilderFactory);
    }

    @Test
    public void testProcessAuthException()
    {
        AuditEntry.Builder entryBuilder = AuditEntry.newBuilder().permissions(PERMISSIONS).resource(ConnectionResource.root());
        when(mockAuditEntryBuilderFactory.createAuthenticationEntryBuilder()).thenReturn(entryBuilder);

        doThrow(new ReadTimeoutException(ConsistencyLevel.QUORUM, 3, 4, true)).when(mockAuditor).audit(any(AuditEntry.class));

        assertThatExceptionOfType(AuthenticationException.class)
        .isThrownBy(() -> auditAdapter.auditAuth(USER, clientAddress, Status.ATTEMPT, TIMESTAMP));
    }

    @Test
    public void testStatusToAuthenticationOperation()
    {
        // Given
        Status mockStatus = mock(Status.class);
        when(mockStatus.getDisplayName()).thenReturn("OK");
        // When
        SimpleAuditOperation operation = AuditAdapter.statusToAuthenticationOperation(mockStatus);
        // Then
        assertThat(operation.getOperationString()).isEqualTo("Authentication OK");
    }

    @Test
    public void testProcessAuthExceptionKeepsCause()
    {
        // Given
        AuditEntry.Builder entryBuilder = AuditEntry.newBuilder().permissions(PERMISSIONS).resource(ConnectionResource.root());
        when(mockAuditEntryBuilderFactory.createAuthenticationEntryBuilder()).thenReturn(entryBuilder);

        ReadTimeoutException expectedCause = new ReadTimeoutException(ConsistencyLevel.QUORUM, 3, 4, true);
        doThrow(expectedCause).when(mockAuditor).audit(any(AuditEntry.class));

        // When / Then
        assertThatExceptionOfType(AuthenticationException.class)
        .isThrownBy(() -> auditAdapter.auditAuth(USER, clientAddress, "bob-the-subject", Status.SUCCEEDED, TIMESTAMP))
        .withMessage(expectedCause.toString())
        .satisfies(e -> assertThat(e.getCause()).isSameAs(expectedCause));
    }

    @Test
    public void testProcessAuthUnexpectedExceptionIsNotWrapped()
    {
        // Given
        AuditEntry.Builder entryBuilder = AuditEntry.newBuilder().permissions(PERMISSIONS).resource(ConnectionResource.root());
        when(mockAuditEntryBuilderFactory.createAuthenticationEntryBuilder()).thenReturn(entryBuilder);

        IllegalStateException expectedException = new IllegalStateException("logger failure");
        doThrow(expectedException).when(mockAuditor).audit(any(AuditEntry.class));

        // When / Then
        assertThatExceptionOfType(IllegalStateException.class)
        .isThrownBy(() -> auditAdapter.auditAuth(USER, clientAddress, Status.ATTEMPT, TIMESTAMP))
        .satisfies(e -> assertThat(e).isSameAs(expectedException));
    }

    @Test
    public void testStatusToAuthenticationOperationForAllStatuses()
    {
        assertThat(AuditAdapter.statusToAuthenticationOperation(Status.ATTEMPT).getOperationString()).isEqualTo("Authentication attempt");
        assertThat(AuditAdapter.statusToAuthenticationOperation(Status.FAILED).getOperationString()).isEqualTo("Authentication failed");
        assertThat(AuditAdapter.statusToAuthenticationOperation(Status.SUCCEEDED).getOperationString()).isEqualTo("Authentication succeeded");
    }

    @Test
    public void testGetAuditor()
    {
        assertThat(auditAdapter.getAuditor()).isSameAs(mockAuditor);
    }

    @Test
    public void testGetInstanceReturnsSameInstance()
    {
        assertThat(AuditAdapter.getInstance()).isSameAs(AuditAdapter.getInstance());
    }

    @Test
    public void testBoundValueSuppressorAccessors()
    {
        // Given
        BoundValueSuppressor suppressor = mock(BoundValueSuppressor.class);
        assertThat(auditAdapter.getBoundValueSuppressor()).isSameAs(mockBoundValueSuppressor);
        // When
        auditAdapter.setBoundValueSuppressor(suppressor);
        // Then
        assertThat(auditAdapter.getBoundValueSuppressor()).isSameAs(suppressor);
    }

    private ImmutableList<ColumnSpecification> createTextColumns(String... columns)
    {
        ImmutableList.Builder<ColumnSpecification> builder = ImmutableList.builder();

        for (String column : columns)
        {
            ColumnIdentifier id = new ColumnIdentifier(ByteBuffer.wrap(column.getBytes()), UTF8Type.instance);
            ColumnSpecification columnSpecification = new ColumnSpecification("ks", "cf", id, UTF8Type.instance);
            builder.add(columnSpecification);
        }

        return builder.build();
    }

    private List<ByteBuffer> createValues(String... values)
    {
        List<ByteBuffer> rawValues = new ArrayList<>();

        for (String value : values)
        {
            ByteBuffer rawValue = ByteBuffer.wrap(value.getBytes());
            rawValues.add(rawValue);
        }

        return rawValues;
    }

    private AuditEntry getAuditEntry()
    {
        ArgumentCaptor<AuditEntry> captor = ArgumentCaptor.forClass(AuditEntry.class);
        verify(mockAuditor, times(1)).audit(captor.capture());

        return captor.getValue();
    }

    private List<AuditEntry> getAuditEntries(int expectedNumberOfEntries)
    {
        ArgumentCaptor<AuditEntry> captor = ArgumentCaptor.forClass(AuditEntry.class);
        verify(mockAuditor, times(expectedNumberOfEntries)).audit(captor.capture());

        return captor.getAllValues();
    }
}
