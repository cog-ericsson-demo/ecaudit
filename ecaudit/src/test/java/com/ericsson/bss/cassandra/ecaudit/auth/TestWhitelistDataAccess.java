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
package com.ericsson.bss.cassandra.ecaudit.auth;

import java.lang.reflect.Constructor;
import java.nio.ByteBuffer;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.stream.Collectors;

import com.google.common.collect.ImmutableSet;
import com.google.common.collect.Sets;

import org.junit.After;
import org.junit.AfterClass;
import org.junit.Before;
import org.junit.BeforeClass;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.slf4j.LoggerFactory;

import ch.qos.logback.classic.Level;
import ch.qos.logback.classic.LoggerContext;
import ch.qos.logback.classic.spi.ILoggingEvent;
import ch.qos.logback.core.Appender;
import com.ericsson.bss.cassandra.ecaudit.test.mode.ClientInitializer;
import org.apache.cassandra.auth.DataResource;
import org.apache.cassandra.auth.IResource;
import org.apache.cassandra.auth.Permission;
import org.apache.cassandra.auth.RoleResource;
import org.apache.cassandra.cql3.CQLStatement;
import org.apache.cassandra.cql3.ColumnIdentifier;
import org.apache.cassandra.cql3.ColumnSpecification;
import org.apache.cassandra.cql3.QueryOptions;
import org.apache.cassandra.cql3.QueryProcessor;
import org.apache.cassandra.cql3.ResultSet;
import org.apache.cassandra.cql3.UntypedResultSet;
import org.apache.cassandra.cql3.statements.DeleteStatement;
import org.apache.cassandra.cql3.statements.SelectStatement;
import org.apache.cassandra.cql3.statements.UpdateStatement;
import org.apache.cassandra.cql3.statements.schema.CreateTableStatement;
import org.apache.cassandra.db.ConsistencyLevel;
import org.apache.cassandra.db.marshal.SetType;
import org.apache.cassandra.db.marshal.UTF8Type;
import org.apache.cassandra.exceptions.SyntaxException;
import org.apache.cassandra.schema.KeyspaceMetadata;
import org.apache.cassandra.schema.KeyspaceParams;
import org.apache.cassandra.schema.Schema;
import org.apache.cassandra.schema.SchemaConstants;
import org.apache.cassandra.schema.SchemaTransformation;
import org.apache.cassandra.schema.SchemaTransformations;
import org.apache.cassandra.schema.TableMetadata;
import org.apache.cassandra.schema.Tables;
import org.apache.cassandra.serializers.SetSerializer;
import org.apache.cassandra.service.ClientState;
import org.apache.cassandra.service.QueryState;
import org.apache.cassandra.transport.Dispatcher;
import org.apache.cassandra.transport.messages.ResultMessage;
import org.apache.cassandra.utils.ByteBufferUtil;
import org.mockito.ArgumentCaptor;
import org.mockito.Captor;
import org.mockito.Mock;
import org.mockito.MockedConstruction;
import org.mockito.MockedStatic;
import org.mockito.junit.MockitoJUnitRunner;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatExceptionOfType;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyLong;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.ArgumentMatchers.startsWith;
import static org.mockito.Mockito.CALLS_REAL_METHODS;
import static org.mockito.Mockito.atLeast;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.mockConstruction;
import static org.mockito.Mockito.mockStatic;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.mockito.Mockito.when;

/**
 * Tests the {@link WhitelistDataAccess} class.
 */
@RunWith(MockitoJUnitRunner.StrictStubs.class)
public class TestWhitelistDataAccess
{
    private static final String AUTH_KEYSPACE = SchemaConstants.AUTH_KEYSPACE_NAME;
    private static final String ECAUDIT_KEYSPACE = "system_ecaudit";
    private static final String WHITELIST_TABLE = "role_audit_whitelists_v2";

    private static final String LOAD_CQL = "SELECT resource, operations from system_auth.role_audit_whitelists_v2 WHERE role = ?";
    private static final String DELETE_CQL = "DELETE FROM system_auth.role_audit_whitelists_v2 WHERE role = ?";
    private static final String ADD_CQL = "UPDATE system_auth.role_audit_whitelists_v2 SET operations = operations + ? WHERE role = ? AND resource = ?";
    private static final String REMOVE_CQL = "UPDATE system_auth.role_audit_whitelists_v2 SET operations = operations - ? WHERE role = ? AND resource = ?";

    private static final String SELECT_AUTH_CQL = "SELECT * FROM system_auth.role_audit_whitelists_v2";
    private static final String SELECT_ECAUDIT_CQL = "SELECT * FROM system_ecaudit.role_audit_whitelists_v2";
    private static final String INSERT_AUTH_CQL = "INSERT INTO system_auth.role_audit_whitelists_v2 (operations, role, resource) VALUES ( ?, ?, ?)";
    private static final String INSERT_ECAUDIT_CQL = "INSERT INTO system_ecaudit.role_audit_whitelists_v2 (operations, role, resource) VALUES ( ?, ?, ?)";
    private static final String CREATE_ECAUDIT_TABLE_CQL_PREFIX = "CREATE TABLE system_ecaudit.role_audit_whitelists_v2";
    private static final String SCHEMA_ALIGNMENT_TIMEOUT_WARNING = "Schema alignment timeout - continuing startup";

    private static final long SCHEMA_ALIGNMENT_DELAY_MS = Long.getLong("ecaudit.schema_alignment_delay_ms", 120_000L);
    private static final SetSerializer<String> SET_SERIALIZER = SetType.getInstance(UTF8Type.instance, true).getSerializer();
    private static final SchemaTransformation NO_SCHEMA_CHANGE = schema -> schema;

    @Mock
    private SelectStatement mockLoadStatement;

    @Mock
    private DeleteStatement mockDeleteStatement;

    @Mock
    private UpdateStatement mockAddStatement;

    @Mock
    private UpdateStatement mockRemoveStatement;

    @Captor
    private ArgumentCaptor<QueryState> queryStateCaptor;

    @Captor
    private ArgumentCaptor<QueryOptions> queryOptionsCaptor;

    @Captor
    private ArgumentCaptor<List<ByteBuffer>> valuesCaptor;

    @Mock
    private Appender<ILoggingEvent> mockLogAppender;

    @Captor
    private ArgumentCaptor<ILoggingEvent> loggingEventCaptor;

    private MockedStatic<QueryProcessor> queryProcessor;
    private MockedConstruction<SchemaHelper> schemaHelpers;
    private boolean schemasAligned = true;

    private WhitelistDataAccess whitelistDataAccess;

    @BeforeClass
    public static void beforeClass()
    {
        ClientInitializer.beforeClass();
    }

    @Before
    public void before() throws Exception
    {
        queryProcessor = mockStatic(QueryProcessor.class);
        schemaHelpers = mockConstruction(SchemaHelper.class,
                                         (schemaHelper, context) -> when(schemaHelper.areSchemasAligned(anyLong())).thenReturn(schemasAligned));

        // The auth keyspace always exists on a node before the whitelist table is added to it
        givenKeyspaceInSchema(AUTH_KEYSPACE);

        LoggerContext loggerContext = (LoggerContext) LoggerFactory.getILoggerFactory();
        loggerContext.getLogger(WhitelistDataAccess.class).addAppender(mockLogAppender);

        Constructor<WhitelistDataAccess> constructor = WhitelistDataAccess.class.getDeclaredConstructor();
        constructor.setAccessible(true);
        whitelistDataAccess = constructor.newInstance();
    }

    @After
    public void after()
    {
        LoggerContext loggerContext = (LoggerContext) LoggerFactory.getILoggerFactory();
        loggerContext.getLogger(WhitelistDataAccess.class).detachAppender(mockLogAppender);
        Schema.instance.transform(schema -> schema.without(Arrays.asList(AUTH_KEYSPACE, ECAUDIT_KEYSPACE)));
        schemaHelpers.close();
        queryProcessor.close();
    }

    @AfterClass
    public static void afterClass()
    {
        ClientInitializer.afterClass();
    }

    @Test
    public void testGetInstanceReturnsSingleton()
    {
        assertThat(WhitelistDataAccess.getInstance()).isNotNull().isSameAs(WhitelistDataAccess.getInstance());
    }

    @Test
    public void testGetSerializedUpdateValues() throws Exception
    {
        // Given
        Set<Permission> operations = Sets.newHashSet(Permission.SELECT, Permission.MODIFY);
        SetSerializer<String> stringSetSerializer = SetType.getInstance(UTF8Type.instance, true).getSerializer();
        // When
        List<ByteBuffer> values = WhitelistDataAccess.getSerializedUpdateValues("Role1", "Resource1", operations);
        // Then
        assertThat(values).hasSize(3);

        ByteBuffer operationsByteBuffer = values.get(0);
        assertThat(stringSetSerializer.deserialize(operationsByteBuffer)).containsOnly("SELECT", "MODIFY");

        ByteBuffer roleByteBuffer = values.get(1);
        assertThat(ByteBufferUtil.string(roleByteBuffer)).isEqualTo("Role1");

        ByteBuffer resourceByteBuffer = values.get(2);
        assertThat(ByteBufferUtil.string(resourceByteBuffer)).isEqualTo("Resource1");
    }

    @Test
    public void testGetSerializedUpdateValuesWithoutOperations() throws Exception
    {
        // When
        List<ByteBuffer> values = WhitelistDataAccess.getSerializedUpdateValues("Role1", "Resource1", Collections.emptySet());
        // Then
        assertSerializedUpdateValues(values, "Role1", "Resource1");
    }

    @Test
    public void testSetupCreatesWhitelistTableAndPreparesStatements()
    {
        // Given
        givenStatementsCanBePrepared();
        // When
        whitelistDataAccess.setup();
        // Then
        KeyspaceMetadata authKeyspace = Schema.instance.getKeyspaceMetadata(AUTH_KEYSPACE);
        TableMetadata whitelistTable = authKeyspace.getTableNullable(WHITELIST_TABLE);
        assertThat(whitelistTable).isNotNull();
        assertThat(whitelistTable.partitionKeyColumns()).extracting(column -> column.name.toString()).containsExactly("role");
        assertThat(whitelistTable.clusteringColumns()).extracting(column -> column.name.toString()).containsExactly("resource");
        assertThat(whitelistTable.regularColumns()).extracting(column -> column.name.toString()).containsExactly("operations");

        queryProcessor.verify(() -> QueryProcessor.parseStatement(LOAD_CQL));
        queryProcessor.verify(() -> QueryProcessor.parseStatement(DELETE_CQL));
        queryProcessor.verify(() -> QueryProcessor.parseStatement(ADD_CQL));
        queryProcessor.verify(() -> QueryProcessor.parseStatement(REMOVE_CQL));
        queryProcessor.verify(() -> QueryProcessor.parseStatement(anyString()), times(4));
    }

    @Test
    public void testSetupDoesNotWaitForSchemaAlignmentWhenSchemaIsChanged()
    {
        // Given
        givenStatementsCanBePrepared();
        // When
        whitelistDataAccess.setup();
        // Then
        assertThat(schemaHelpers.constructed()).isEmpty();
    }

    @Test
    public void testSetupWaitsForSchemaAlignmentWhenSchemaIsUnchanged()
    {
        // Given
        givenStatementsCanBePrepared();
        try (MockedStatic<SchemaTransformations> schemaTransformations = mockStatic(SchemaTransformations.class, CALLS_REAL_METHODS))
        {
            schemaTransformations.when(() -> SchemaTransformations.updateSystemKeyspace(any(KeyspaceMetadata.class), anyLong()))
                                 .thenReturn(NO_SCHEMA_CHANGE);
            // When
            whitelistDataAccess.setup();
            // Then
            schemaTransformations.verify(() -> SchemaTransformations.updateSystemKeyspace(any(KeyspaceMetadata.class), eq(1L)));
        }
        assertThat(schemaHelpers.constructed()).hasSize(1);
        verify(schemaHelpers.constructed().get(0)).areSchemasAligned(SCHEMA_ALIGNMENT_DELAY_MS);
        assertThat(loggedWarnings()).isEmpty();
        queryProcessor.verify(() -> QueryProcessor.parseStatement(anyString()), times(4));
    }

    @Test
    public void testSetupContinuesWhenSchemaAlignmentTimesOut()
    {
        // Given
        schemasAligned = false;
        givenStatementsCanBePrepared();
        try (MockedStatic<SchemaTransformations> schemaTransformations = mockStatic(SchemaTransformations.class, CALLS_REAL_METHODS))
        {
            schemaTransformations.when(() -> SchemaTransformations.updateSystemKeyspace(any(KeyspaceMetadata.class), anyLong()))
                                 .thenReturn(NO_SCHEMA_CHANGE);
            // When
            whitelistDataAccess.setup();
        }
        // Then
        verify(schemaHelpers.constructed().get(0)).areSchemasAligned(SCHEMA_ALIGNMENT_DELAY_MS);
        assertThat(loggedWarnings()).containsExactly(SCHEMA_ALIGNMENT_TIMEOUT_WARNING);
        queryProcessor.verify(() -> QueryProcessor.parseStatement(anyString()), times(4));
    }

    @Test
    public void testSetupIsOnlyPerformedOnce()
    {
        // Given
        givenStatementsCanBePrepared();
        // When
        whitelistDataAccess.setup();
        whitelistDataAccess.setup();
        // Then
        queryProcessor.verify(() -> QueryProcessor.parseStatement(anyString()), times(4));
    }

    @Test
    public void testSetupFailsWhenStatementIsInvalid()
    {
        // Given
        SyntaxException syntaxException = new SyntaxException("Invalid statement");
        queryProcessor.when(() -> QueryProcessor.parseStatement(anyString())).thenThrow(syntaxException);
        // When, Then
        assertThatExceptionOfType(AssertionError.class)
        .isThrownBy(() -> whitelistDataAccess.setup())
        .withCause(syntaxException);
    }

    @Test
    public void testSetupIsRetriedAfterFailure()
    {
        // Given
        queryProcessor.when(() -> QueryProcessor.parseStatement(anyString())).thenThrow(new SyntaxException("Invalid statement"));
        assertThatExceptionOfType(AssertionError.class).isThrownBy(() -> whitelistDataAccess.setup());
        queryProcessor.reset();
        givenStatementsCanBePrepared();
        // When
        whitelistDataAccess.setup();
        // Then
        queryProcessor.verify(() -> QueryProcessor.parseStatement(anyString()), times(4));
    }

    @Test
    public void testAddToWhitelist() throws Exception
    {
        // Given
        givenSetupIsCompleted();
        // When
        whitelistDataAccess.addToWhitelist(RoleResource.role("Role1"), DataResource.table("ks", "tbl"), ImmutableSet.of(Permission.SELECT, Permission.MODIFY));
        // Then
        verify(mockAddStatement).execute(queryStateCaptor.capture(), queryOptionsCaptor.capture(), any(Dispatcher.RequestTime.class));
        assertThat(queryStateCaptor.getValue().getClientState().isInternal).isTrue();
        assertThat(queryOptionsCaptor.getValue().getConsistency()).isEqualTo(ConsistencyLevel.LOCAL_ONE);
        assertSerializedUpdateValues(queryOptionsCaptor.getValue().getValues(), "Role1", "data/ks/tbl", "SELECT", "MODIFY");
        verifyNoInteractions(mockRemoveStatement, mockLoadStatement, mockDeleteStatement);
    }

    @Test
    public void testAddToWhitelistForDefaultSuperuserUsesQuorum() throws Exception
    {
        // Given
        givenSetupIsCompleted();
        // When
        whitelistDataAccess.addToWhitelist(RoleResource.role("cassandra"), ConnectionResource.root(), ImmutableSet.of(Permission.AUTHORIZE));
        // Then
        verify(mockAddStatement).execute(any(QueryState.class), queryOptionsCaptor.capture(), any(Dispatcher.RequestTime.class));
        assertThat(queryOptionsCaptor.getValue().getConsistency()).isEqualTo(ConsistencyLevel.QUORUM);
        assertSerializedUpdateValues(queryOptionsCaptor.getValue().getValues(), "cassandra", "connections", "AUTHORIZE");
    }

    @Test
    public void testRemoveFromWhitelist() throws Exception
    {
        // Given
        givenSetupIsCompleted();
        // When
        whitelistDataAccess.removeFromWhitelist(RoleResource.role("Role1"), DataResource.keyspace("ks"), ImmutableSet.of(Permission.SELECT));
        // Then
        verify(mockRemoveStatement).execute(queryStateCaptor.capture(), queryOptionsCaptor.capture(), any(Dispatcher.RequestTime.class));
        assertThat(queryStateCaptor.getValue().getClientState().isInternal).isTrue();
        assertThat(queryOptionsCaptor.getValue().getConsistency()).isEqualTo(ConsistencyLevel.LOCAL_ONE);
        assertSerializedUpdateValues(queryOptionsCaptor.getValue().getValues(), "Role1", "data/ks", "SELECT");
        verifyNoInteractions(mockAddStatement, mockLoadStatement, mockDeleteStatement);
    }

    @Test
    public void testRemoveFromWhitelistForDefaultSuperuserUsesQuorum() throws Exception
    {
        // Given
        givenSetupIsCompleted();
        // When
        whitelistDataAccess.removeFromWhitelist(RoleResource.role("cassandra"), DataResource.root(), ImmutableSet.of(Permission.MODIFY));
        // Then
        verify(mockRemoveStatement).execute(any(QueryState.class), queryOptionsCaptor.capture(), any(Dispatcher.RequestTime.class));
        assertThat(queryOptionsCaptor.getValue().getConsistency()).isEqualTo(ConsistencyLevel.QUORUM);
        assertSerializedUpdateValues(queryOptionsCaptor.getValue().getValues(), "cassandra", "data", "MODIFY");
    }

    @Test
    public void testDeleteWhitelist() throws Exception
    {
        // Given
        givenSetupIsCompleted();
        // When
        whitelistDataAccess.deleteWhitelist(RoleResource.role("Role1"));
        // Then
        verify(mockDeleteStatement).execute(queryStateCaptor.capture(), queryOptionsCaptor.capture(), any(Dispatcher.RequestTime.class));
        assertThat(queryStateCaptor.getValue().getClientState().isInternal).isTrue();
        assertThat(queryOptionsCaptor.getValue().getConsistency()).isEqualTo(ConsistencyLevel.LOCAL_ONE);
        assertRoleValue(queryOptionsCaptor.getValue().getValues(), "Role1");
        verifyNoInteractions(mockAddStatement, mockRemoveStatement, mockLoadStatement);
    }

    @Test
    public void testDeleteWhitelistForDefaultSuperuserUsesQuorum() throws Exception
    {
        // Given
        givenSetupIsCompleted();
        // When
        whitelistDataAccess.deleteWhitelist(RoleResource.role("cassandra"));
        // Then
        verify(mockDeleteStatement).execute(any(QueryState.class), queryOptionsCaptor.capture(), any(Dispatcher.RequestTime.class));
        assertThat(queryOptionsCaptor.getValue().getConsistency()).isEqualTo(ConsistencyLevel.QUORUM);
        assertRoleValue(queryOptionsCaptor.getValue().getValues(), "cassandra");
    }

    @Test
    public void testGetWhitelistWithoutEntries() throws Exception
    {
        // Given
        givenSetupIsCompleted();
        givenStoredWhitelist();
        // When
        Map<IResource, Set<Permission>> whitelist = whitelistDataAccess.getWhitelist(RoleResource.role("Role1"));
        // Then
        assertThat(whitelist).isEmpty();
        verify(mockLoadStatement).execute(queryStateCaptor.capture(), queryOptionsCaptor.capture(), any(Dispatcher.RequestTime.class));
        assertThat(queryStateCaptor.getValue().getClientState().isInternal).isTrue();
        assertThat(queryOptionsCaptor.getValue().getConsistency()).isEqualTo(ConsistencyLevel.LOCAL_ONE);
        assertRoleValue(queryOptionsCaptor.getValue().getValues(), "Role1");
        verifyNoInteractions(mockAddStatement, mockRemoveStatement, mockDeleteStatement);
    }

    @Test
    public void testGetWhitelistWithEntries()
    {
        // Given
        givenSetupIsCompleted();
        givenStoredWhitelist(whitelistRow("data/ks/tbl", "SELECT", "MODIFY"),
                             whitelistRow("connections", "AUTHORIZE"),
                             whitelistRow("roles/Role2", "ALTER"),
                             whitelistRow("grants/data/ks", "SELECT"));
        // When
        Map<IResource, Set<Permission>> whitelist = whitelistDataAccess.getWhitelist(RoleResource.role("Role1"));
        // Then
        assertThat(whitelist).hasSize(4);
        assertThat(whitelist.get(DataResource.table("ks", "tbl"))).containsExactlyInAnyOrder(Permission.SELECT, Permission.MODIFY);
        assertThat(whitelist.get(ConnectionResource.root())).containsExactly(Permission.AUTHORIZE);
        assertThat(whitelist.get(RoleResource.role("Role2"))).containsExactly(Permission.ALTER);
        assertThat(whitelist.get(GrantResource.fromResource(DataResource.keyspace("ks")))).containsExactly(Permission.SELECT);
    }

    @Test
    public void testGetWhitelistForDefaultSuperuserUsesQuorum() throws Exception
    {
        // Given
        givenSetupIsCompleted();
        givenStoredWhitelist(whitelistRow("data", "SELECT"));
        // When
        Map<IResource, Set<Permission>> whitelist = whitelistDataAccess.getWhitelist(RoleResource.role("cassandra"));
        // Then
        assertThat(whitelist).containsOnlyKeys(DataResource.root());
        verify(mockLoadStatement).execute(any(QueryState.class), queryOptionsCaptor.capture(), any(Dispatcher.RequestTime.class));
        assertThat(queryOptionsCaptor.getValue().getConsistency()).isEqualTo(ConsistencyLevel.QUORUM);
        assertRoleValue(queryOptionsCaptor.getValue().getValues(), "cassandra");
    }

    @Test
    public void testGetWhitelistSkipsEntryWithInvalidResource()
    {
        // Given
        givenSetupIsCompleted();
        givenStoredWhitelist(whitelistRow("unknown/ks/tbl", "SELECT"),
                             whitelistRow("data/invalid-keyspace", "SELECT"),
                             whitelistRow("data/ks", "MODIFY"));
        // When
        Map<IResource, Set<Permission>> whitelist = whitelistDataAccess.getWhitelist(RoleResource.role("Role1"));
        // Then
        assertThat(whitelist).containsOnlyKeys(DataResource.keyspace("ks"));
        assertThat(whitelist.get(DataResource.keyspace("ks"))).containsExactly(Permission.MODIFY);
    }

    @Test
    public void testGetWhitelistSkipsEntryWithInvalidOperation()
    {
        // Given
        givenSetupIsCompleted();
        givenStoredWhitelist(whitelistRow("data/ks/tbl", "SELECT", "UNKNOWN"),
                             whitelistRow("data/ks", "MODIFY"));
        // When
        Map<IResource, Set<Permission>> whitelist = whitelistDataAccess.getWhitelist(RoleResource.role("Role1"));
        // Then
        assertThat(whitelist).containsOnlyKeys(DataResource.keyspace("ks"));
        assertThat(whitelist.get(DataResource.keyspace("ks"))).containsExactly(Permission.MODIFY);
    }

    @Test
    public void testGetWhitelistWithOnlyInvalidEntries()
    {
        // Given
        givenSetupIsCompleted();
        givenStoredWhitelist(whitelistRow("unknown", "SELECT"),
                             whitelistRow("data", "UNKNOWN"));
        // When
        Map<IResource, Set<Permission>> whitelist = whitelistDataAccess.getWhitelist(RoleResource.role("Role1"));
        // Then
        assertThat(whitelist).isEmpty();
    }

    @Test
    public void testMigrateCreatesKeyspaceAndTableBeforeCopyingData() throws Exception
    {
        // Given
        givenEcauditKeyspaceCanBeCreated();
        givenEcauditTableCanBeCreated();
        givenTableData(SELECT_AUTH_CQL,
                       storedRow("Role1", "data/ks/tbl", "SELECT", "MODIFY"),
                       storedRow("Role2", "connections", "AUTHORIZE"));
        // When
        whitelistDataAccess.migrateTableData();
        // Then
        queryProcessor.verify(() -> QueryProcessor.executeOnceInternal(EcauditKeyspace.CREATE_KEYSPACE));
        queryProcessor.verify(() -> QueryProcessor.executeOnceInternal(startsWith(CREATE_ECAUDIT_TABLE_CQL_PREFIX)));
        assertThat(schemaHelpers.constructed()).hasSize(1);
        verify(schemaHelpers.constructed().get(0)).areSchemasAligned(SCHEMA_ALIGNMENT_DELAY_MS);
        assertThat(loggedWarnings()).isEmpty();

        queryProcessor.verify(() -> QueryProcessor.process(eq(INSERT_ECAUDIT_CQL), eq(ConsistencyLevel.LOCAL_QUORUM), valuesCaptor.capture()), times(2));
        assertSerializedUpdateValues(valuesCaptor.getAllValues().get(0), "Role1", "data/ks/tbl", "SELECT", "MODIFY");
        assertSerializedUpdateValues(valuesCaptor.getAllValues().get(1), "Role2", "connections", "AUTHORIZE");
    }

    @Test
    public void testMigrateCreatesTableWhenOnlyKeyspaceExists() throws Exception
    {
        // Given
        givenKeyspaceInSchema(ECAUDIT_KEYSPACE);
        givenEcauditTableCanBeCreated();
        givenTableData(SELECT_AUTH_CQL, storedRow("Role1", "data/ks/tbl", "SELECT"));
        // When
        whitelistDataAccess.migrateTableData();
        // Then
        queryProcessor.verify(() -> QueryProcessor.executeOnceInternal(startsWith("CREATE KEYSPACE")), never());
        queryProcessor.verify(() -> QueryProcessor.executeOnceInternal(startsWith(CREATE_ECAUDIT_TABLE_CQL_PREFIX)));
        assertThat(schemaHelpers.constructed()).hasSize(1);
        verify(schemaHelpers.constructed().get(0)).areSchemasAligned(SCHEMA_ALIGNMENT_DELAY_MS);

        queryProcessor.verify(() -> QueryProcessor.process(eq(INSERT_ECAUDIT_CQL), eq(ConsistencyLevel.LOCAL_QUORUM), valuesCaptor.capture()));
        assertSerializedUpdateValues(valuesCaptor.getValue(), "Role1", "data/ks/tbl", "SELECT");
    }

    @Test
    public void testMigrateDoesNotChangeSchemaWhenKeyspaceAndTableExist() throws Exception
    {
        // Given
        givenKeyspaceInSchema(ECAUDIT_KEYSPACE, whitelistTable(ECAUDIT_KEYSPACE));
        givenTableData(SELECT_AUTH_CQL, storedRow("Role1", "data/ks/tbl", "SELECT"));
        // When
        whitelistDataAccess.migrateTableData();
        // Then
        queryProcessor.verify(() -> QueryProcessor.executeOnceInternal(anyString()), never());
        assertThat(schemaHelpers.constructed()).isEmpty();

        queryProcessor.verify(() -> QueryProcessor.process(eq(INSERT_ECAUDIT_CQL), eq(ConsistencyLevel.LOCAL_QUORUM), valuesCaptor.capture()));
        assertSerializedUpdateValues(valuesCaptor.getValue(), "Role1", "data/ks/tbl", "SELECT");
    }

    @Test
    public void testMigrateContinuesWhenSchemaAlignmentTimesOut() throws Exception
    {
        // Given
        schemasAligned = false;
        givenKeyspaceInSchema(ECAUDIT_KEYSPACE);
        givenEcauditTableCanBeCreated();
        givenTableData(SELECT_AUTH_CQL, storedRow("Role1", "data/ks/tbl", "SELECT"));
        // When
        whitelistDataAccess.migrateTableData();
        // Then
        verify(schemaHelpers.constructed().get(0)).areSchemasAligned(SCHEMA_ALIGNMENT_DELAY_MS);
        assertThat(loggedWarnings()).containsExactly(SCHEMA_ALIGNMENT_TIMEOUT_WARNING);
        queryProcessor.verify(() -> QueryProcessor.process(eq(INSERT_ECAUDIT_CQL), eq(ConsistencyLevel.LOCAL_QUORUM), valuesCaptor.capture()));
        assertSerializedUpdateValues(valuesCaptor.getValue(), "Role1", "data/ks/tbl", "SELECT");
    }

    @Test
    public void testMigrateWithoutData()
    {
        // Given
        givenKeyspaceInSchema(ECAUDIT_KEYSPACE, whitelistTable(ECAUDIT_KEYSPACE));
        givenTableData(SELECT_AUTH_CQL);
        // When
        whitelistDataAccess.migrateTableData();
        // Then
        queryProcessor.verify(() -> QueryProcessor.process(SELECT_AUTH_CQL, ConsistencyLevel.LOCAL_QUORUM));
        queryProcessor.verify(() -> QueryProcessor.process(anyString(), any(ConsistencyLevel.class), any()), never());
    }

    @Test
    public void testMigrateFailsWhenDataCannotBeRead()
    {
        // Given
        givenKeyspaceInSchema(ECAUDIT_KEYSPACE, whitelistTable(ECAUDIT_KEYSPACE));
        IllegalStateException failure = new IllegalStateException("Not enough replicas");
        queryProcessor.when(() -> QueryProcessor.process(SELECT_AUTH_CQL, ConsistencyLevel.LOCAL_QUORUM)).thenThrow(failure);
        // When, Then
        assertThatExceptionOfType(RuntimeException.class)
        .isThrownBy(() -> whitelistDataAccess.migrateTableData())
        .withMessageContaining("Unable to complete migration of whitelist data")
        .withCause(failure);
        queryProcessor.verify(() -> QueryProcessor.process(anyString(), any(ConsistencyLevel.class), any()), never());
    }

    @Test
    public void testMigrateFailsWhenDataCannotBeWritten()
    {
        // Given
        givenKeyspaceInSchema(ECAUDIT_KEYSPACE, whitelistTable(ECAUDIT_KEYSPACE));
        givenTableData(SELECT_AUTH_CQL,
                       storedRow("Role1", "data/ks/tbl", "SELECT"),
                       storedRow("Role2", "connections", "AUTHORIZE"));
        IllegalStateException failure = new IllegalStateException("Not enough replicas");
        queryProcessor.when(() -> QueryProcessor.process(eq(INSERT_ECAUDIT_CQL), eq(ConsistencyLevel.LOCAL_QUORUM), any())).thenThrow(failure);
        // When, Then
        assertThatExceptionOfType(RuntimeException.class)
        .isThrownBy(() -> whitelistDataAccess.migrateTableData())
        .withMessageContaining("Unable to complete migration of whitelist data")
        .withCause(failure);
        queryProcessor.verify(() -> QueryProcessor.process(eq(INSERT_ECAUDIT_CQL), eq(ConsistencyLevel.LOCAL_QUORUM), any()), times(1));
    }

    @Test
    public void testMigrateFailsWhenDataContainsInvalidOperation()
    {
        // Given
        givenKeyspaceInSchema(ECAUDIT_KEYSPACE, whitelistTable(ECAUDIT_KEYSPACE));
        givenTableData(SELECT_AUTH_CQL, storedRow("Role1", "data/ks/tbl", "UNKNOWN"));
        // When, Then
        assertThatExceptionOfType(RuntimeException.class)
        .isThrownBy(() -> whitelistDataAccess.migrateTableData())
        .withMessageContaining("Unable to complete migration of whitelist data")
        .withCauseInstanceOf(IllegalArgumentException.class);
        queryProcessor.verify(() -> QueryProcessor.process(anyString(), any(ConsistencyLevel.class), any()), never());
    }

    @Test
    public void testDemigrateCopiesData() throws Exception
    {
        // Given
        givenTableData(SELECT_ECAUDIT_CQL,
                       storedRow("Role1", "data/ks/tbl", "SELECT", "MODIFY"),
                       storedRow("Role2", "connections", "AUTHORIZE"));
        // When
        whitelistDataAccess.demigrateTableData();
        // Then
        queryProcessor.verify(() -> QueryProcessor.process(eq(INSERT_AUTH_CQL), eq(ConsistencyLevel.LOCAL_QUORUM), valuesCaptor.capture()), times(2));
        assertSerializedUpdateValues(valuesCaptor.getAllValues().get(0), "Role1", "data/ks/tbl", "SELECT", "MODIFY");
        assertSerializedUpdateValues(valuesCaptor.getAllValues().get(1), "Role2", "connections", "AUTHORIZE");
        queryProcessor.verify(() -> QueryProcessor.executeOnceInternal(anyString()), never());
        assertThat(schemaHelpers.constructed()).isEmpty();
    }

    @Test
    public void testDemigrateWithoutData()
    {
        // Given
        givenTableData(SELECT_ECAUDIT_CQL);
        // When
        whitelistDataAccess.demigrateTableData();
        // Then
        queryProcessor.verify(() -> QueryProcessor.process(SELECT_ECAUDIT_CQL, ConsistencyLevel.LOCAL_QUORUM));
        queryProcessor.verify(() -> QueryProcessor.process(anyString(), any(ConsistencyLevel.class), any()), never());
    }

    @Test
    public void testDemigrateFailsWhenDataCannotBeRead()
    {
        // Given
        IllegalStateException failure = new IllegalStateException("Not enough replicas");
        queryProcessor.when(() -> QueryProcessor.process(SELECT_ECAUDIT_CQL, ConsistencyLevel.LOCAL_QUORUM)).thenThrow(failure);
        // When, Then
        assertThatExceptionOfType(RuntimeException.class)
        .isThrownBy(() -> whitelistDataAccess.demigrateTableData())
        .withMessageContaining("Unable to complete demigration of whitelist data")
        .withCause(failure);
        queryProcessor.verify(() -> QueryProcessor.process(anyString(), any(ConsistencyLevel.class), any()), never());
    }

    @Test
    public void testDemigrateFailsWhenDataCannotBeWritten()
    {
        // Given
        givenTableData(SELECT_ECAUDIT_CQL,
                       storedRow("Role1", "data/ks/tbl", "SELECT"),
                       storedRow("Role2", "connections", "AUTHORIZE"));
        IllegalStateException failure = new IllegalStateException("Not enough replicas");
        queryProcessor.when(() -> QueryProcessor.process(eq(INSERT_AUTH_CQL), eq(ConsistencyLevel.LOCAL_QUORUM), any())).thenThrow(failure);
        // When, Then
        assertThatExceptionOfType(RuntimeException.class)
        .isThrownBy(() -> whitelistDataAccess.demigrateTableData())
        .withMessageContaining("Unable to complete demigration of whitelist data")
        .withCause(failure);
        queryProcessor.verify(() -> QueryProcessor.process(eq(INSERT_AUTH_CQL), eq(ConsistencyLevel.LOCAL_QUORUM), any()), times(1));
    }

    @Test
    public void testDemigrateFailsWhenDataContainsInvalidOperation()
    {
        // Given
        givenTableData(SELECT_ECAUDIT_CQL, storedRow("Role1", "data/ks/tbl", "UNKNOWN"));
        // When, Then
        assertThatExceptionOfType(RuntimeException.class)
        .isThrownBy(() -> whitelistDataAccess.demigrateTableData())
        .withMessageContaining("Unable to complete demigration of whitelist data")
        .withCauseInstanceOf(IllegalArgumentException.class);
        queryProcessor.verify(() -> QueryProcessor.process(anyString(), any(ConsistencyLevel.class), any()), never());
    }

    private void givenSetupIsCompleted()
    {
        givenStatementsCanBePrepared();
        whitelistDataAccess.setup();
    }

    private void givenStatementsCanBePrepared()
    {
        givenStatementCanBePrepared(LOAD_CQL, mockLoadStatement);
        givenStatementCanBePrepared(DELETE_CQL, mockDeleteStatement);
        givenStatementCanBePrepared(ADD_CQL, mockAddStatement);
        givenStatementCanBePrepared(REMOVE_CQL, mockRemoveStatement);
    }

    private void givenStatementCanBePrepared(String cql, CQLStatement statement)
    {
        CQLStatement.Raw rawStatement = mock(CQLStatement.Raw.class);
        when(rawStatement.prepare(any(ClientState.class))).thenReturn(statement);
        queryProcessor.when(() -> QueryProcessor.parseStatement(cql)).thenReturn(rawStatement);
    }

    @SafeVarargs
    private final void givenStoredWhitelist(List<ByteBuffer>... rows)
    {
        List<ColumnSpecification> columns = Arrays.asList(
        new ColumnSpecification(AUTH_KEYSPACE, WHITELIST_TABLE, new ColumnIdentifier("resource", true), UTF8Type.instance),
        new ColumnSpecification(AUTH_KEYSPACE, WHITELIST_TABLE, new ColumnIdentifier("operations", true), SetType.getInstance(UTF8Type.instance, true)));
        ResultSet resultSet = new ResultSet(new ResultSet.ResultMetadata(columns), new ArrayList<>(Arrays.asList(rows)));

        when(mockLoadStatement.execute(any(QueryState.class), any(QueryOptions.class), any(Dispatcher.RequestTime.class)))
        .thenReturn(new ResultMessage.Rows(resultSet));
    }

    private static List<ByteBuffer> whitelistRow(String resource, String... operations)
    {
        return Arrays.asList(ByteBufferUtil.bytes(resource), SET_SERIALIZER.serialize(Sets.newHashSet(operations)));
    }

    @SafeVarargs
    private final void givenTableData(String selectCql, Map<String, ByteBuffer>... rows)
    {
        queryProcessor.when(() -> QueryProcessor.process(selectCql, ConsistencyLevel.LOCAL_QUORUM))
                      .thenReturn(UntypedResultSet.create(Arrays.asList(rows)));
    }

    private static Map<String, ByteBuffer> storedRow(String role, String resource, String... operations)
    {
        Map<String, ByteBuffer> row = new HashMap<>();
        row.put("role", ByteBufferUtil.bytes(role));
        row.put("resource", ByteBufferUtil.bytes(resource));
        row.put("operations", SET_SERIALIZER.serialize(Sets.newHashSet(operations)));
        return row;
    }

    private void givenEcauditKeyspaceCanBeCreated()
    {
        queryProcessor.when(() -> QueryProcessor.executeOnceInternal(EcauditKeyspace.CREATE_KEYSPACE))
                      .thenAnswer(invocation -> {
                          givenKeyspaceInSchema(ECAUDIT_KEYSPACE);
                          return null;
                      });
    }

    private void givenEcauditTableCanBeCreated()
    {
        queryProcessor.when(() -> QueryProcessor.executeOnceInternal(startsWith(CREATE_ECAUDIT_TABLE_CQL_PREFIX)))
                      .thenAnswer(invocation -> {
                          givenKeyspaceInSchema(ECAUDIT_KEYSPACE, whitelistTable(ECAUDIT_KEYSPACE));
                          return null;
                      });
    }

    private static void givenKeyspaceInSchema(String keyspace, TableMetadata... tables)
    {
        KeyspaceMetadata keyspaceMetadata = KeyspaceMetadata.create(keyspace, KeyspaceParams.simple(1), Tables.of(tables));
        Schema.instance.transform(schema -> schema.withAddedOrReplaced(keyspaceMetadata));
    }

    private static TableMetadata whitelistTable(String keyspace)
    {
        return CreateTableStatement.parse("CREATE TABLE " + WHITELIST_TABLE + " ("
                                          + "role text,"
                                          + "resource text,"
                                          + "operations set<text>,"
                                          + "PRIMARY KEY(role, resource))", keyspace)
                                   .build();
    }

    private List<String> loggedWarnings()
    {
        verify(mockLogAppender, atLeast(0)).doAppend(loggingEventCaptor.capture());
        return loggingEventCaptor.getAllValues()
                                 .stream()
                                 .filter(event -> event.getLevel() == Level.WARN)
                                 .map(ILoggingEvent::getFormattedMessage)
                                 .collect(Collectors.toList());
    }

    private static void assertSerializedUpdateValues(List<ByteBuffer> values, String role, String resource, String... operations) throws Exception
    {
        assertThat(values).hasSize(3);
        assertThat(SET_SERIALIZER.deserialize(values.get(0))).containsExactlyInAnyOrder(operations);
        assertThat(ByteBufferUtil.string(values.get(1))).isEqualTo(role);
        assertThat(ByteBufferUtil.string(values.get(2))).isEqualTo(resource);
    }

    private static void assertRoleValue(List<ByteBuffer> values, String role) throws Exception
    {
        assertThat(values).hasSize(1);
        assertThat(ByteBufferUtil.string(values.get(0))).isEqualTo(role);
    }
}
