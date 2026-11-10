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
package com.ericsson.bss.cassandra.ecaudit.entry.factory;

import java.util.Set;

import com.google.common.collect.ImmutableSet;
import org.apache.commons.lang3.reflect.FieldUtils;
import org.junit.AfterClass;
import org.junit.Before;
import org.junit.BeforeClass;
import org.junit.Test;
import org.junit.runner.RunWith;

import com.ericsson.bss.cassandra.ecaudit.auth.ConnectionResource;
import com.ericsson.bss.cassandra.ecaudit.entry.AuditEntry;
import com.ericsson.bss.cassandra.ecaudit.facade.CassandraAuditException;
import com.ericsson.bss.cassandra.ecaudit.test.mode.ClientInitializer;
import junitparams.JUnitParamsRunner;
import junitparams.Parameters;
import org.apache.cassandra.auth.Permission;
import org.apache.cassandra.cql3.CQLStatement;
import org.apache.cassandra.cql3.QueryProcessor;
import org.apache.cassandra.cql3.statements.AuthenticationStatement;
import org.apache.cassandra.cql3.statements.AuthorizationStatement;
import org.apache.cassandra.cql3.statements.BatchStatement;
import org.apache.cassandra.cql3.statements.ModificationStatement;
import org.apache.cassandra.cql3.statements.SelectStatement;
import org.apache.cassandra.db.marshal.Int32Type;
import org.apache.cassandra.db.view.View;
import org.apache.cassandra.exceptions.InvalidRequestException;
import org.apache.cassandra.schema.TableMetadata;
import org.apache.cassandra.schema.TableMetadataRef;
import org.apache.cassandra.service.ClientState;
import org.mockito.MockedStatic;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatExceptionOfType;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyBoolean;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.mockStatic;
import static org.mockito.Mockito.when;

/**
 * Tests the {@link AuditEntryBuilderFactory} class.
 *
 * Statements are mapped in two different ways by the factory, here referred to as <em>prepared</em> and <em>raw</em>.
 * The raw mapping is used as a fallback by {@link AuditEntryBuilderFactory#createEntryBuilder(String, ClientState)}
 * when Cassandra fails to prepare the statement.
 */
@RunWith(JUnitParamsRunner.class)
public class TestAuditEntryBuilderFactory
{
    private static final Set<Permission> ALL = ImmutableSet.copyOf(Permission.ALL);
    private static final Set<Permission> USE = ImmutableSet.of(Permission.CREATE, Permission.ALTER, Permission.DROP,
                                                               Permission.SELECT, Permission.MODIFY, Permission.AUTHORIZE);
    private static final Set<Permission> CAS = ImmutableSet.of(Permission.SELECT, Permission.MODIFY);
    private static final Set<Permission> SELECT = ImmutableSet.of(Permission.SELECT);
    private static final Set<Permission> MODIFY = ImmutableSet.of(Permission.MODIFY);
    private static final Set<Permission> EXECUTE = ImmutableSet.of(Permission.EXECUTE);
    private static final Set<Permission> CREATE = ImmutableSet.of(Permission.CREATE);
    private static final Set<Permission> ALTER = ImmutableSet.of(Permission.ALTER);
    private static final Set<Permission> DROP = ImmutableSet.of(Permission.DROP);
    private static final Set<Permission> DESCRIBE = ImmutableSet.of(Permission.DESCRIBE);
    private static final Set<Permission> AUTHORIZE = ImmutableSet.of(Permission.AUTHORIZE);

    private static final String ROOT = "data";
    private static final String KEYSPACE = "data/ks";
    private static final String TABLE = "data/ks/tbl";

    private static ClientState clientState;

    private AuditEntryBuilderFactory factory;

    @BeforeClass
    public static void beforeClass()
    {
        ClientInitializer.beforeClass();
        clientState = ClientState.forInternalCalls();
    }

    @AfterClass
    public static void afterClass()
    {
        ClientInitializer.afterClass();
    }

    @Before
    public void before()
    {
        factory = new AuditEntryBuilderFactory();
    }

    @Test
    public void testAuthenticationEntryBuilder()
    {
        // Given
        // When
        AuditEntry entry = factory.createAuthenticationEntryBuilder().build();
        // Then
        assertThat(entry.getPermissions()).isEqualTo(EXECUTE);
        assertThat(entry.getResource()).isEqualTo(ConnectionResource.root());
        assertThat(entry.hasKnownOperation()).isTrue();
    }

    @Test
    public void testBatchEntryBuilder()
    {
        // Given
        // When
        AuditEntry entry = factory.createBatchEntryBuilder().build();
        // Then
        assertEntry(entry, CAS, ROOT, true);
    }

    @Test
    @Parameters(method = "testPreparedStatement_parameters")
    public void testPreparedStatement(String operation, Set<Permission> expectedPermissions, String expectedResource)
    {
        // Given
        CQLStatement statement = QueryProcessor.parseStatement(operation).prepare(clientState);
        // When
        AuditEntry entry = factory.createEntryBuilder(statement).build();
        // Then
        assertEntry(entry, expectedPermissions, expectedResource, true);
    }

    public Object[][] testPreparedStatement_parameters()
    {
        return new Object[][]{
            { "TRUNCATE ks.tbl", MODIFY, TABLE },
            { "USE ks", USE, KEYSPACE },
            { "CREATE KEYSPACE ks WITH replication = {'class': 'SimpleStrategy', 'replication_factor': 1}", CREATE, KEYSPACE },
            { "ALTER KEYSPACE ks WITH durable_writes = false", ALTER, KEYSPACE },
            { "DROP KEYSPACE ks", DROP, KEYSPACE },
            { "CREATE TABLE ks.tbl (k int PRIMARY KEY, v int)", CREATE, TABLE },
            { "ALTER TABLE ks.tbl ADD v2 int", ALTER, TABLE },
            { "DROP TABLE ks.tbl", DROP, TABLE },
            { "CREATE MATERIALIZED VIEW ks.mv AS SELECT * FROM ks.tbl WHERE k IS NOT NULL AND v IS NOT NULL PRIMARY KEY (v, k)", ALTER, TABLE },
            // The base table of a view can't be resolved unless the view exists in the schema
            { "ALTER MATERIALIZED VIEW ks.mv WITH comment = 'c'", ALTER, KEYSPACE },
            { "DROP MATERIALIZED VIEW ks.mv", ALTER, KEYSPACE },
            { "CREATE TYPE ks.tp (a int)", CREATE, KEYSPACE },
            { "ALTER TYPE ks.tp ADD b int", ALTER, KEYSPACE },
            { "DROP TYPE ks.tp", DROP, KEYSPACE },
            { "CREATE FUNCTION ks.fn (a int) RETURNS NULL ON NULL INPUT RETURNS int LANGUAGE java AS 'return a;'", CREATE, "functions/ks" },
            { "DROP FUNCTION ks.fn", DROP, "functions/ks/fn[]" },
            { "CREATE AGGREGATE ks.agg (int) SFUNC fn STYPE int", CREATE, "functions/ks" },
            { "DROP AGGREGATE ks.agg", DROP, "functions/ks/agg[]" },
            { "CREATE INDEX idx ON ks.tbl (v)", ALTER, TABLE },
            // The indexed table can't be resolved unless the index exists in the schema
            { "DROP INDEX ks.idx", ALTER, KEYSPACE },
            { "CREATE TRIGGER trg ON ks.tbl USING 'org.Example'", USE, "data/ks/trg" },
            { "DROP TRIGGER trg ON ks.tbl", USE, "data/ks/trg" },
            { "CREATE ROLE bob WITH PASSWORD = 'secret' AND LOGIN = true", CREATE, "roles/bob" },
            { "ALTER ROLE bob WITH LOGIN = false", ALTER, "roles/bob" },
            { "DROP ROLE bob", DROP, "roles/bob" },
            { "GRANT bob TO alice", AUTHORIZE, "roles/bob" },
            { "REVOKE bob FROM alice", AUTHORIZE, "roles/bob" },
            { "LIST ROLES", DESCRIBE, "roles" },
            { "LIST ROLES OF bob", DESCRIBE, "roles/bob" },
            { "LIST ALL PERMISSIONS", AUTHORIZE, "roles" },
            { "LIST ALL PERMISSIONS OF bob", AUTHORIZE, "roles/bob" },
            { "GRANT SELECT ON ks.tbl TO bob", AUTHORIZE, TABLE },
            { "REVOKE MODIFY ON KEYSPACE ks FROM bob", AUTHORIZE, KEYSPACE },
            { "DESCRIBE TABLE ks.tbl", DESCRIBE, "data/null/null" },
        };
    }

    @Test
    @Parameters(method = "testExistingView_parameters")
    public void testPreparedStatementOnExistingView(String operation)
    {
        try (MockedStatic<View> view = mockStatic(View.class))
        {
            // Given
            givenViewExistsInSchema(view);
            CQLStatement statement = QueryProcessor.parseStatement(operation).prepare(clientState);
            // When
            AuditEntry entry = factory.createEntryBuilder(statement).build();
            // Then
            assertEntry(entry, ALTER, TABLE, true);
        }
    }

    public Object[][] testExistingView_parameters()
    {
        return new Object[][]{
            { "ALTER MATERIALIZED VIEW ks.mv WITH comment = 'c'" },
            { "DROP MATERIALIZED VIEW ks.mv" },
        };
    }

    @Test
    public void testPreparedSelectStatement()
    {
        // Given
        SelectStatement statement = mock(SelectStatement.class);
        when(statement.keyspace()).thenReturn("ks");
        when(statement.table()).thenReturn("tbl");
        // When
        AuditEntry entry = factory.createEntryBuilder(statement).build();
        // Then
        assertEntry(entry, SELECT, TABLE, true);
    }

    @Test
    public void testPreparedModificationStatement()
    {
        // Given
        ModificationStatement statement = mockModificationStatement(false);
        // When
        AuditEntry entry = factory.createEntryBuilder(statement).build();
        // Then
        assertEntry(entry, MODIFY, TABLE, true);
    }

    @Test
    public void testPreparedConditionalModificationStatement()
    {
        // Given
        ModificationStatement statement = mockModificationStatement(true);
        // When
        AuditEntry entry = factory.createEntryBuilder(statement).build();
        // Then
        assertEntry(entry, CAS, TABLE, true);
    }

    @Test
    public void testPreparedBatchStatement()
    {
        // Given
        BatchStatement statement = mock(BatchStatement.class);
        // When
        AuditEntry entry = factory.createEntryBuilder(statement).build();
        // Then
        assertEntry(entry, CAS, ROOT, true);
    }

    @Test
    public void testPreparedUnknownStatement()
    {
        // Given
        CQLStatement statement = mock(CQLStatement.class);
        // When
        AuditEntry entry = factory.createEntryBuilder(statement).build();
        // Then
        assertEntry(entry, ALL, ROOT, false);
    }

    @Test
    public void testPreparedUnknownAuthenticationStatement()
    {
        // Given
        CQLStatement statement = mock(AuthenticationStatement.class);
        // When
        AuditEntry entry = factory.createEntryBuilder(statement).build();
        // Then
        assertEntry(entry, ALL, ROOT, true);
    }

    @Test
    public void testPreparedUnknownAuthorizationStatement()
    {
        // Given
        CQLStatement statement = mock(AuthorizationStatement.class);
        // When
        AuditEntry entry = factory.createEntryBuilder(statement).build();
        // Then
        assertEntry(entry, ALL, ROOT, true);
    }

    @Test
    @Parameters(method = "testRawStatement_parameters")
    public void testRawStatement(String operation, Set<Permission> expectedPermissions, String expectedResource)
    {
        try (MockedStatic<QueryProcessor> queryProcessor = mockStatic(QueryProcessor.class))
        {
            // Given
            givenStatementIsRejectedAtPrepare(queryProcessor);
            // When
            AuditEntry entry = factory.createEntryBuilder(operation, clientState).build();
            // Then
            assertEntry(entry, expectedPermissions, expectedResource, true);
        }
    }

    public Object[][] testRawStatement_parameters()
    {
        return new Object[][]{
            { "SELECT * FROM ks.tbl", SELECT, TABLE },
            { "INSERT INTO ks.tbl (k, v) VALUES (1, 2)", MODIFY, TABLE },
            { "INSERT INTO ks.tbl (k, v) VALUES (1, 2) IF NOT EXISTS", MODIFY, TABLE },
            { "UPDATE ks.tbl SET v = 2 WHERE k = 1", MODIFY, TABLE },
            { "UPDATE ks.tbl SET v = 2 WHERE k = 1 IF v = 1", CAS, TABLE },
            { "DELETE FROM ks.tbl WHERE k = 1", MODIFY, TABLE },
            { "DELETE FROM ks.tbl WHERE k = 1 IF v = 1", CAS, TABLE },
            { "BEGIN BATCH INSERT INTO ks.tbl (k, v) VALUES (1, 2); APPLY BATCH", CAS, ROOT },
            { "TRUNCATE ks.tbl", MODIFY, TABLE },
            { "USE ks", USE, KEYSPACE },
            { "CREATE KEYSPACE ks WITH replication = {'class': 'SimpleStrategy', 'replication_factor': 1}", CREATE, KEYSPACE },
            { "ALTER KEYSPACE ks WITH durable_writes = false", ALTER, KEYSPACE },
            { "DROP KEYSPACE ks", DROP, KEYSPACE },
            { "CREATE TABLE ks.tbl (k int PRIMARY KEY, v int)", CREATE, TABLE },
            { "ALTER TABLE ks.tbl ADD v2 int", ALTER, TABLE },
            { "DROP TABLE ks.tbl", DROP, TABLE },
            { "CREATE MATERIALIZED VIEW ks.mv AS SELECT * FROM ks.tbl WHERE k IS NOT NULL AND v IS NOT NULL PRIMARY KEY (v, k)", ALTER, TABLE },
            { "CREATE TYPE ks.tp (a int)", CREATE, KEYSPACE },
            { "ALTER TYPE ks.tp ADD b int", ALTER, KEYSPACE },
            { "DROP TYPE ks.tp", DROP, KEYSPACE },
            { "CREATE FUNCTION ks.fn (a int) RETURNS NULL ON NULL INPUT RETURNS int LANGUAGE java AS 'return a;'", CREATE, "functions/ks" },
            { "DROP FUNCTION ks.fn", DROP, "functions/ks/fn[]" },
            { "DROP AGGREGATE ks.agg", DROP, "functions/ks/agg[]" },
            { "CREATE INDEX idx ON ks.tbl (v)", ALTER, TABLE },
            // The indexed table can't be resolved unless the index exists in the schema
            { "DROP INDEX ks.idx", ALTER, KEYSPACE },
            { "CREATE TRIGGER trg ON ks.tbl USING 'org.Example'", USE, TABLE },
            { "DROP TRIGGER trg ON ks.tbl", USE, TABLE },
            { "CREATE ROLE bob WITH PASSWORD = 'secret' AND LOGIN = true", CREATE, "roles/bob" },
            { "ALTER ROLE bob WITH LOGIN = false", ALTER, "roles/bob" },
            { "DROP ROLE bob", DROP, "roles/bob" },
            { "GRANT bob TO alice", AUTHORIZE, "roles/bob" },
            { "REVOKE bob FROM alice", AUTHORIZE, "roles/bob" },
            { "LIST ROLES", DESCRIBE, "roles" },
            { "LIST ROLES OF bob", DESCRIBE, "roles/bob" },
            { "LIST ALL PERMISSIONS", AUTHORIZE, "roles" },
            { "LIST ALL PERMISSIONS OF bob", AUTHORIZE, "roles/bob" },
            { "GRANT SELECT ON ks.tbl TO bob", AUTHORIZE, TABLE },
            { "REVOKE MODIFY ON KEYSPACE ks FROM bob", AUTHORIZE, KEYSPACE },
            { "DESCRIBE TABLE ks.tbl", DESCRIBE, "data/null/null" },
        };
    }

    @Test
    @Parameters(method = "testExistingView_parameters")
    public void testRawStatementOnExistingView(String operation)
    {
        try (MockedStatic<QueryProcessor> queryProcessor = mockStatic(QueryProcessor.class);
             MockedStatic<View> view = mockStatic(View.class))
        {
            // Given
            givenStatementIsRejectedAtPrepare(queryProcessor);
            givenViewExistsInSchema(view);
            // When
            AuditEntry entry = factory.createEntryBuilder(operation, clientState).build();
            // Then
            assertEntry(entry, ALTER, TABLE, true);
        }
    }

    @Test
    public void testRawStatementUsesKeyspaceFromClientState()
    {
        try (MockedStatic<QueryProcessor> queryProcessor = mockStatic(QueryProcessor.class))
        {
            // Given
            givenStatementIsRejectedAtPrepare(queryProcessor);
            ClientState stateWithKeyspace = ClientState.forInternalCalls("ks");
            // When
            AuditEntry entry = factory.createEntryBuilder("SELECT * FROM tbl", stateWithKeyspace).build();
            // Then
            assertEntry(entry, SELECT, TABLE, true);
        }
    }

    @Test
    @Parameters(method = "testRawStatementWithInaccessibleField_parameters")
    public void testRawStatementWithInaccessibleField(String operation)
    {
        try (MockedStatic<QueryProcessor> queryProcessor = mockStatic(QueryProcessor.class);
             MockedStatic<FieldUtils> fieldUtils = mockStatic(FieldUtils.class))
        {
            // Given
            givenStatementIsRejectedAtPrepare(queryProcessor);
            fieldUtils.when(() -> FieldUtils.readField(any(Object.class), anyString(), anyBoolean()))
                      .thenThrow(new IllegalAccessException("Field is not accessible"));
            // When
            AuditEntry entry = factory.createEntryBuilder(operation, clientState).build();
            // Then
            assertEntry(entry, ALL, ROOT, false);
        }
    }

    public Object[][] testRawStatementWithInaccessibleField_parameters()
    {
        return new Object[][]{
            { "INSERT INTO ks.tbl (k, v) VALUES (1, 2)" },
            { "ALTER KEYSPACE ks WITH durable_writes = false" },
            { "DROP KEYSPACE ks" },
            { "ALTER TABLE ks.tbl ADD v2 int" },
            { "DROP TABLE ks.tbl" },
            { "CREATE TYPE ks.tp (a int)" },
            { "ALTER TYPE ks.tp ADD b int" },
            { "DROP TYPE ks.tp" },
            { "CREATE TRIGGER trg ON ks.tbl USING 'org.Example'" },
            { "DROP TRIGGER trg ON ks.tbl" },
        };
    }

    @Test
    public void testRawUnknownStatement()
    {
        // Given
        CQLStatement.Raw statement = mock(CQLStatement.Raw.class);
        // When
        AuditEntry entry = createEntryForRawStatement(statement);
        // Then
        assertEntry(entry, ALL, ROOT, false);
    }

    @Test
    public void testRawUnknownAuthenticationStatement()
    {
        // Given
        CQLStatement.Raw statement = mock(AuthenticationStatement.class);
        // When
        AuditEntry entry = createEntryForRawStatement(statement);
        // Then
        assertEntry(entry, ALL, ROOT, true);
    }

    @Test
    public void testRawUnknownAuthorizationStatement()
    {
        // Given
        CQLStatement.Raw statement = mock(AuthorizationStatement.class);
        // When
        AuditEntry entry = createEntryForRawStatement(statement);
        // Then
        assertEntry(entry, ALL, ROOT, true);
    }

    @Test
    public void testOperationIsMappedFromPreparedStatement()
    {
        // Given
        String operation = "CREATE TABLE ks.tbl (k int PRIMARY KEY, v int)";
        // When
        AuditEntry entry = factory.createEntryBuilder(operation, clientState).build();
        // Then
        assertEntry(entry, CREATE, TABLE, true);
    }

    @Test
    public void testOperationOnUnknownKeyspaceIsMappedFromRawStatement()
    {
        // Given
        String operation = "UPDATE ks.tbl SET v = 2 WHERE k = 1 IF v = 1";
        // When
        AuditEntry entry = factory.createEntryBuilder(operation, clientState).build();
        // Then
        assertEntry(entry, CAS, TABLE, true);
    }

    @Test
    @Parameters(method = "testOperationWithDefaultMapping_parameters")
    public void testOperationWithDefaultMapping(String operation)
    {
        // Given
        // When
        AuditEntry entry = factory.createEntryBuilder(operation, clientState).build();
        // Then
        assertEntry(entry, ALL, ROOT, false);
    }

    public Object[][] testOperationWithDefaultMapping_parameters()
    {
        return new Object[][]{
            // Invalid syntax
            { "SELECT * FROM" },
            { "this is not cql" },
            // No keyspace in statement or client state
            { "SELECT * FROM tbl" },
            { "INSERT INTO tbl (k, v) VALUES (1, 2)" },
            // Argument types can't be resolved unless the keyspace exists in the schema
            { "DROP FUNCTION ks.fn (int)" },
            { "DROP AGGREGATE ks.agg (int)" },
        };
    }

    @Test
    public void testUpdateBatchEntryBuilderWithStatement()
    {
        // Given
        AuditEntry.Builder builder = factory.createBatchEntryBuilder();
        ModificationStatement statement = mockModificationStatement(false);
        // When
        AuditEntry.Builder updatedBuilder = factory.updateBatchEntryBuilder(builder, statement);
        // Then
        assertThat(updatedBuilder).isSameAs(builder);
        assertEntry(updatedBuilder.build(), MODIFY, TABLE, true);
    }

    @Test
    public void testUpdateBatchEntryBuilderWithConditionalStatement()
    {
        // Given
        AuditEntry.Builder builder = factory.createBatchEntryBuilder();
        ModificationStatement statement = mockModificationStatement(true);
        // When
        AuditEntry.Builder updatedBuilder = factory.updateBatchEntryBuilder(builder, statement);
        // Then
        assertThat(updatedBuilder).isSameAs(builder);
        assertEntry(updatedBuilder.build(), CAS, TABLE, true);
    }

    @Test
    public void testUpdateBatchEntryBuilderWithOperation()
    {
        try (MockedStatic<QueryProcessor> queryProcessor = mockStatic(QueryProcessor.class))
        {
            // Given
            String operation = "INSERT INTO ks.tbl (k, v) VALUES (1, 2)";
            ModificationStatement statement = mockModificationStatement(false);
            queryProcessor.when(() -> QueryProcessor.getStatement(operation, clientState)).thenReturn(statement);
            AuditEntry.Builder builder = factory.createBatchEntryBuilder();
            // When
            AuditEntry.Builder updatedBuilder = factory.updateBatchEntryBuilder(builder, operation, clientState);
            // Then
            assertThat(updatedBuilder).isSameAs(builder);
            assertEntry(updatedBuilder.build(), MODIFY, TABLE, true);
        }
    }

    @Test
    public void testUpdateBatchEntryBuilderWithOperationOnUnknownKeyspace()
    {
        // Given
        String operation = "INSERT INTO ks.tbl (k, v) VALUES (1, 2)";
        AuditEntry.Builder builder = factory.createBatchEntryBuilder();
        // When
        // Then
        assertThatExceptionOfType(CassandraAuditException.class)
        .isThrownBy(() -> factory.updateBatchEntryBuilder(builder, operation, clientState))
        .withMessage("Failed to parse and prepare BatchStatement when mapping single query for audit")
        .withCauseInstanceOf(InvalidRequestException.class);
        assertEntry(builder.build(), CAS, ROOT, true);
    }

    private AuditEntry createEntryForRawStatement(CQLStatement.Raw statement)
    {
        try (MockedStatic<QueryProcessor> queryProcessor = mockStatic(QueryProcessor.class))
        {
            queryProcessor.when(() -> QueryProcessor.getStatement(anyString(), any(ClientState.class)))
                          .thenThrow(new InvalidRequestException("Statement can't be prepared"));
            queryProcessor.when(() -> QueryProcessor.parseStatement(anyString())).thenReturn(statement);

            return factory.createEntryBuilder("operation", clientState).build();
        }
    }

    private static void givenStatementIsRejectedAtPrepare(MockedStatic<QueryProcessor> queryProcessor)
    {
        queryProcessor.when(() -> QueryProcessor.getStatement(anyString(), any(ClientState.class)))
                      .thenThrow(new InvalidRequestException("Statement can't be prepared"));
        queryProcessor.when(() -> QueryProcessor.parseStatement(anyString())).thenCallRealMethod();
    }

    private static void givenViewExistsInSchema(MockedStatic<View> view)
    {
        TableMetadata baseTable = TableMetadata.builder("ks", "tbl")
                                               .addPartitionKeyColumn("k", Int32Type.instance)
                                               .build();
        view.when(() -> View.findBaseTable("ks", "mv")).thenReturn(TableMetadataRef.forOfflineTools(baseTable));
    }

    private static ModificationStatement mockModificationStatement(boolean hasConditions)
    {
        ModificationStatement statement = mock(ModificationStatement.class);
        when(statement.hasConditions()).thenReturn(hasConditions);
        when(statement.keyspace()).thenReturn("ks");
        when(statement.table()).thenReturn("tbl");
        return statement;
    }

    private static void assertEntry(AuditEntry entry, Set<Permission> expectedPermissions, String expectedResource, boolean expectedKnownOperation)
    {
        assertThat(entry.getPermissions()).isEqualTo(expectedPermissions);
        assertThat(entry.getResource().getName()).isEqualTo(expectedResource);
        assertThat(entry.hasKnownOperation()).isEqualTo(expectedKnownOperation);
    }
}
