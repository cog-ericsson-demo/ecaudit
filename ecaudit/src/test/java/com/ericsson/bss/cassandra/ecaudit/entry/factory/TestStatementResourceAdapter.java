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

import java.util.Arrays;
import java.util.Collections;
import java.util.List;

import com.google.common.collect.ImmutableSet;
import org.apache.commons.lang3.reflect.FieldUtils;
import org.assertj.core.api.ThrowableAssert.ThrowingCallable;
import org.junit.AfterClass;
import org.junit.Before;
import org.junit.BeforeClass;
import org.junit.Test;

import com.ericsson.bss.cassandra.ecaudit.facade.CassandraAuditException;
import com.ericsson.bss.cassandra.ecaudit.test.mode.ClientInitializer;
import org.apache.cassandra.auth.DataResource;
import org.apache.cassandra.auth.FunctionResource;
import org.apache.cassandra.auth.IResource;
import org.apache.cassandra.auth.Permission;
import org.apache.cassandra.auth.RoleResource;
import org.apache.cassandra.cql3.CQL3Type;
import org.apache.cassandra.cql3.ColumnIdentifier;
import org.apache.cassandra.cql3.QualifiedName;
import org.apache.cassandra.cql3.RoleName;
import org.apache.cassandra.cql3.WhereClause;
import org.apache.cassandra.cql3.functions.FunctionName;
import org.apache.cassandra.cql3.statements.AlterRoleStatement;
import org.apache.cassandra.cql3.statements.AuthenticationStatement;
import org.apache.cassandra.cql3.statements.CreateRoleStatement;
import org.apache.cassandra.cql3.statements.DropRoleStatement;
import org.apache.cassandra.cql3.statements.GrantPermissionsStatement;
import org.apache.cassandra.cql3.statements.GrantRoleStatement;
import org.apache.cassandra.cql3.statements.ListPermissionsStatement;
import org.apache.cassandra.cql3.statements.ListRolesStatement;
import org.apache.cassandra.cql3.statements.RevokePermissionsStatement;
import org.apache.cassandra.cql3.statements.RevokeRoleStatement;
import org.apache.cassandra.cql3.statements.UseStatement;
import org.apache.cassandra.cql3.statements.schema.AlterViewStatement;
import org.apache.cassandra.cql3.statements.schema.CreateAggregateStatement;
import org.apache.cassandra.cql3.statements.schema.CreateFunctionStatement;
import org.apache.cassandra.cql3.statements.schema.CreateIndexStatement;
import org.apache.cassandra.cql3.statements.schema.CreateViewStatement;
import org.apache.cassandra.cql3.statements.schema.DropAggregateStatement;
import org.apache.cassandra.cql3.statements.schema.DropFunctionStatement;
import org.apache.cassandra.cql3.statements.schema.DropIndexStatement;
import org.apache.cassandra.cql3.statements.schema.DropViewStatement;
import org.apache.cassandra.cql3.statements.schema.IndexTarget;
import org.apache.cassandra.db.marshal.Int32Type;
import org.apache.cassandra.db.marshal.UTF8Type;
import org.apache.cassandra.exceptions.InvalidRequestException;
import org.apache.cassandra.schema.IndexMetadata;
import org.apache.cassandra.schema.Indexes;
import org.apache.cassandra.schema.KeyspaceMetadata;
import org.apache.cassandra.schema.KeyspaceParams;
import org.apache.cassandra.schema.Schema;
import org.apache.cassandra.schema.TableMetadata;
import org.apache.cassandra.schema.Tables;
import org.apache.cassandra.schema.Types;
import org.apache.cassandra.schema.UserFunctions;
import org.apache.cassandra.schema.ViewMetadata;
import org.apache.cassandra.schema.Views;
import org.mockito.MockedStatic;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatExceptionOfType;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyBoolean;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.mockStatic;

public class TestStatementResourceAdapter
{
    private static final String KEYSPACE = "sra_ks";
    private static final String TABLE = "sra_tbl";
    private static final String VIEW = "sra_view";
    private static final String INDEX = "sra_idx";
    private static final String UNKNOWN_KEYSPACE = "sra_unknown_ks";
    private static final String UNKNOWN_VIEW = "sra_unknown_view";
    private static final String UNKNOWN_INDEX = "sra_unknown_idx";
    private static final String FUNCTION = "sra_func";
    private static final String AGGREGATE = "sra_aggr";

    private static final String FAILED_TO_RESOLVE_RESOURCE = "Failed to resolve resource";
    private static final String FAILED_TO_RESOLVE_BASE_TABLE_OF_VIEW = "Failed to resolve base table of view";
    private static final String FAILED_TO_RESOLVE_BASE_TABLE_OF_FUNCTION = "Failed to resolve base table of function";

    private static final List<CQL3Type.Raw> RAW_ARGUMENTS = Arrays.asList(CQL3Type.Raw.from(CQL3Type.Native.TEXT),
                                                                          CQL3Type.Raw.from(CQL3Type.Native.INT));

    private StatementResourceAdapter adapter;

    @BeforeClass
    public static void beforeClass()
    {
        ClientInitializer.beforeClass();
        Schema.instance.transform(keyspaces -> keyspaces.withAddedOrUpdated(createKeyspaceWithIndexedTableAndView()));
    }

    @Before
    public void before()
    {
        adapter = new StatementResourceAdapter();
    }

    @AfterClass
    public static void afterClass()
    {
        Schema.instance.transform(keyspaces -> keyspaces.without(KEYSPACE));
        ClientInitializer.afterClass();
    }

    @Test
    public void testCreateRoleResolvesRole()
    {
        CreateRoleStatement statement = new CreateRoleStatement(roleName("alice"), null, null, null, false);

        assertThat(adapter.resolveRoleResource(statement)).isEqualTo(RoleResource.role("alice"));
    }

    @Test
    public void testAlterRoleResolvesRole()
    {
        AlterRoleStatement statement = new AlterRoleStatement(roleName("alice"), null);

        assertThat(adapter.resolveRoleResource(statement)).isEqualTo(RoleResource.role("alice"));
    }

    @Test
    public void testDropRoleResolvesRole()
    {
        DropRoleStatement statement = new DropRoleStatement(roleName("alice"), true);

        assertThat(adapter.resolveRoleResource(statement)).isEqualTo(RoleResource.role("alice"));
    }

    @Test
    public void testGrantRoleResolvesGrantedRoleAndNotGrantee()
    {
        GrantRoleStatement statement = new GrantRoleStatement(roleName("granted"), roleName("grantee"));

        assertThat(adapter.resolveRoleResource(statement)).isEqualTo(RoleResource.role("granted"));
    }

    @Test
    public void testRevokeRoleResolvesRevokedRoleAndNotGrantee()
    {
        RevokeRoleStatement statement = new RevokeRoleStatement(roleName("revoked"), roleName("grantee"));

        assertThat(adapter.resolveRoleResource(statement)).isEqualTo(RoleResource.role("revoked"));
    }

    @Test
    public void testAuthenticationStatementWithoutRoleFieldIsRejected()
    {
        AuthenticationStatement statement = mock(AuthenticationStatement.class);

        assertThatExceptionOfType(IllegalArgumentException.class)
        .isThrownBy(() -> adapter.resolveRoleResource(statement))
        .withMessageContaining("role");
    }

    @Test
    public void testRoleResolutionFailureIsWrapped()
    {
        DropRoleStatement statement = new DropRoleStatement(roleName("alice"), false);

        assertFieldAccessFailureIsWrapped(() -> adapter.resolveRoleResource(statement), FAILED_TO_RESOLVE_RESOURCE);
    }

    @Test
    public void testGrantPermissionsResolvesManagedResource()
    {
        IResource resource = DataResource.table(KEYSPACE, TABLE);
        GrantPermissionsStatement statement = new GrantPermissionsStatement(ImmutableSet.of(Permission.SELECT), resource, roleName("alice"));

        assertThat(adapter.resolveManagedResource(statement)).isSameAs(resource);
    }

    @Test
    public void testRevokePermissionsResolvesManagedResource()
    {
        IResource resource = RoleResource.role("bob");
        RevokePermissionsStatement statement = new RevokePermissionsStatement(ImmutableSet.of(Permission.ALTER), resource, roleName("alice"));

        assertThat(adapter.resolveManagedResource(statement)).isSameAs(resource);
    }

    @Test
    public void testManagedResourceResolutionFailureIsWrapped()
    {
        GrantPermissionsStatement statement = new GrantPermissionsStatement(ImmutableSet.of(Permission.SELECT), DataResource.root(), roleName("alice"));

        assertFieldAccessFailureIsWrapped(() -> adapter.resolveManagedResource(statement), FAILED_TO_RESOLVE_RESOURCE);
    }

    @Test
    public void testListRolesOfRoleResolvesGrantee()
    {
        ListRolesStatement statement = new ListRolesStatement(roleName("alice"), false);

        assertThat(adapter.resolveGranteeResource(statement)).isEqualTo(RoleResource.role("alice"));
    }

    @Test
    public void testListRolesWithoutGranteeResolvesRootRole()
    {
        ListRolesStatement statement = new ListRolesStatement();

        assertThat(adapter.resolveGranteeResource(statement)).isEqualTo(RoleResource.root());
    }

    @Test
    public void testListPermissionsOfRoleResolvesGrantee()
    {
        ListPermissionsStatement statement = new ListPermissionsStatement(Permission.ALL, DataResource.root(), roleName("alice"), false);

        assertThat(adapter.resolveGranteeResource(statement)).isEqualTo(RoleResource.role("alice"));
    }

    @Test
    public void testListPermissionsWithoutGranteeResolvesRootRole()
    {
        ListPermissionsStatement statement = new ListPermissionsStatement(Permission.ALL, null, new RoleName(), false);

        assertThat(adapter.resolveGranteeResource(statement)).isEqualTo(RoleResource.root());
    }

    @Test
    public void testGranteeResolutionFailureIsWrapped()
    {
        ListRolesStatement statement = new ListRolesStatement();

        assertFieldAccessFailureIsWrapped(() -> adapter.resolveGranteeResource(statement), FAILED_TO_RESOLVE_RESOURCE);
    }

    @Test
    public void testUseResolvesKeyspace()
    {
        UseStatement statement = new UseStatement(KEYSPACE);

        assertThat(adapter.resolveKeyspaceResource(statement)).isEqualTo(DataResource.keyspace(KEYSPACE));
    }

    @Test
    public void testKeyspaceResolutionFailureIsWrapped()
    {
        UseStatement statement = new UseStatement(KEYSPACE);

        assertFieldAccessFailureIsWrapped(() -> adapter.resolveKeyspaceResource(statement), FAILED_TO_RESOLVE_RESOURCE);
    }

    @Test
    public void testCreateViewResolvesBaseTable()
    {
        CreateViewStatement statement = createViewStatement();

        assertThat(adapter.resolveBaseTableResource(statement)).isEqualTo(DataResource.table(KEYSPACE, TABLE));
    }

    @Test
    public void testCreateViewResolutionFailureIsWrappedWithViewName()
    {
        CreateViewStatement statement = createViewStatement();

        assertFieldAccessFailureIsWrapped(() -> adapter.resolveBaseTableResource(statement),
                                          FAILED_TO_RESOLVE_BASE_TABLE_OF_VIEW + " " + KEYSPACE + "." + VIEW);
    }

    @Test
    public void testRawCreateViewResolvesBaseTable()
    {
        CreateViewStatement.Raw statement = rawCreateViewStatement();

        assertThat(adapter.resolveBaseTableResource(statement)).isEqualTo(DataResource.table(KEYSPACE, TABLE));
    }

    @Test
    public void testRawCreateViewResolutionFailureIsWrapped()
    {
        CreateViewStatement.Raw statement = rawCreateViewStatement();

        assertFieldAccessFailureIsWrapped(() -> adapter.resolveBaseTableResource(statement), FAILED_TO_RESOLVE_BASE_TABLE_OF_VIEW);
    }

    @Test
    public void testAlterViewResolvesBaseTable()
    {
        AlterViewStatement statement = new AlterViewStatement(KEYSPACE, VIEW, null, false);

        assertThat(adapter.resolveBaseTableResource(statement)).isEqualTo(DataResource.table(KEYSPACE, TABLE));
    }

    @Test
    public void testAlterUnknownViewResolvesKeyspace()
    {
        AlterViewStatement statement = new AlterViewStatement(KEYSPACE, UNKNOWN_VIEW, null, false);

        assertThat(adapter.resolveBaseTableResource(statement)).isEqualTo(DataResource.keyspace(KEYSPACE));
    }

    @Test
    public void testAlterViewInUnknownKeyspaceResolvesKeyspace()
    {
        AlterViewStatement statement = new AlterViewStatement(UNKNOWN_KEYSPACE, VIEW, null, false);

        assertThat(adapter.resolveBaseTableResource(statement)).isEqualTo(DataResource.keyspace(UNKNOWN_KEYSPACE));
    }

    @Test
    public void testRawAlterViewResolvesBaseTable()
    {
        AlterViewStatement.Raw statement = new AlterViewStatement.Raw(new QualifiedName(KEYSPACE, VIEW), null, false);

        assertThat(adapter.resolveBaseTableResource(statement)).isEqualTo(DataResource.table(KEYSPACE, TABLE));
    }

    /**
     * Documents current behavior: when the view is unknown, the fallback resource is built from the view name and not
     * from the keyspace name as done for the prepared statement.
     */
    @Test
    public void testRawAlterUnknownViewResolvesKeyspaceResourceFromViewName()
    {
        AlterViewStatement.Raw statement = new AlterViewStatement.Raw(new QualifiedName(KEYSPACE, UNKNOWN_VIEW), null, false);

        assertThat(adapter.resolveBaseTableResource(statement)).isEqualTo(DataResource.keyspace(UNKNOWN_VIEW));
    }

    @Test
    public void testRawAlterViewResolutionFailureIsWrapped()
    {
        AlterViewStatement.Raw statement = new AlterViewStatement.Raw(new QualifiedName(KEYSPACE, VIEW), null, false);

        assertFieldAccessFailureIsWrapped(() -> adapter.resolveBaseTableResource(statement), FAILED_TO_RESOLVE_BASE_TABLE_OF_VIEW);
    }

    @Test
    public void testDropViewResolvesBaseTable()
    {
        DropViewStatement statement = new DropViewStatement(KEYSPACE, VIEW, false);

        assertThat(adapter.resolveBaseTableResource(statement)).isEqualTo(DataResource.table(KEYSPACE, TABLE));
    }

    @Test
    public void testDropUnknownViewResolvesKeyspace()
    {
        DropViewStatement statement = new DropViewStatement(KEYSPACE, UNKNOWN_VIEW, true);

        assertThat(adapter.resolveBaseTableResource(statement)).isEqualTo(DataResource.keyspace(KEYSPACE));
    }

    @Test
    public void testRawDropViewResolvesBaseTable()
    {
        DropViewStatement.Raw statement = new DropViewStatement.Raw(new QualifiedName(KEYSPACE, VIEW), false);

        assertThat(adapter.resolveBaseTableResource(statement)).isEqualTo(DataResource.table(KEYSPACE, TABLE));
    }

    /**
     * Documents current behavior: when the view is unknown, the fallback resource is built from the view name and not
     * from the keyspace name as done for the prepared statement.
     */
    @Test
    public void testRawDropUnknownViewResolvesKeyspaceResourceFromViewName()
    {
        DropViewStatement.Raw statement = new DropViewStatement.Raw(new QualifiedName(KEYSPACE, UNKNOWN_VIEW), true);

        assertThat(adapter.resolveBaseTableResource(statement)).isEqualTo(DataResource.keyspace(UNKNOWN_VIEW));
    }

    @Test
    public void testRawDropViewResolutionFailureIsWrapped()
    {
        DropViewStatement.Raw statement = new DropViewStatement.Raw(new QualifiedName(KEYSPACE, VIEW), false);

        assertFieldAccessFailureIsWrapped(() -> adapter.resolveBaseTableResource(statement), FAILED_TO_RESOLVE_BASE_TABLE_OF_VIEW);
    }

    @Test
    public void testCreateIndexResolvesBaseTable()
    {
        CreateIndexStatement statement = new CreateIndexStatement(KEYSPACE, TABLE, INDEX, Collections.emptyList(), null, false);

        assertThat(adapter.resolveBaseTableResource(statement)).isEqualTo(DataResource.table(KEYSPACE, TABLE));
    }

    @Test
    public void testCreateIndexResolutionFailureIsWrapped()
    {
        CreateIndexStatement statement = new CreateIndexStatement(KEYSPACE, TABLE, INDEX, Collections.emptyList(), null, false);

        assertFieldAccessFailureIsWrapped(() -> adapter.resolveBaseTableResource(statement), FAILED_TO_RESOLVE_RESOURCE);
    }

    @Test
    public void testRawCreateIndexResolvesBaseTable()
    {
        CreateIndexStatement.Raw statement = rawCreateIndexStatement();

        assertThat(adapter.resolveBaseTableResource(statement)).isEqualTo(DataResource.table(KEYSPACE, TABLE));
    }

    @Test
    public void testRawCreateIndexResolutionFailureIsWrapped()
    {
        CreateIndexStatement.Raw statement = rawCreateIndexStatement();

        assertFieldAccessFailureIsWrapped(() -> adapter.resolveBaseTableResource(statement), FAILED_TO_RESOLVE_RESOURCE);
    }

    @Test
    public void testDropIndexResolvesIndexedTable()
    {
        DropIndexStatement statement = new DropIndexStatement(KEYSPACE, INDEX, false);

        assertThat(adapter.resolveBaseTableResource(statement)).isEqualTo(DataResource.table(KEYSPACE, TABLE));
    }

    @Test
    public void testDropUnknownIndexResolvesKeyspace()
    {
        DropIndexStatement statement = new DropIndexStatement(KEYSPACE, UNKNOWN_INDEX, true);

        assertThat(adapter.resolveBaseTableResource(statement)).isEqualTo(DataResource.keyspace(KEYSPACE));
    }

    @Test
    public void testDropIndexInUnknownKeyspaceResolvesKeyspace()
    {
        DropIndexStatement statement = new DropIndexStatement(UNKNOWN_KEYSPACE, INDEX, true);

        assertThat(adapter.resolveBaseTableResource(statement)).isEqualTo(DataResource.keyspace(UNKNOWN_KEYSPACE));
    }

    @Test
    public void testRawDropIndexResolvesIndexedTable()
    {
        DropIndexStatement.Raw statement = new DropIndexStatement.Raw(new QualifiedName(KEYSPACE, INDEX), false);

        assertThat(adapter.resolveBaseTableResource(statement)).isEqualTo(DataResource.table(KEYSPACE, TABLE));
    }

    @Test
    public void testRawDropUnknownIndexResolvesKeyspace()
    {
        DropIndexStatement.Raw statement = new DropIndexStatement.Raw(new QualifiedName(KEYSPACE, UNKNOWN_INDEX), true);

        assertThat(adapter.resolveBaseTableResource(statement)).isEqualTo(DataResource.keyspace(KEYSPACE));
    }

    @Test
    public void testRawDropIndexInUnknownKeyspaceResolvesKeyspace()
    {
        DropIndexStatement.Raw statement = new DropIndexStatement.Raw(new QualifiedName(UNKNOWN_KEYSPACE, INDEX), true);

        assertThat(adapter.resolveBaseTableResource(statement)).isEqualTo(DataResource.keyspace(UNKNOWN_KEYSPACE));
    }

    @Test
    public void testRawDropIndexResolutionFailureIsWrapped()
    {
        DropIndexStatement.Raw statement = new DropIndexStatement.Raw(new QualifiedName(KEYSPACE, INDEX), false);

        assertFieldAccessFailureIsWrapped(() -> adapter.resolveBaseTableResource(statement), FAILED_TO_RESOLVE_RESOURCE);
    }

    @Test
    public void testCreateFunctionResolvesFunctionKeyspace()
    {
        CreateFunctionStatement statement = new CreateFunctionStatement(KEYSPACE, FUNCTION, Collections.emptyList(), Collections.emptyList(), null, false, "java", "return 0;", false, false);

        assertThat(adapter.resolveFunctionKeyspaceResource(statement)).isEqualTo(FunctionResource.keyspace(KEYSPACE));
    }

    @Test
    public void testRawCreateFunctionResolvesFunctionKeyspace()
    {
        CreateFunctionStatement.Raw statement = rawCreateFunctionStatement();

        assertThat(adapter.resolveFunctionKeyspaceResource(statement)).isEqualTo(FunctionResource.keyspace(KEYSPACE));
    }

    @Test
    public void testRawCreateFunctionResolutionFailureIsWrapped()
    {
        CreateFunctionStatement.Raw statement = rawCreateFunctionStatement();

        assertFieldAccessFailureIsWrapped(() -> adapter.resolveFunctionKeyspaceResource(statement), FAILED_TO_RESOLVE_BASE_TABLE_OF_FUNCTION);
    }

    @Test
    public void testDropFunctionResolvesFunctionWithArgumentTypes()
    {
        DropFunctionStatement statement = new DropFunctionStatement(KEYSPACE, FUNCTION, RAW_ARGUMENTS, true, false);

        assertThat(adapter.resolveFunctionResource(statement)).isEqualTo(functionResource(FUNCTION));
    }

    @Test
    public void testDropFunctionWithoutArgumentsResolvesFunction()
    {
        DropFunctionStatement statement = new DropFunctionStatement(KEYSPACE, FUNCTION, Collections.emptyList(), false, false);

        assertThat(adapter.resolveFunctionResource(statement)).isEqualTo(FunctionResource.function(KEYSPACE, FUNCTION, Collections.emptyList()));
    }

    @Test
    public void testDropFunctionResolutionFailureIsWrappedWithFunctionName()
    {
        DropFunctionStatement statement = new DropFunctionStatement(KEYSPACE, FUNCTION, RAW_ARGUMENTS, true, false);

        assertFieldAccessFailureIsWrapped(() -> adapter.resolveFunctionResource(statement),
                                          FAILED_TO_RESOLVE_BASE_TABLE_OF_FUNCTION + " " + KEYSPACE + "." + FUNCTION);
    }

    @Test
    public void testRawDropFunctionResolvesFunctionWithArgumentTypes()
    {
        DropFunctionStatement.Raw statement = new DropFunctionStatement.Raw(new FunctionName(KEYSPACE, FUNCTION), RAW_ARGUMENTS, true, false);

        assertThat(adapter.resolveFunctionResource(statement)).isEqualTo(functionResource(FUNCTION));
    }

    @Test
    public void testRawDropFunctionWithoutKeyspaceIsRejected()
    {
        DropFunctionStatement.Raw statement = new DropFunctionStatement.Raw(new FunctionName(null, FUNCTION), RAW_ARGUMENTS, true, false);

        assertThatExceptionOfType(InvalidRequestException.class)
        .isThrownBy(() -> adapter.resolveFunctionResource(statement));
    }

    @Test
    public void testRawDropFunctionResolutionFailureIsWrapped()
    {
        DropFunctionStatement.Raw statement = new DropFunctionStatement.Raw(new FunctionName(KEYSPACE, FUNCTION), RAW_ARGUMENTS, true, false);

        assertFieldAccessFailureIsWrapped(() -> adapter.resolveFunctionResource(statement), FAILED_TO_RESOLVE_BASE_TABLE_OF_FUNCTION);
    }

    @Test
    public void testCreateAggregateResolvesFunctionKeyspace()
    {
        CreateAggregateStatement statement = new CreateAggregateStatement(KEYSPACE, AGGREGATE, Collections.emptyList(), null, null, null, null, false, false);

        assertThat(adapter.resolveAggregateKeyspaceResource(statement)).isEqualTo(FunctionResource.keyspace(KEYSPACE));
    }

    /**
     * Documents current behavior: the adapter reads a member called "name", but in Cassandra 5.0 the corresponding
     * member of {@link CreateAggregateStatement.Raw} is called "aggregateName".
     */
    @Test
    public void testRawCreateAggregateIsRejectedAsNameFieldIsMissing()
    {
        CreateAggregateStatement.Raw statement = rawCreateAggregateStatement();

        assertThatExceptionOfType(IllegalArgumentException.class)
        .isThrownBy(() -> adapter.resolveAggregateKeyspaceResource(statement))
        .withMessageContaining("name");
    }

    @Test
    public void testRawCreateAggregateResolutionFailureIsWrapped()
    {
        CreateAggregateStatement.Raw statement = rawCreateAggregateStatement();

        assertFieldAccessFailureIsWrapped(() -> adapter.resolveAggregateKeyspaceResource(statement), FAILED_TO_RESOLVE_BASE_TABLE_OF_FUNCTION);
    }

    @Test
    public void testDropAggregateResolvesFunctionWithArgumentTypes()
    {
        DropAggregateStatement statement = new DropAggregateStatement(KEYSPACE, AGGREGATE, RAW_ARGUMENTS, true, false);

        assertThat(adapter.resolveAggregateResource(statement)).isEqualTo(functionResource(AGGREGATE));
    }

    @Test
    public void testDropAggregateResolutionFailureIsWrappedWithAggregateName()
    {
        DropAggregateStatement statement = new DropAggregateStatement(KEYSPACE, AGGREGATE, RAW_ARGUMENTS, true, false);

        assertFieldAccessFailureIsWrapped(() -> adapter.resolveAggregateResource(statement),
                                          FAILED_TO_RESOLVE_BASE_TABLE_OF_FUNCTION + " " + KEYSPACE + "." + AGGREGATE);
    }

    @Test
    public void testRawDropAggregateResolvesFunctionWithArgumentTypes()
    {
        DropAggregateStatement.Raw statement = new DropAggregateStatement.Raw(new FunctionName(KEYSPACE, AGGREGATE), RAW_ARGUMENTS, true, false);

        assertThat(adapter.resolveAggregateResource(statement)).isEqualTo(functionResource(AGGREGATE));
    }

    @Test
    public void testRawDropAggregateWithoutKeyspaceIsRejected()
    {
        DropAggregateStatement.Raw statement = new DropAggregateStatement.Raw(new FunctionName(null, AGGREGATE), RAW_ARGUMENTS, true, false);

        assertThatExceptionOfType(InvalidRequestException.class)
        .isThrownBy(() -> adapter.resolveAggregateResource(statement));
    }

    @Test
    public void testRawDropAggregateResolutionFailureIsWrapped()
    {
        DropAggregateStatement.Raw statement = new DropAggregateStatement.Raw(new FunctionName(KEYSPACE, AGGREGATE), RAW_ARGUMENTS, true, false);

        assertFieldAccessFailureIsWrapped(() -> adapter.resolveAggregateResource(statement), FAILED_TO_RESOLVE_BASE_TABLE_OF_FUNCTION);
    }

    private static void assertFieldAccessFailureIsWrapped(ThrowingCallable resolveResource, String expectedMessage)
    {
        IllegalAccessException cause = new IllegalAccessException("Access denied by test");

        try (MockedStatic<FieldUtils> fieldUtils = mockStatic(FieldUtils.class))
        {
            fieldUtils.when(() -> FieldUtils.readField(any(Object.class), anyString(), anyBoolean())).thenThrow(cause);

            assertThatExceptionOfType(CassandraAuditException.class)
            .isThrownBy(resolveResource)
            .withMessage(expectedMessage)
            .withCause(cause);
        }
    }

    private static KeyspaceMetadata createKeyspaceWithIndexedTableAndView()
    {
        IndexTarget indexTarget = new IndexTarget(ColumnIdentifier.getInterned("val", false), IndexTarget.Type.VALUES);
        IndexMetadata index = IndexMetadata.fromIndexTargets(Collections.singletonList(indexTarget), INDEX, IndexMetadata.Kind.COMPOSITES, Collections.emptyMap());

        TableMetadata table = TableMetadata.builder(KEYSPACE, TABLE)
                                           .addPartitionKeyColumn("pk", UTF8Type.instance)
                                           .addRegularColumn("val", UTF8Type.instance)
                                           .indexes(Indexes.of(index))
                                           .build();

        TableMetadata viewTable = TableMetadata.builder(KEYSPACE, VIEW)
                                               .kind(TableMetadata.Kind.VIEW)
                                               .addPartitionKeyColumn("val", UTF8Type.instance)
                                               .addClusteringColumn("pk", UTF8Type.instance)
                                               .build();
        ViewMetadata view = new ViewMetadata(table.id, table.name, true, WhereClause.empty(), viewTable);

        return KeyspaceMetadata.create(KEYSPACE, KeyspaceParams.simple(1), Tables.of(table), Views.builder().put(view).build(), Types.none(), UserFunctions.none());
    }

    private static RoleName roleName(String name)
    {
        RoleName roleName = new RoleName();
        roleName.setName(name, true);
        return roleName;
    }

    private static FunctionResource functionResource(String name)
    {
        return FunctionResource.function(KEYSPACE, name, Arrays.asList(UTF8Type.instance, Int32Type.instance));
    }

    private static CreateViewStatement createViewStatement()
    {
        return new CreateViewStatement(KEYSPACE, TABLE, VIEW, Collections.emptyList(), Collections.emptyList(), Collections.emptyList(), WhereClause.empty(), null, null, false);
    }

    private static CreateViewStatement.Raw rawCreateViewStatement()
    {
        return new CreateViewStatement.Raw(new QualifiedName(KEYSPACE, TABLE), new QualifiedName(KEYSPACE, VIEW), Collections.emptyList(), WhereClause.empty(), false);
    }

    private static CreateIndexStatement.Raw rawCreateIndexStatement()
    {
        return new CreateIndexStatement.Raw(new QualifiedName(KEYSPACE, TABLE), new QualifiedName(KEYSPACE, INDEX), Collections.emptyList(), null, false);
    }

    private static CreateFunctionStatement.Raw rawCreateFunctionStatement()
    {
        return new CreateFunctionStatement.Raw(new FunctionName(KEYSPACE, FUNCTION), Collections.emptyList(), Collections.emptyList(), null, false, "java", "return 0;", false, false);
    }

    private static CreateAggregateStatement.Raw rawCreateAggregateStatement()
    {
        return new CreateAggregateStatement.Raw(new FunctionName(KEYSPACE, AGGREGATE), Collections.emptyList(), null, "sra_state", "sra_final", null, false, false);
    }
}
