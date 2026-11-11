/*
 * Copyright 2020 Telefonaktiebolaget LM Ericsson
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
package com.ericsson.bss.cassandra.ecaudit.filter.role;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;
import java.util.concurrent.atomic.AtomicReference;
import java.util.function.Supplier;

import com.google.common.collect.ImmutableList;
import com.google.common.collect.Sets;

import org.junit.AfterClass;
import org.junit.BeforeClass;
import org.junit.Test;
import org.junit.runner.RunWith;

import com.ericsson.bss.cassandra.ecaudit.auth.AuditAuthorizer;
import com.ericsson.bss.cassandra.ecaudit.test.mode.ClientInitializer;

import junitparams.JUnitParamsRunner;
import junitparams.Parameters;

import org.apache.cassandra.auth.AuthenticatedUser;
import org.apache.cassandra.auth.DataResource;
import org.apache.cassandra.auth.IAuthorizer;
import org.apache.cassandra.auth.IResource;
import org.apache.cassandra.auth.Permission;
import org.apache.cassandra.config.DatabaseDescriptor;
import org.apache.cassandra.db.SystemKeyspace;
import org.apache.cassandra.schema.SchemaConstants;

import static java.util.Arrays.asList;
import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

@RunWith(JUnitParamsRunner.class)
public class TestAuditFilterAuthorizer
{
    private static final String AUTH_USER = "auth_user";
    private static final String UNAUTH_USER = "unauth_user";
    private static final IResource RESOURCE_DATA = DataResource.fromName("data");
    private static final IResource RESOURCE_KEYSPACE = DataResource.fromName("data/ks");
    private static final IResource RESOURCE_TABLE = DataResource.fromName("data/ks/tbl");
    private static final AuditFilterAuthorizer AUTHORIZER = new AuditFilterAuthorizer();

    // From SchemaKeyspace
    private static final ImmutableList<String> ALL_SCHEMA_TABLES = ImmutableList.of("columns", "dropped_columns", "triggers", "types", "functions", "aggregates", "indexes", "tables", "views", "keyspaces");
    private static final ImmutableList<String> ALL_VIRTUAL_SCHEMA_TABLES = ImmutableList.of("columns", "tables", "keyspaces");

    @BeforeClass
    public static void beforeAll()
    {
        ClientInitializer.beforeClass();

        AuthenticatedUser user = new AuthenticatedUser(AUTH_USER);
        IAuthorizer authorizerMock = mock(IAuthorizer.class);
        when(authorizerMock.authorize(user, RESOURCE_TABLE)).thenReturn(Sets.newHashSet(Permission.SELECT, Permission.MODIFY));
        when(authorizerMock.authorize(user, RESOURCE_KEYSPACE)).thenReturn(Sets.newHashSet(Permission.CREATE));
        AUTHORIZER.setAuthorizer(authorizerMock);
    }

    @AfterClass
    public static void afterAll()
    {
        ClientInitializer.afterClass();
    }

    @Test
    public void testGetAuthorizer()
    {
        assertThat(AUTHORIZER.getAuthorizer())
            .isInstanceOf(IAuthorizer.class)
            .isNotInstanceOf(AuditAuthorizer.class);
    }

    @Test
    public void testGetAuthorizerResolvesFromDatabaseDescriptorOnce()
    {
        IAuthorizer authorizer = mock(IAuthorizer.class);
        AuditFilterAuthorizer filterAuthorizer = new AuditFilterAuthorizer();

        IAuthorizer first = withDatabaseDescriptorAuthorizer(authorizer, filterAuthorizer::getAuthorizer);
        IAuthorizer second = withDatabaseDescriptorAuthorizer(mock(IAuthorizer.class), filterAuthorizer::getAuthorizer);

        assertThat(first).isSameAs(authorizer);
        assertThat(second).isSameAs(authorizer);
    }

    @Test
    public void testGetAuthorizerUnwrapsAuditAuthorizer()
    {
        IAuthorizer wrappedAuthorizer = mock(IAuthorizer.class);
        AuditAuthorizer auditAuthorizer = mock(AuditAuthorizer.class);
        when(auditAuthorizer.getWrappedAuthorizer()).thenReturn(wrappedAuthorizer);
        AuditFilterAuthorizer filterAuthorizer = new AuditFilterAuthorizer();

        IAuthorizer resolved = withDatabaseDescriptorAuthorizer(auditAuthorizer, filterAuthorizer::getAuthorizer);

        assertThat(resolved).isSameAs(wrappedAuthorizer);
    }

    @Test
    public void testOperationAuthorizationResolvesWrappedAuthorizerLazily()
    {
        AuthenticatedUser user = new AuthenticatedUser(AUTH_USER);
        IAuthorizer wrappedAuthorizer = mock(IAuthorizer.class);
        when(wrappedAuthorizer.authorize(user, RESOURCE_TABLE)).thenReturn(Sets.newHashSet(Permission.SELECT));
        AuditAuthorizer auditAuthorizer = mock(AuditAuthorizer.class);
        when(auditAuthorizer.getWrappedAuthorizer()).thenReturn(wrappedAuthorizer);
        AuditFilterAuthorizer filterAuthorizer = new AuditFilterAuthorizer();

        boolean selectAuthorized = withDatabaseDescriptorAuthorizer(auditAuthorizer,
            () -> filterAuthorizer.isOperationAuthorizedForUser(Permission.SELECT, AUTH_USER, asList(RESOURCE_TABLE)));
        boolean alterAuthorized = filterAuthorizer.isOperationAuthorizedForUser(Permission.ALTER, AUTH_USER, asList(RESOURCE_TABLE));

        assertThat(selectAuthorized).isTrue();
        assertThat(alterAuthorized).isFalse();
        verify(auditAuthorizer, never()).authorize(any(), any());
    }

    @Test
    public void testSystemResourceSkipsAuthorizerLookup()
    {
        IAuthorizer authorizer = mock(IAuthorizer.class);
        AuditFilterAuthorizer filterAuthorizer = new AuditFilterAuthorizer();
        filterAuthorizer.setAuthorizer(authorizer);

        List<DataResource> resources = toDataResources(SchemaConstants.SYSTEM_KEYSPACE_NAME, SystemKeyspace.LOCAL);

        assertThat(filterAuthorizer.isOperationAuthorizedForUser(Permission.SELECT, AUTH_USER, resources)).isTrue();
        verify(authorizer, never()).authorize(any(), any());
    }

    @Test
    public void testEmptyResourceChainIsNotAuthorized()
    {
        assertThat(AUTHORIZER.isOperationAuthorizedForUser(Permission.SELECT, AUTH_USER, Collections.emptyList())).isFalse();
        assertThat(AUTHORIZER.isOperationAuthorizedForUser(Permission.MODIFY, AUTH_USER, Collections.emptyList())).isFalse();
    }

    @Test
    public void testConcurrentResolutionKeepsAuthorizerSetWhileWaiting() throws Exception
    {
        IAuthorizer descriptorAuthorizer = mock(IAuthorizer.class);
        IAuthorizer injectedAuthorizer = mock(IAuthorizer.class);
        AuditFilterAuthorizer filterAuthorizer = new AuditFilterAuthorizer();
        AtomicReference<IAuthorizer> resolved = new AtomicReference<>();
        Thread resolver = new Thread(() -> resolved.set(filterAuthorizer.getAuthorizer()));

        IAuthorizer original = DatabaseDescriptor.getAuthorizer();
        DatabaseDescriptor.setAuthorizer(descriptorAuthorizer);
        try
        {
            synchronized (filterAuthorizer)
            {
                resolver.start();
                while (resolver.getState() != Thread.State.BLOCKED)
                {
                    Thread.sleep(1);
                }
                filterAuthorizer.setAuthorizer(injectedAuthorizer);
            }
            resolver.join(10_000);
        }
        finally
        {
            DatabaseDescriptor.setAuthorizer(original);
        }

        assertThat(resolver.isAlive()).isFalse();
        assertThat(resolved.get()).isSameAs(injectedAuthorizer);
    }

    @SuppressWarnings("unused")
    private Object[] parametersForTestOperationAuthorization()
    {
        return new Object[]{
            new Object[]{ Permission.SELECT, AUTH_USER, asList(RESOURCE_TABLE), true },
            new Object[]{ Permission.MODIFY, AUTH_USER, asList(RESOURCE_TABLE), true },
            new Object[]{ Permission.ALTER, AUTH_USER, asList(RESOURCE_TABLE), false },
            new Object[]{ Permission.SELECT, AUTH_USER, asList(RESOURCE_KEYSPACE), false },
            new Object[]{ Permission.CREATE, AUTH_USER, asList(RESOURCE_KEYSPACE), true },
            new Object[]{ Permission.MODIFY, AUTH_USER, asList(RESOURCE_DATA), false },
            new Object[]{ Permission.SELECT, UNAUTH_USER, asList(RESOURCE_TABLE), false },
            new Object[]{ Permission.CREATE, AUTH_USER, asList(RESOURCE_DATA, RESOURCE_KEYSPACE, RESOURCE_TABLE), true },
            new Object[]{ Permission.DESCRIBE, AUTH_USER, asList(RESOURCE_DATA, RESOURCE_KEYSPACE, RESOURCE_TABLE), false },
        };
    }

    @Test
    @Parameters
    public void testOperationAuthorization(Permission operation, String user, List<IResource> resources, boolean expectedAuthorized)
    {
        assertThat(AUTHORIZER.isOperationAuthorizedForUser(operation, user, resources)).isEqualTo(expectedAuthorized);
    }

    @SuppressWarnings("unused")
    private Object[] parametersForTestSystemOperationAuthorization()
    {
        List<Object[]> objects = new ArrayList<>();
        objects.add(new Object[] {toDataResources(SchemaConstants.SYSTEM_KEYSPACE_NAME, SystemKeyspace.LOCAL)});
        objects.add(new Object[] {toDataResources(SchemaConstants.SYSTEM_KEYSPACE_NAME, SystemKeyspace.PEERS_V2)});
        objects.add(new Object[] {toDataResources(SchemaConstants.SYSTEM_KEYSPACE_NAME, "peers")});

        for (String table : ALL_SCHEMA_TABLES)
        {
            objects.add(new Object[] {toDataResources(SchemaConstants.SCHEMA_KEYSPACE_NAME, table)});
        }

        for (String table : ALL_VIRTUAL_SCHEMA_TABLES)
        {
            objects.add(new Object[] {toDataResources(SchemaConstants.VIRTUAL_SCHEMA, table)});
        }

        return objects.toArray();
    }

    @Test
    @Parameters
    public void testSystemOperationAuthorization(List<IResource> resources)
    {
        // Select on system keyspaces are ok
        assertThat(AUTHORIZER.isOperationAuthorizedForUser(Permission.SELECT, AUTH_USER, resources)).isEqualTo(true);

        List<Permission> NOT_OK = new ArrayList<>(Permission.ALL);
        NOT_OK.remove(Permission.SELECT);
        for (Permission permission : NOT_OK)
        {
            assertThat(AUTHORIZER.isOperationAuthorizedForUser(permission, AUTH_USER, resources)).isEqualTo(false);
        }
    }

    private static <T> T withDatabaseDescriptorAuthorizer(IAuthorizer authorizer, Supplier<T> action)
    {
        IAuthorizer original = DatabaseDescriptor.getAuthorizer();
        DatabaseDescriptor.setAuthorizer(authorizer);
        try
        {
            return action.get();
        }
        finally
        {
            DatabaseDescriptor.setAuthorizer(original);
        }
    }

    private static List<DataResource> toDataResources(String keyspace, String table)
    {
        return Arrays.asList(
            DataResource.fromName(String.format("data/%s/%s", keyspace, table)),
            DataResource.fromName(String.format("data/%s", keyspace)),
            DataResource.fromName("data")
        );
    }
}
