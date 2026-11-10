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
package com.ericsson.bss.cassandra.ecaudit.auth;

import java.util.Map;
import java.util.Optional;
import java.util.Set;

import com.google.common.collect.ImmutableMap;
import com.google.common.collect.ImmutableSet;

import org.junit.After;
import org.junit.AfterClass;
import org.junit.Before;
import org.junit.BeforeClass;
import org.junit.Test;
import org.junit.runner.RunWith;

import com.ericsson.bss.cassandra.ecaudit.AuditAdapter;
import com.ericsson.bss.cassandra.ecaudit.test.mode.ClientInitializer;

import org.apache.cassandra.auth.AuthenticatedUser;
import org.apache.cassandra.auth.DataResource;
import org.apache.cassandra.auth.IAuthenticator;
import org.apache.cassandra.auth.IResource;
import org.apache.cassandra.auth.IRoleManager;
import org.apache.cassandra.auth.PasswordAuthenticator;
import org.apache.cassandra.auth.Role;
import org.apache.cassandra.auth.RoleOptions;
import org.apache.cassandra.auth.RoleResource;
import org.apache.cassandra.config.DatabaseDescriptor;
import org.apache.cassandra.exceptions.ConfigurationException;
import org.apache.cassandra.exceptions.InvalidRequestException;
import org.apache.cassandra.exceptions.UnauthorizedException;
import org.mockito.InOrder;
import org.mockito.Mock;
import org.mockito.junit.MockitoJUnitRunner;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatExceptionOfType;
import static org.mockito.ArgumentMatchers.anyBoolean;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.doReturn;
import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.inOrder;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoMoreInteractions;
import static org.mockito.Mockito.when;

@RunWith(MockitoJUnitRunner.StrictStubs.class)
public class TestAuditRoleManager
{
    private AuditRoleManager auditRoleManager;

    @Mock
    private IRoleManager mockWrappedRoleManager;

    @Mock
    private AuditWhitelistManager mockAuditWhitelistManager;

    @Mock
    private IDecoratedAuthenticator mockDecoratedAuthenticator;

    @Mock
    private AuditAdapter mockAuditAdapter;

    @BeforeClass
    public static void beforeClass()
    {
        ClientInitializer.beforeClass();
    }

    @Before
    public void before()
    {
        when(mockDecoratedAuthenticator.alterableOptions()).thenReturn(ImmutableSet.of(IRoleManager.Option.PASSWORD));
        when(mockDecoratedAuthenticator.supportedOptions()).thenReturn(ImmutableSet.of(IRoleManager.Option.LOGIN, IRoleManager.Option.SUPERUSER, IRoleManager.Option.PASSWORD));

        auditRoleManager = new AuditRoleManager(mockWrappedRoleManager, mockAuditWhitelistManager, mockAuditAdapter, new AuditAuthenticator(mockDecoratedAuthenticator, mockAuditAdapter));
    }

    @After
    public void after()
    {
        verifyNoMoreInteractions(mockWrappedRoleManager);
        verifyNoMoreInteractions(mockAuditWhitelistManager);
    }

    @AfterClass
    public static void afterClass()
    {
        ClientInitializer.afterClass();
    }

    @Test
    public void testSetupDelegation()
    {
        auditRoleManager.setup();

        verify(mockWrappedRoleManager).setup();
        verify(mockAuditWhitelistManager).setup();
        verify(mockAuditAdapter).setup();
    }

    @Test
    public void testSupportedOptions()
    {
        Set<IRoleManager.Option> options = auditRoleManager.supportedOptions();

        assertThat(options).containsExactlyInAnyOrder(IRoleManager.Option.LOGIN, IRoleManager.Option.SUPERUSER, IRoleManager.Option.PASSWORD, IRoleManager.Option.OPTIONS);
    }

    @Test
    public void testStandAloneSupportedOptions()
    {
        IAuthenticator authenticator = mock(IAuthenticator.class);
        AuditRoleManager standAloneAuditRoleManager = new AuditRoleManager(mockWrappedRoleManager, mockAuditWhitelistManager, mockAuditAdapter, authenticator);

        Set<IRoleManager.Option> options = standAloneAuditRoleManager.supportedOptions();

        assertThat(options).containsExactlyInAnyOrder(IRoleManager.Option.LOGIN, IRoleManager.Option.SUPERUSER, IRoleManager.Option.OPTIONS);
    }

    @Test
    public void testAlterableOptions()
    {
        Set<IRoleManager.Option> options = auditRoleManager.alterableOptions();

        assertThat(options).containsExactlyInAnyOrder(IRoleManager.Option.PASSWORD, IRoleManager.Option.OPTIONS);
    }

    @Test
    public void testStandAloneAlterableOptions()
    {
        IAuthenticator authenticator = mock(IAuthenticator.class);
        AuditRoleManager standAloneAuditRoleManager = new AuditRoleManager(mockWrappedRoleManager, mockAuditWhitelistManager, mockAuditAdapter, authenticator);

        Set<IRoleManager.Option> options = standAloneAuditRoleManager.alterableOptions();

        assertThat(options).containsExactlyInAnyOrder(IRoleManager.Option.OPTIONS);
    }

    @Test
    public void testPasswordAuthenticatorSupportedOptions()
    {
        IAuthenticator authenticator = mock(PasswordAuthenticator.class);
        AuditRoleManager passwordAuditRoleManager = new AuditRoleManager(mockWrappedRoleManager, mockAuditWhitelistManager, mockAuditAdapter, authenticator);

        Set<IRoleManager.Option> options = passwordAuditRoleManager.supportedOptions();

        assertThat(options).containsExactlyInAnyOrder(IRoleManager.Option.LOGIN, IRoleManager.Option.SUPERUSER, IRoleManager.Option.PASSWORD, IRoleManager.Option.OPTIONS);
    }

    @Test
    public void testPasswordAuthenticatorAlterableOptions()
    {
        IAuthenticator authenticator = mock(PasswordAuthenticator.class);
        AuditRoleManager passwordAuditRoleManager = new AuditRoleManager(mockWrappedRoleManager, mockAuditWhitelistManager, mockAuditAdapter, authenticator);

        Set<IRoleManager.Option> options = passwordAuditRoleManager.alterableOptions();

        assertThat(options).containsExactlyInAnyOrder(IRoleManager.Option.PASSWORD, IRoleManager.Option.OPTIONS);
    }

    @Test
    public void testAuditAuthenticatorWithoutOptions()
    {
        when(mockDecoratedAuthenticator.supportedOptions()).thenReturn(ImmutableSet.of());
        when(mockDecoratedAuthenticator.alterableOptions()).thenReturn(ImmutableSet.of());
        AuditRoleManager noOptionsAuditRoleManager = new AuditRoleManager(mockWrappedRoleManager, mockAuditWhitelistManager, mockAuditAdapter, new AuditAuthenticator(mockDecoratedAuthenticator, mockAuditAdapter));

        assertThat(noOptionsAuditRoleManager.supportedOptions()).containsExactlyInAnyOrder(IRoleManager.Option.LOGIN, IRoleManager.Option.SUPERUSER, IRoleManager.Option.OPTIONS);
        assertThat(noOptionsAuditRoleManager.alterableOptions()).containsExactlyInAnyOrder(IRoleManager.Option.OPTIONS);
    }

    @Test
    @SuppressWarnings("unchecked")
    public void testDefaultConstructorWrapsCassandraRoleManager()
    {
        AuditRoleManager defaultAuditRoleManager = new AuditRoleManager();

        Set<IResource> actualResources = (Set<IResource>) defaultAuditRoleManager.protectedResources();

        assertThat(defaultAuditRoleManager.supportedOptions()).containsExactlyInAnyOrder(IRoleManager.Option.LOGIN, IRoleManager.Option.SUPERUSER, IRoleManager.Option.OPTIONS);
        assertThat(defaultAuditRoleManager.alterableOptions()).containsExactlyInAnyOrder(IRoleManager.Option.OPTIONS);
        assertThat(actualResources).containsExactlyInAnyOrder(DataResource.table("system_auth", "roles"),
                                                              DataResource.table("system_auth", "role_members"),
                                                              DataResource.table("system_auth", "role_audit_whitelists"),
                                                              DataResource.table("system_auth", "role_audit_whitelists_v2"));
    }

    @Test
    public void testWrappingConstructorUsesConfiguredAuthenticator()
    {
        RoleResource role = mock(RoleResource.class);
        when(mockWrappedRoleManager.canLogin(eq(role))).thenReturn(true);
        IAuthenticator oldAuthenticatorToRestore = DatabaseDescriptor.getAuthenticator();
        DatabaseDescriptor.setAuthenticator(mock(PasswordAuthenticator.class));
        try
        {
            AuditRoleManager wrappingAuditRoleManager = new AuditRoleManager(mockWrappedRoleManager);

            assertThat(wrappingAuditRoleManager.supportedOptions()).containsExactlyInAnyOrder(IRoleManager.Option.LOGIN, IRoleManager.Option.SUPERUSER, IRoleManager.Option.PASSWORD, IRoleManager.Option.OPTIONS);
            assertThat(wrappingAuditRoleManager.alterableOptions()).containsExactlyInAnyOrder(IRoleManager.Option.PASSWORD, IRoleManager.Option.OPTIONS);
            assertThat(wrappingAuditRoleManager.canLogin(role)).isTrue();
            verify(mockWrappedRoleManager).canLogin(eq(role));
        }
        finally
        {
            DatabaseDescriptor.setAuthenticator(oldAuthenticatorToRestore);
        }
    }

    @Test
    public void testCreateRole()
    {
        AuthenticatedUser authenticatedUser = mock(AuthenticatedUser.class);
        RoleResource role = mock(RoleResource.class);
        RoleOptions roleOptions = mock(RoleOptions.class);

        auditRoleManager.createRole(authenticatedUser, role, roleOptions);

        verify(mockAuditWhitelistManager).createRoleOption(eq(roleOptions));
        verify(mockWrappedRoleManager).createRole(eq(authenticatedUser), eq(role), eq(roleOptions));
    }

    @Test
    public void testCreateRoleValidatesWhitelistOptionsBeforeDelegation()
    {
        AuthenticatedUser authenticatedUser = mock(AuthenticatedUser.class);
        RoleResource role = mock(RoleResource.class);
        RoleOptions roleOptions = mock(RoleOptions.class);

        auditRoleManager.createRole(authenticatedUser, role, roleOptions);

        InOrder inOrder = inOrder(mockAuditWhitelistManager, mockWrappedRoleManager);
        inOrder.verify(mockAuditWhitelistManager).createRoleOption(eq(roleOptions));
        inOrder.verify(mockWrappedRoleManager).createRole(eq(authenticatedUser), eq(role), eq(roleOptions));
    }

    @Test
    public void testCreateRoleIsNotDelegatedWhenWhitelistOptionsAreRejected()
    {
        AuthenticatedUser authenticatedUser = mock(AuthenticatedUser.class);
        RoleResource role = mock(RoleResource.class);
        RoleOptions roleOptions = mock(RoleOptions.class);
        doThrow(new InvalidRequestException("Whitelist options are not supported")).when(mockAuditWhitelistManager).createRoleOption(eq(roleOptions));

        assertThatExceptionOfType(InvalidRequestException.class)
        .isThrownBy(() -> auditRoleManager.createRole(authenticatedUser, role, roleOptions))
        .withMessage("Whitelist options are not supported");

        verify(mockAuditWhitelistManager).createRoleOption(eq(roleOptions));
    }

    @Test
    public void testAlterRole()
    {
        AuthenticatedUser authenticatedUser = mock(AuthenticatedUser.class);
        RoleResource role = mock(RoleResource.class);
        RoleOptions roleOptions = mock(RoleOptions.class);
        when(roleOptions.getPassword()).thenReturn(Optional.empty());
        when(roleOptions.getLogin()).thenReturn(Optional.empty());
        when(roleOptions.getSuperuser()).thenReturn(Optional.empty());

        auditRoleManager.alterRole(authenticatedUser, role, roleOptions);

        verify(mockAuditWhitelistManager).alterRoleOption(eq(authenticatedUser), eq(role), eq(roleOptions));
        verify(mockWrappedRoleManager).alterRole(eq(authenticatedUser), eq(role), eq(roleOptions));
    }

    @Test
    public void testAlterRoleUpdatesWhitelistBeforeDelegation()
    {
        AuthenticatedUser authenticatedUser = mock(AuthenticatedUser.class);
        RoleResource role = mock(RoleResource.class);
        RoleOptions roleOptions = mock(RoleOptions.class);
        when(authenticatedUser.isSuper()).thenReturn(true);

        auditRoleManager.alterRole(authenticatedUser, role, roleOptions);

        InOrder inOrder = inOrder(mockAuditWhitelistManager, mockWrappedRoleManager);
        inOrder.verify(mockAuditWhitelistManager).alterRoleOption(eq(authenticatedUser), eq(role), eq(roleOptions));
        inOrder.verify(mockWrappedRoleManager).alterRole(eq(authenticatedUser), eq(role), eq(roleOptions));
    }

    @Test
    public void testAlterRoleIsRejectedWithoutPermission()
    {
        // The authorizer installed by ClientInitializer grants no permissions
        AuthenticatedUser authenticatedUser = mock(AuthenticatedUser.class);
        when(authenticatedUser.getName()).thenReturn("performer");
        RoleResource role = RoleResource.role("other_role");
        RoleOptions roleOptions = mock(RoleOptions.class);
        when(roleOptions.getPassword()).thenReturn(Optional.of("secret"));

        assertThatExceptionOfType(UnauthorizedException.class)
        .isThrownBy(() -> auditRoleManager.alterRole(authenticatedUser, role, roleOptions))
        .withMessage("User performer is not authorized to alter role other_role");
    }

    @Test
    public void testAlterRoleIsNotDelegatedWhenWhitelistOptionsAreRejected()
    {
        AuthenticatedUser authenticatedUser = mock(AuthenticatedUser.class);
        RoleResource role = mock(RoleResource.class);
        RoleOptions roleOptions = mock(RoleOptions.class);
        when(authenticatedUser.isSuper()).thenReturn(true);
        doThrow(new InvalidRequestException("Exactly one whitelist option is supported")).when(mockAuditWhitelistManager).alterRoleOption(eq(authenticatedUser), eq(role), eq(roleOptions));

        assertThatExceptionOfType(InvalidRequestException.class)
        .isThrownBy(() -> auditRoleManager.alterRole(authenticatedUser, role, roleOptions))
        .withMessage("Exactly one whitelist option is supported");

        verify(mockAuditWhitelistManager).alterRoleOption(eq(authenticatedUser), eq(role), eq(roleOptions));
    }

    @Test
    public void testGrantRole()
    {
        AuthenticatedUser authenticatedUser = mock(AuthenticatedUser.class);
        RoleResource role = mock(RoleResource.class);
        RoleResource grantee = mock(RoleResource.class);

        auditRoleManager.grantRole(authenticatedUser, role, grantee);

        verify(mockWrappedRoleManager).grantRole(eq(authenticatedUser), eq(role), eq(grantee));
    }

    @Test
    public void testRevokeRole()
    {
        AuthenticatedUser authenticatedUser = mock(AuthenticatedUser.class);
        RoleResource role = mock(RoleResource.class);
        RoleResource grantee = mock(RoleResource.class);

        auditRoleManager.revokeRole(authenticatedUser, role, grantee);

        verify(mockWrappedRoleManager).revokeRole(eq(authenticatedUser), eq(role), eq(grantee));
    }

    @Test
    public void testDropRole()
    {
        AuthenticatedUser authenticatedUser = mock(AuthenticatedUser.class);
        RoleResource role = mock(RoleResource.class);

        auditRoleManager.dropRole(authenticatedUser, role);

        verify(mockWrappedRoleManager).dropRole(eq(authenticatedUser), eq(role));
        verify(mockAuditWhitelistManager).dropRoleWhitelist(eq(role));
    }

    @Test
    public void testDropRoleRemovesWhitelistAfterDelegation()
    {
        AuthenticatedUser authenticatedUser = mock(AuthenticatedUser.class);
        RoleResource role = mock(RoleResource.class);

        auditRoleManager.dropRole(authenticatedUser, role);

        InOrder inOrder = inOrder(mockWrappedRoleManager, mockAuditWhitelistManager);
        inOrder.verify(mockWrappedRoleManager).dropRole(eq(authenticatedUser), eq(role));
        inOrder.verify(mockAuditWhitelistManager).dropRoleWhitelist(eq(role));
    }

    @Test
    public void testDropRoleKeepsWhitelistWhenDelegationFails()
    {
        AuthenticatedUser authenticatedUser = mock(AuthenticatedUser.class);
        RoleResource role = mock(RoleResource.class);
        doThrow(new InvalidRequestException("Role does not exist")).when(mockWrappedRoleManager).dropRole(eq(authenticatedUser), eq(role));

        assertThatExceptionOfType(InvalidRequestException.class)
        .isThrownBy(() -> auditRoleManager.dropRole(authenticatedUser, role))
        .withMessage("Role does not exist");

        verify(mockWrappedRoleManager).dropRole(eq(authenticatedUser), eq(role));
    }

    @Test
    public void testGetRoles()
    {
        RoleResource role = mock(RoleResource.class);
        Set<RoleResource> expectedRoles = givenRoleManagerHasRoleWithRoles(mockWrappedRoleManager, role);

        Set<RoleResource> actualRoles = auditRoleManager.getRoles(role, true);

        verify(mockWrappedRoleManager).getRoles(eq(role), eq(true));
        assertThat(actualRoles).containsExactlyInAnyOrderElementsOf(expectedRoles);
    }

    @Test
    public void testGetRolesWithoutInherited()
    {
        RoleResource role = mock(RoleResource.class);
        Set<RoleResource> expectedRoles = ImmutableSet.of(role);
        when(mockWrappedRoleManager.getRoles(eq(role), eq(false))).thenReturn(expectedRoles);

        Set<RoleResource> actualRoles = auditRoleManager.getRoles(role, false);

        verify(mockWrappedRoleManager).getRoles(eq(role), eq(false));
        assertThat(actualRoles).isSameAs(expectedRoles);
    }

    @Test
    public void testGetRoleDetails()
    {
        RoleResource role = mock(RoleResource.class);
        Set<Role> expectedRoleDetails = ImmutableSet.of(mock(Role.class));
        when(mockWrappedRoleManager.getRoleDetails(eq(role))).thenReturn(expectedRoleDetails);

        Set<Role> actualRoleDetails = auditRoleManager.getRoleDetails(role);

        verify(mockWrappedRoleManager).getRoleDetails(eq(role));
        assertThat(actualRoleDetails).isSameAs(expectedRoleDetails);
    }

    @Test
    public void testGetAllRoles()
    {
        RoleResource role = mock(RoleResource.class);
        Set<RoleResource> expectedRoles = givenRoleManagerHasRoleWithRoles(mockWrappedRoleManager, role);

        Set<RoleResource> actualRoles = auditRoleManager.getAllRoles();

        verify(mockWrappedRoleManager).getAllRoles();
        assertThat(actualRoles).containsExactlyInAnyOrderElementsOf(expectedRoles);
    }

    @Test
    public void testIsSuper()
    {
        RoleResource role = mock(RoleResource.class);
        when(mockWrappedRoleManager.isSuper(eq(role))).thenReturn(true);

        boolean isSuper = auditRoleManager.isSuper(role);

        verify(mockWrappedRoleManager).isSuper(eq(role));
        assertThat(isSuper).isTrue();
    }

    @Test
    public void testCanLogin()
    {
        RoleResource role = mock(RoleResource.class);
        when(mockWrappedRoleManager.canLogin(eq(role))).thenReturn(true);

        boolean canLogin = auditRoleManager.canLogin(role);

        verify(mockWrappedRoleManager).canLogin(eq(role));
        assertThat(canLogin).isTrue();
    }

    @Test
    public void testGetCustomOptions()
    {
        RoleResource role = mock(RoleResource.class);
        Map<String, String> expectedOptions = givenWhitelistManagerHasRoleWithOptions(mockAuditWhitelistManager, role);

        Map<String, String> actualOptions = auditRoleManager.getCustomOptions(role);

        verify(mockAuditWhitelistManager).getRoleWhitelist(eq(role));
        assertThat(actualOptions.entrySet()).containsExactlyInAnyOrderElementsOf(expectedOptions.entrySet());
    }

    @Test
    public void testIsExistingRole()
    {
        RoleResource role = mock(RoleResource.class);
        when(mockWrappedRoleManager.isExistingRole(eq(role))).thenReturn(true);

        boolean isExitingRole = auditRoleManager.isExistingRole(role);

        verify(mockWrappedRoleManager).isExistingRole(eq(role));
        assertThat(isExitingRole).isTrue();
    }

    @Test
    @SuppressWarnings("unchecked")
    public void testProtectedResources()
    {
        Set<IResource> cassandraResources = givenProtectedCassandraResources(mockWrappedRoleManager);

        Set<IResource> actualResources = (Set<IResource>) auditRoleManager.protectedResources();

        assertThat(actualResources).containsAll(cassandraResources);
        assertThat(actualResources).containsAll(ImmutableSet.of(DataResource.table("system_auth", "role_audit_whitelists"),
                                                                DataResource.table("system_auth", "role_audit_whitelists_v2")));
        assertThat(actualResources).hasSize(cassandraResources.size() + 2);
    }

    @Test
    public void testProtectedResourcesAreImmutable()
    {
        givenProtectedCassandraResources(mockWrappedRoleManager);

        Set<? extends IResource> actualResources = auditRoleManager.protectedResources();

        assertThat(actualResources).isInstanceOf(ImmutableSet.class);
    }

    @Test
    public void testValidateConfiguration()
    {
        auditRoleManager.validateConfiguration();

        verify(mockWrappedRoleManager).validateConfiguration();
    }

    @Test
    public void testValidateConfigurationPropagatesFailure()
    {
        doThrow(new ConfigurationException("Invalid role manager configuration")).when(mockWrappedRoleManager).validateConfiguration();

        assertThatExceptionOfType(ConfigurationException.class)
        .isThrownBy(() -> auditRoleManager.validateConfiguration())
        .withMessage("Invalid role manager configuration");

        verify(mockWrappedRoleManager).validateConfiguration();
    }

    private Set<RoleResource> givenRoleManagerHasRoleWithRoles(IRoleManager roleManager, RoleResource role)
    {
        RoleResource otherRole = mock(RoleResource.class);

        Set<RoleResource> expectedRoles = ImmutableSet.of(role, otherRole);
        when(roleManager.getRoles(eq(role), anyBoolean())).thenReturn(expectedRoles);
        when(roleManager.getAllRoles()).thenReturn(expectedRoles);

        return expectedRoles;
    }

    private Map<String, String> givenWhitelistManagerHasRoleWithOptions(AuditWhitelistManager auditWhitelistManager, RoleResource role)
    {
        Map<String, String> expectedOptions = ImmutableMap.of("optionKey", "optionValue");
        when(auditWhitelistManager.getRoleWhitelist(eq(role))).thenReturn(expectedOptions);

        return expectedOptions;
    }

    private Set<IResource> givenProtectedCassandraResources(IRoleManager roleManager)
    {
        Set<IResource> cassandraResources = ImmutableSet.of(DataResource.table("ks", "tbl"));
        doReturn(cassandraResources).when(roleManager).protectedResources();
        return cassandraResources;
    }
}
