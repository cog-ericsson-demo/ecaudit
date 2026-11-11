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

import java.util.Collections;
import java.util.EnumSet;

import org.junit.AfterClass;
import org.junit.Before;
import org.junit.BeforeClass;
import org.junit.Test;
import org.junit.runner.RunWith;

import com.ericsson.bss.cassandra.ecaudit.test.mode.ClientInitializer;
import org.apache.cassandra.auth.AuthenticatedUser;
import org.apache.cassandra.auth.IAuthorizer;
import org.apache.cassandra.auth.IRoleManager;
import org.apache.cassandra.auth.Permission;
import org.apache.cassandra.auth.RoleOptions;
import org.apache.cassandra.auth.RoleResource;
import org.apache.cassandra.config.DatabaseDescriptor;
import org.apache.cassandra.exceptions.UnauthorizedException;
import org.mockito.Mock;
import org.mockito.junit.MockitoJUnitRunner;

import static org.assertj.core.api.Assertions.assertThatExceptionOfType;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

@RunWith(MockitoJUnitRunner.StrictStubs.class)
public class TestPermissionChecker
{
    @Mock
    private AuditAuthorizer authorizer;

    private PermissionChecker permissionChecker;

    @BeforeClass
    public static void beforeClass()
    {
        ClientInitializer.beforeClass();
    }

    @Before
    public void before()
    {
        permissionChecker = new PermissionChecker(authorizer);
    }

    @AfterClass
    public static void afterClass()
    {
        ClientInitializer.afterClass();
    }

    @Test
    public void superUserCanChangeAllAttributes()
    {
        AuthenticatedUser performer = givenSuperUser();
        RoleResource grantee = givenNormalRole();
        RoleOptions options = givenAllOptions();

        permissionChecker.checkAlterRoleAccess(performer, grantee, options);
    }

    @Test
    public void normalUserCanChangeOwnPassword()
    {
        AuthenticatedUser performer = givenNormalUser();
        RoleResource grantee = givenNormalRole();
        RoleOptions options = givenPasswordOptions();

        permissionChecker.checkAlterRoleAccess(performer, grantee, options);
    }

    @Test
    public void normalUserCanAlterOtherOptionMap()
    {
        AuthenticatedUser performer = givenNormalUser();
        RoleResource grantee = givenOtherRole();
        RoleOptions options = givenOptionsOptions();

        permissionChecker.checkAlterRoleAccess(performer, grantee, options);
    }

    @Test
    public void normalUserCanNotAlterOtherAllAttributes()
    {
        AuthenticatedUser performer = givenNormalUser();
        RoleResource grantee = givenOtherRole();
        RoleOptions options = givenAllOptions();

        assertThatExceptionOfType(UnauthorizedException.class)
        .isThrownBy(() -> permissionChecker.checkAlterRoleAccess(performer, grantee, options));
    }

    @Test
    public void trustedUserCanAlterOtherAllAttributes()
    {
        AuthenticatedUser performer = givenTrustedUser();
        RoleResource grantee = givenOtherRole();
        RoleOptions options = givenAllOptions();

        permissionChecker.checkAlterRoleAccess(performer, grantee, options);
    }

    private AuthenticatedUser givenSuperUser()
    {
        AuthenticatedUser user = mock(AuthenticatedUser.class);
        when(user.isSuper()).thenReturn(true);
        return user;
    }

    private AuthenticatedUser givenTrustedUser()
    {
        AuthenticatedUser user = mock(AuthenticatedUser.class);
        when(user.getName()).thenReturn("trusted");

        when(authorizer.realAuthorize(eq(user), any(RoleResource.class))).thenReturn(EnumSet.of(Permission.ALTER));

        return user;
    }

    private AuthenticatedUser givenNormalUser()
    {
        AuthenticatedUser user = mock(AuthenticatedUser.class);
        when(user.getName()).thenReturn("normal");
        return user;
    }

    private RoleResource givenNormalRole()
    {
        return RoleResource.role("normal");
    }

    private RoleResource givenOtherRole()
    {
        return RoleResource.role("other");
    }

    private RoleOptions givenAllOptions()
    {
        RoleOptions options = new RoleOptions();
        options.setOption(IRoleManager.Option.LOGIN, true);
        options.setOption(IRoleManager.Option.PASSWORD, "secret");
        options.setOption(IRoleManager.Option.SUPERUSER, true);
        options.setOption(IRoleManager.Option.OPTIONS, Collections.emptyMap());
        return options;
    }

    private RoleOptions givenPasswordOptions()
    {
        RoleOptions options = new RoleOptions();
        options.setOption(IRoleManager.Option.PASSWORD, "secret");
        return options;
    }

    private RoleOptions givenOptionsOptions()
    {
        RoleOptions options = new RoleOptions();
        options.setOption(IRoleManager.Option.OPTIONS, Collections.emptyMap());
        return options;
    }

    @Test
    public void normalUserCanNotChangeLoginOfOtherRole()
    {
        AuthenticatedUser performer = givenNormalUser();
        RoleResource grantee = givenOtherRole();
        RoleOptions options = givenLoginOptions();

        assertThatExceptionOfType(UnauthorizedException.class)
        .isThrownBy(() -> permissionChecker.checkAlterRoleAccess(performer, grantee, options))
        .withMessage("User normal is not authorized to alter role other");
    }

    @Test
    public void normalUserCanNotChangeOwnSuperuserStatus()
    {
        AuthenticatedUser performer = givenNormalUser();
        RoleResource grantee = givenNormalRole();
        RoleOptions options = givenSuperuserOptions();

        assertThatExceptionOfType(UnauthorizedException.class)
        .isThrownBy(() -> permissionChecker.checkAlterRoleAccess(performer, grantee, options));
    }

    @Test
    public void trustedUserCanChangeOwnSuperuserStatus()
    {
        AuthenticatedUser performer = givenTrustedUser();
        RoleResource grantee = RoleResource.role("trusted");
        RoleOptions options = givenSuperuserOptions();

        permissionChecker.checkAlterRoleAccess(performer, grantee, options);
    }

    @Test
    public void plainAuthorizerPermissionsAreUsed()
    {
        IAuthorizer plainAuthorizer = mock(IAuthorizer.class);
        AuthenticatedUser performer = givenNormalUser();
        when(plainAuthorizer.authorize(eq(performer), any(RoleResource.class))).thenReturn(EnumSet.of(Permission.ALTER));
        PermissionChecker checker = new PermissionChecker(plainAuthorizer);

        checker.checkAlterRoleAccess(performer, givenOtherRole(), givenAllOptions());

        verify(plainAuthorizer).authorize(eq(performer), eq(givenOtherRole()));
    }

    @Test
    public void plainAuthorizerWithoutAlterPermissionIsRejected()
    {
        IAuthorizer plainAuthorizer = mock(IAuthorizer.class);
        AuthenticatedUser performer = givenNormalUser();
        when(plainAuthorizer.authorize(eq(performer), any(RoleResource.class))).thenReturn(EnumSet.of(Permission.SELECT));
        PermissionChecker checker = new PermissionChecker(plainAuthorizer);

        assertThatExceptionOfType(UnauthorizedException.class)
        .isThrownBy(() -> checker.checkAlterRoleAccess(performer, givenOtherRole(), givenAllOptions()));
    }

    @Test
    public void defaultConstructorLazilyUsesConfiguredAuthorizer()
    {
        IAuthorizer originalAuthorizer = DatabaseDescriptor.getAuthorizer();
        IAuthorizer configuredAuthorizer = mock(IAuthorizer.class);
        AuthenticatedUser performer = givenNormalUser();
        when(configuredAuthorizer.authorize(eq(performer), any(RoleResource.class))).thenReturn(EnumSet.of(Permission.ALTER));
        DatabaseDescriptor.setAuthorizer(configuredAuthorizer);
        try
        {
            PermissionChecker checker = new PermissionChecker();

            checker.checkAlterRoleAccess(performer, givenOtherRole(), givenAllOptions());
            checker.checkAlterRoleAccess(performer, givenOtherRole(), givenAllOptions());
        }
        finally
        {
            DatabaseDescriptor.setAuthorizer(originalAuthorizer);
        }

        verify(configuredAuthorizer, times(2)).authorize(eq(performer), eq(givenOtherRole()));
    }

    private RoleOptions givenLoginOptions()
    {
        RoleOptions options = new RoleOptions();
        options.setOption(IRoleManager.Option.LOGIN, true);
        return options;
    }

    private RoleOptions givenSuperuserOptions()
    {
        RoleOptions options = new RoleOptions();
        options.setOption(IRoleManager.Option.SUPERUSER, true);
        return options;
    }
}
