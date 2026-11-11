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
package com.ericsson.bss.cassandra.ecaudit.auth;

import java.util.Collections;

import org.junit.AfterClass;
import org.junit.BeforeClass;
import org.junit.Test;
import org.junit.runner.RunWith;

import com.ericsson.bss.cassandra.ecaudit.AuditAdapter;
import com.ericsson.bss.cassandra.ecaudit.test.mode.ClientInitializer;
import org.apache.cassandra.auth.IRoleManager;
import org.mockito.Mock;
import org.mockito.MockedConstruction;
import org.mockito.MockedStatic;
import org.mockito.junit.MockitoJUnitRunner;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.mockConstruction;
import static org.mockito.Mockito.mockStatic;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.mockito.Mockito.when;

@RunWith(MockitoJUnitRunner.StrictStubs.class)
public class TestAuditPasswordAuthenticator
{
    @Mock
    private AuditAdapter mockAuditAdapter;

    @BeforeClass
    public static void beforeClass()
    {
        ClientInitializer.beforeClass();
    }

    @AfterClass
    public static void afterClass()
    {
        ClientInitializer.afterClass();
    }

    @Test
    @SuppressWarnings("deprecation")
    public void testWrapsPasswordAuthenticatorWithAuditAdapterSingleton()
    {
        try (MockedStatic<AuditAdapter> auditAdapter = mockStatic(AuditAdapter.class);
             MockedConstruction<DecoratedPasswordAuthenticator> wrapped = mockConstruction(DecoratedPasswordAuthenticator.class,
                                                                                          (mock, context) -> when(mock.supportedOptions()).thenReturn(Collections.singleton(IRoleManager.Option.PASSWORD))))
        {
            auditAdapter.when(AuditAdapter::getInstance).thenReturn(mockAuditAdapter);

            AuditPasswordAuthenticator authenticator = new AuditPasswordAuthenticator();

            assertThat(authenticator).isInstanceOf(AuditAuthenticator.class);
            assertThat(authenticator.supportedOptions()).containsExactly(IRoleManager.Option.PASSWORD);
            assertThat(wrapped.constructed()).hasSize(1);
            auditAdapter.verify(AuditAdapter::getInstance);
        }

        verifyNoInteractions(mockAuditAdapter);
    }
}
