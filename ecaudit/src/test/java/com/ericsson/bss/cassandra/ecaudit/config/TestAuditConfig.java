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
package com.ericsson.bss.cassandra.ecaudit.config;

import java.util.Arrays;
import java.util.Collections;

import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.Mock;
import org.mockito.junit.MockitoJUnitRunner;

import org.apache.cassandra.config.ParameterizedClass;
import org.apache.cassandra.exceptions.ConfigurationException;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatExceptionOfType;
import static org.assertj.core.api.Assertions.entry;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

@RunWith(MockitoJUnitRunner.StrictStubs.class)
public class TestAuditConfig
{
    @Mock
    private AuditYamlConfigurationLoader mockLoader;

    private AuditYamlConfig yamlConfig;

    private AuditConfig config;

    @Before
    public void before()
    {
        yamlConfig = new AuditYamlConfig();
        config = new AuditConfig(mockLoader);
    }

    @Test
    public void testGetInstanceReturnsSingleton()
    {
        assertThat(AuditConfig.getInstance()).isNotNull();
        assertThat(AuditConfig.getInstance()).isSameAs(AuditConfig.getInstance());
    }

    @Test
    public void testConfigIsLoadedOnlyOnce()
    {
        when(mockLoader.loadConfig()).thenReturn(yamlConfig);

        config.getWrappedAuthorizer();
        config.getWrappedAuthenticator();
        config.isPostLogging();

        verify(mockLoader, times(1)).loadConfig();
    }

    @Test
    public void testLoadFailureIsPropagatedAndRetried()
    {
        when(mockLoader.loadConfig())
        .thenThrow(new ConfigurationException("Invalid configuration file"))
        .thenReturn(yamlConfig);

        assertThatExceptionOfType(ConfigurationException.class)
        .isThrownBy(config::getBoundValueSuppressor)
        .withMessage("Invalid configuration file");

        assertThat(config.getBoundValueSuppressor()).isEqualTo(yamlConfig.getBoundValueSuppressor());
        verify(mockLoader, times(2)).loadConfig();
    }

    @Test
    public void testYamlWhitelistFromFile()
    {
        yamlConfig.whitelist = Arrays.asList("User1", "User2");
        when(mockLoader.loadConfig()).thenReturn(yamlConfig);

        assertThat(config.getYamlWhitelist()).containsExactly("User1", "User2");
    }

    @Test
    public void testYamlWhitelistWithoutFileThrows()
    {
        when(mockLoader.loadConfig()).thenReturn(AuditYamlConfig.createWithoutFile());

        assertThatExceptionOfType(ConfigurationException.class)
        .isThrownBy(config::getYamlWhitelist)
        .withMessage("No audit configuration file found for yaml based whitelist");
    }

    @Test
    public void testValuesAreDelegated()
    {
        yamlConfig.logger_backend = new ParameterizedClass("MyLogger", Collections.singletonMap("key", "value"));
        yamlConfig.log_timing_strategy = LoggerTiming.post_logging;
        yamlConfig.wrapped_authorizer = "MyAuthorizer";
        yamlConfig.wrapped_authenticator = "MyAuthenticator";
        yamlConfig.bound_value_suppressor = "MySuppressor";
        yamlConfig.whitelist_cache_validity_in_ms = 1;
        yamlConfig.whitelist_cache_update_interval_in_ms = 2;
        yamlConfig.whitelist_cache_max_entries = 3;
        yamlConfig.whitelist_cache_active_update = true;
        yamlConfig.suppress_prepare_statements = false;
        when(mockLoader.loadConfig()).thenReturn(yamlConfig);

        assertThat(config.getLoggerBackendParameters().class_name).isEqualTo("MyLogger");
        assertThat(config.getLoggerBackendParameters().parameters).containsOnly(entry("key", "value"));
        assertThat(config.isPostLogging()).isTrue();
        assertThat(config.getWrappedAuthorizer()).isEqualTo("MyAuthorizer");
        assertThat(config.getWrappedAuthenticator()).isEqualTo("MyAuthenticator");
        assertThat(config.getBoundValueSuppressor()).isEqualTo("MySuppressor");
        assertThat(config.getWhitelistCacheValidity()).isEqualTo(1);
        assertThat(config.getWhitelistCacheUpdateInterval()).isEqualTo(2);
        assertThat(config.getWhitelistCacheMaxEntries()).isEqualTo(3);
        assertThat(config.isWhitelistCacheActiveUpdate()).isTrue();
        assertThat(config.isSuppressPrepareStatements()).isFalse();
    }

    @Test
    public void testSettersUpdateLoadedConfig()
    {
        when(mockLoader.loadConfig()).thenReturn(yamlConfig);

        config.setWhitelistCacheValidity(10);
        config.setWhitelistCacheUpdateInterval(20);
        config.setWhitelistCacheMaxEntries(30);
        config.setWhitelistCacheActiveUpdate(true);

        assertThat(config.getWhitelistCacheValidity()).isEqualTo(10);
        assertThat(config.getWhitelistCacheUpdateInterval()).isEqualTo(20);
        assertThat(config.getWhitelistCacheMaxEntries()).isEqualTo(30);
        assertThat(config.isWhitelistCacheActiveUpdate()).isTrue();
        assertThat(yamlConfig.whitelist_cache_validity_in_ms).isEqualTo(10);
        assertThat(yamlConfig.whitelist_cache_update_interval_in_ms).isEqualTo(20);
        assertThat(yamlConfig.whitelist_cache_max_entries).isEqualTo(30);
        assertThat(yamlConfig.whitelist_cache_active_update).isTrue();
    }
}
