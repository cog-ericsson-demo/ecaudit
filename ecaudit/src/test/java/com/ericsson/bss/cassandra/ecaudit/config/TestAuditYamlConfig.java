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

import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import org.junit.AfterClass;
import org.junit.BeforeClass;
import org.junit.Test;

import com.ericsson.bss.cassandra.ecaudit.auth.DecoratedPasswordAuthenticator;
import com.ericsson.bss.cassandra.ecaudit.entry.suppressor.SuppressNothing;
import com.ericsson.bss.cassandra.ecaudit.logger.Slf4jAuditLogger;
import com.ericsson.bss.cassandra.ecaudit.test.mode.ClientInitializer;
import org.apache.cassandra.auth.CassandraAuthorizer;
import org.apache.cassandra.config.DatabaseDescriptor;
import org.apache.cassandra.config.ParameterizedClass;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatExceptionOfType;
import static org.assertj.core.api.Assertions.entry;

public class TestAuditYamlConfig
{
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
    public void testNewInstanceIsFromFile()
    {
        assertThat(new AuditYamlConfig().isFromFile()).isTrue();
    }

    @Test
    public void testCreateWithoutFileIsNotFromFile()
    {
        assertThat(AuditYamlConfig.createWithoutFile().isFromFile()).isFalse();
    }

    @Test
    public void testDefaults()
    {
        AuditYamlConfig config = new AuditYamlConfig();

        assertThat(config.getWhitelist()).isEmpty();
        assertThat(config.isPostLogging()).isFalse();
        assertThat(config.getWrappedAuthorizer()).isEqualTo(CassandraAuthorizer.class.getName());
        assertThat(config.getWrappedAuthenticator()).isEqualTo(DecoratedPasswordAuthenticator.class.getName());
        assertThat(config.getBoundValueSuppressor()).isEqualTo(SuppressNothing.class.getName());
        assertThat(config.getWhitelistCacheValidity()).isEqualTo(DatabaseDescriptor.getRolesValidity());
        assertThat(config.getWhitelistCacheUpdateInterval()).isEqualTo(DatabaseDescriptor.getRolesUpdateInterval());
        assertThat(config.getWhitelistCacheMaxEntries()).isEqualTo(DatabaseDescriptor.getRolesCacheMaxEntries() * 10);
        assertThat(config.isWhitelistCacheActiveUpdate()).isEqualTo(DatabaseDescriptor.getRolesCacheActiveUpdate());
        assertThat(config.isSuppressPrepareStatements()).isTrue();
    }

    @Test
    public void testDefaultLoggerBackend()
    {
        ParameterizedClass backend = new AuditYamlConfig().getLoggerBackendParameters();

        assertThat(backend.class_name).isEqualTo(Slf4jAuditLogger.class.getCanonicalName());
        assertThat(backend.parameters).isEmpty();
    }

    @Test
    public void testExplicitValues()
    {
        AuditYamlConfig config = new AuditYamlConfig();
        config.whitelist = Arrays.asList("User1", "User2");
        config.log_timing_strategy = LoggerTiming.post_logging;
        config.wrapped_authorizer = "MyAuthorizer";
        config.wrapped_authenticator = "MyAuthenticator";
        config.bound_value_suppressor = "MySuppressor";
        config.whitelist_cache_validity_in_ms = 1;
        config.whitelist_cache_update_interval_in_ms = 2;
        config.whitelist_cache_max_entries = 3;
        config.whitelist_cache_active_update = !DatabaseDescriptor.getRolesCacheActiveUpdate();
        config.suppress_prepare_statements = false;

        assertThat(config.getWhitelist()).containsExactly("User1", "User2");
        assertThat(config.isPostLogging()).isTrue();
        assertThat(config.getWrappedAuthorizer()).isEqualTo("MyAuthorizer");
        assertThat(config.getWrappedAuthenticator()).isEqualTo("MyAuthenticator");
        assertThat(config.getBoundValueSuppressor()).isEqualTo("MySuppressor");
        assertThat(config.getWhitelistCacheValidity()).isEqualTo(1);
        assertThat(config.getWhitelistCacheUpdateInterval()).isEqualTo(2);
        assertThat(config.getWhitelistCacheMaxEntries()).isEqualTo(3);
        assertThat(config.isWhitelistCacheActiveUpdate()).isEqualTo(!DatabaseDescriptor.getRolesCacheActiveUpdate());
        assertThat(config.isSuppressPrepareStatements()).isFalse();
    }

    @Test
    public void testPreLoggingIsNotPostLogging()
    {
        AuditYamlConfig config = new AuditYamlConfig();
        config.log_timing_strategy = LoggerTiming.pre_logging;

        assertThat(config.isPostLogging()).isFalse();
    }

    @Test
    public void testWhitelistIsUnmodifiable()
    {
        AuditYamlConfig config = new AuditYamlConfig();
        config.whitelist = new ArrayList<>(Arrays.asList("User1"));

        List<String> whitelist = config.getWhitelist();

        assertThatExceptionOfType(UnsupportedOperationException.class)
        .isThrownBy(() -> whitelist.add("User2"));
    }

    @Test
    public void testSetters()
    {
        AuditYamlConfig config = new AuditYamlConfig();

        config.setWhitelistCacheValidity(10);
        config.setWhitelistCacheUpdateInterval(20);
        config.setWhitelistCacheMaxEntries(30);
        config.setWhitelistCacheActiveUpdate(true);

        assertThat(config.getWhitelistCacheValidity()).isEqualTo(10);
        assertThat(config.getWhitelistCacheUpdateInterval()).isEqualTo(20);
        assertThat(config.getWhitelistCacheMaxEntries()).isEqualTo(30);
        assertThat(config.isWhitelistCacheActiveUpdate()).isTrue();

        config.setWhitelistCacheActiveUpdate(false);

        assertThat(config.isWhitelistCacheActiveUpdate()).isFalse();
    }

    @Test
    @SuppressWarnings({ "unchecked", "rawtypes" })
    public void testLoggerBackendParametersAreConvertedToStrings()
    {
        Map parameters = new HashMap<>();
        parameters.put("log_dir", "/tmp");
        parameters.put("max_log_size", 1000000);
        AuditYamlConfig config = new AuditYamlConfig();
        config.logger_backend = new ParameterizedClass("MyLogger", parameters);

        ParameterizedClass backend = config.getLoggerBackendParameters();

        assertThat(backend.class_name).isEqualTo("MyLogger");
        assertThat(backend.parameters).containsOnly(entry("log_dir", "/tmp"),
                                                    entry("max_log_size", "1000000"));
    }

    @Test
    public void testLoggerBackendWithoutParameters()
    {
        AuditYamlConfig config = new AuditYamlConfig();
        config.logger_backend = new ParameterizedClass("MyLogger", null);

        ParameterizedClass backend = config.getLoggerBackendParameters();

        assertThat(backend.class_name).isEqualTo("MyLogger");
        assertThat(backend.parameters).isEmpty();
    }

    @Test
    public void testLoggerBackendIsDeepCopy()
    {
        Map<String, String> parameters = new HashMap<>();
        parameters.put("key", "value");
        AuditYamlConfig config = new AuditYamlConfig();
        config.logger_backend = new ParameterizedClass("MyLogger", parameters);

        ParameterizedClass first = config.getLoggerBackendParameters();
        first.class_name = "Changed";
        first.parameters.put("other", "value");

        ParameterizedClass second = config.getLoggerBackendParameters();
        assertThat(second).isNotSameAs(first);
        assertThat(second.class_name).isEqualTo("MyLogger");
        assertThat(second.parameters).containsOnly(entry("key", "value"));
        assertThat(parameters).containsOnly(entry("key", "value"));
    }
}
