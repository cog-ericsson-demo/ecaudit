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
package com.ericsson.bss.cassandra.ecaudit.config;

import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.net.URL;
import java.net.URLClassLoader;
import java.net.URLConnection;
import java.net.URLStreamHandler;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.util.Properties;

import org.junit.AfterClass;
import org.junit.BeforeClass;
import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.TemporaryFolder;

import com.ericsson.bss.cassandra.ecaudit.entry.suppressor.SuppressNothing;
import com.ericsson.bss.cassandra.ecaudit.test.mode.ClientInitializer;
import org.apache.cassandra.config.DatabaseDescriptor;
import org.apache.cassandra.exceptions.ConfigurationException;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatExceptionOfType;
import static org.assertj.core.api.Assertions.entry;

public class TestAuditYamlConfigurationLoader
{
    @Rule
    public TemporaryFolder temporaryFolder = new TemporaryFolder();

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
    public void testEmptyPropertyThrowsConfigurationException()
    {
        Properties properties = new Properties();
        properties.put(AuditYamlConfigurationLoader.PROPERTY_CONFIG_FILE, "");

        AuditConfig config = givenLoadedConfig(properties);

        assertThatExceptionOfType(ConfigurationException.class)
        .isThrownBy(config::getYamlWhitelist);
        assertThatExceptionOfType(ConfigurationException.class)
        .isThrownBy(config::getLoggerBackendParameters);
    }

    @Test
    public void testNonExistingPathPropertyThrowsConfigurationExceptionOnAllGetters()
    {
        Properties properties = new Properties();
        properties.put(AuditYamlConfigurationLoader.PROPERTY_CONFIG_FILE, "does_not_exist.yaml");

        AuditConfig config = givenLoadedConfig(properties);

        assertThatExceptionOfType(ConfigurationException.class)
        .isThrownBy(config::getYamlWhitelist);
        assertThatExceptionOfType(ConfigurationException.class)
        .isThrownBy(config::getLoggerBackendParameters);
    }

    // If ecAudit is configured to use a yaml based whitelist we expect a file to be there
    // This behavior is different for other properties which should fall back to default values
    @Test
    public void testMissingDefaultFileForWhitelistThrowsConfigurationException()
    {
        AuditConfig config = givenLoadedDefaultConfig();

        assertThatExceptionOfType(ConfigurationException.class)
        .isThrownBy(config::getYamlWhitelist);
    }

    @Test
    public void testDefaultConfiguration()
    {
        Properties properties = getProperties("empty.yaml");

        AuditConfig config = givenLoadedConfig(properties);

        assertThat(config.getYamlWhitelist()).isEmpty();
        assertThat(config.isPostLogging()).isFalse();
        assertThat(config.getBoundValueSuppressor()).isEqualTo(SuppressNothing.class.getName());
        assertThat(config.getWhitelistCacheValidity()).isEqualTo(DatabaseDescriptor.getRolesValidity());
        assertThat(config.getWhitelistCacheUpdateInterval()).isEqualTo(DatabaseDescriptor.getRolesUpdateInterval());
        assertThat(config.getWhitelistCacheMaxEntries()).isEqualTo(DatabaseDescriptor.getRolesCacheMaxEntries() * 10);
        assertThat(config.isSuppressPrepareStatements()).isEqualTo(true);
    }

    @Test
    public void testEmptyWhitelistIsStillValid()
    {
        Properties properties = getProperties("missing_all.yaml");

        AuditConfig config = givenLoadedConfig(properties);

        assertThat(config.getYamlWhitelist()).isEmpty();
    }

    @Test
    public void testCustomConfiguration()
    {
        Properties properties = getProperties("mock_configuration.yaml");

        AuditConfig config = givenLoadedConfig(properties);

        assertThat(config.getYamlWhitelist()).containsOnly("User1", "User2");
        assertThat(config.isPostLogging()).isTrue();
        assertThat(config.getBoundValueSuppressor()).isEqualTo("SuppressBlobs");
        assertThat(config.getWhitelistCacheValidity()).isEqualTo(42);
        assertThat(config.getWhitelistCacheUpdateInterval()).isEqualTo(41);
        assertThat(config.getWhitelistCacheMaxEntries()).isEqualTo(40);
        assertThat(config.isSuppressPrepareStatements()).isEqualTo(false);
    }

    @Test
    public void testPostLoggingDefault()
    {
        Properties properties = getProperties("empty.yaml");

        AuditConfig config = givenLoadedConfig(properties);

        assertThat(config.isPostLogging()).isFalse();
    }

    @Test
    public void testPostLoggingConfigured()
    {
        Properties properties = getProperties("mock_configuration.yaml");

        AuditConfig config = givenLoadedConfig(properties);

        assertThat(config.isPostLogging()).isTrue();
    }

    @Test
    public void testLoggerTypeWhenMissingDefaultFile()
    {
        AuditConfig config = givenLoadedDefaultConfig();

        assertThat(config.getLoggerBackendParameters().class_name).isEqualTo("com.ericsson.bss.cassandra.ecaudit.logger.Slf4jAuditLogger");
        assertThat(config.getLoggerBackendParameters().parameters).isEmpty();
    }

    @Test
    public void testLoggerParametersWhenLoadingCustomConfiguration()
    {
        Properties properties = getProperties("mock_log_format.yaml");
        AuditConfig config = givenLoadedConfig(properties);

        assertThat(config.getLoggerBackendParameters().class_name).isEqualTo("com.ericsson.bss.cassandra.ecaudit.logger.ChronicleAuditLogger");
        assertThat(config.getLoggerBackendParameters().parameters).containsOnly(entry("log_dir", "/tmp"),
                                                                                entry("roll_cycle", "MINUTELY"),
                                                                                entry("max_log_size", "1000000"));
    }

    @Test
    public void testAuthorizerTypeWhenMissingDefaultFile()
    {
        AuditConfig config = givenLoadedDefaultConfig();

        assertThat(config.getWrappedAuthorizer()).isEqualTo("org.apache.cassandra.auth.CassandraAuthorizer");
    }

    @Test
    public void testCustomAuthorizerType()
    {
        Properties properties = getProperties("mock_configuration.yaml");
        AuditConfig config = givenLoadedConfig(properties);

        assertThat(config.getWrappedAuthorizer()).isEqualTo("org.apache.cassandra.auth.AllowAllAuthorizer");
    }

    @Test
    public void testWhitelistCacheParametersCanBeSet()
    {
        Properties properties = getProperties("empty.yaml");

        AuditConfig config = givenLoadedConfig(properties);

        config.setWhitelistCacheValidity(99);
        config.setWhitelistCacheUpdateInterval(88);
        config.setWhitelistCacheMaxEntries(77);

        assertThat(config.getWhitelistCacheValidity()).isEqualTo(99);
        assertThat(config.getWhitelistCacheUpdateInterval()).isEqualTo(88);
        assertThat(config.getWhitelistCacheMaxEntries()).isEqualTo(77);
    }

    @Test
    public void testInvalidPropertyInFileThrowsConfigurationException() throws IOException
    {
        File file = givenFile("invalid.yaml", "no_such_property: 1\n");
        Properties properties = new Properties();
        properties.put(AuditYamlConfigurationLoader.PROPERTY_CONFIG_FILE, file.getPath());

        AuditYamlConfigurationLoader loader = AuditYamlConfigurationLoader.withProperties(properties);

        assertThatExceptionOfType(ConfigurationException.class)
        .isThrownBy(loader::loadConfig)
        .withMessage("Invalid configuration file");
    }

    @Test
    public void testMalformedFileThrowsConfigurationException() throws IOException
    {
        File file = givenFile("malformed.yaml", "whitelist: [User1\n");
        Properties properties = new Properties();
        properties.put(AuditYamlConfigurationLoader.PROPERTY_CONFIG_FILE, file.getPath());

        AuditYamlConfigurationLoader loader = AuditYamlConfigurationLoader.withProperties(properties);

        assertThatExceptionOfType(ConfigurationException.class)
        .isThrownBy(loader::loadConfig)
        .withMessage("Invalid configuration file");
    }

    @Test
    public void testCustomPathFromSystemProperties()
    {
        String previous = System.getProperty(AuditYamlConfigurationLoader.PROPERTY_CONFIG_FILE);
        System.setProperty(AuditYamlConfigurationLoader.PROPERTY_CONFIG_FILE, getPath("mock_configuration.yaml"));
        try
        {
            AuditYamlConfig config = AuditYamlConfigurationLoader.withSystemProperties().loadConfig();

            assertThat(config.isFromFile()).isTrue();
            assertThat(config.getWhitelist()).containsOnly("User1", "User2");
        }
        finally
        {
            if (previous == null)
            {
                System.clearProperty(AuditYamlConfigurationLoader.PROPERTY_CONFIG_FILE);
            }
            else
            {
                System.setProperty(AuditYamlConfigurationLoader.PROPERTY_CONFIG_FILE, previous);
            }
        }
    }

    @Test
    public void testConfigAtDefaultPathIsLoaded() throws IOException
    {
        File directory = temporaryFolder.newFolder();
        givenFile(directory, "audit.yaml", "whitelist:\n  - DefaultUser\nwrapped_authenticator: MyAuthenticator\n");

        try (URLClassLoader classLoader = new URLClassLoader(new URL[]{ directory.toURI().toURL() }, null))
        {
            AuditYamlConfig config = loadWithContextClassLoader(new Properties(), classLoader);

            assertThat(config.isFromFile()).isTrue();
            assertThat(config.getWhitelist()).containsOnly("DefaultUser");
            assertThat(config.getWrappedAuthenticator()).isEqualTo("MyAuthenticator");
        }
    }

    @Test
    public void testEmptyConfigAtDefaultPathGivesDefaults() throws IOException
    {
        File directory = temporaryFolder.newFolder();
        givenFile(directory, "audit.yaml", "");

        try (URLClassLoader classLoader = new URLClassLoader(new URL[]{ directory.toURI().toURL() }, null))
        {
            AuditYamlConfig config = loadWithContextClassLoader(new Properties(), classLoader);

            assertThat(config.isFromFile()).isTrue();
            assertThat(config.getWhitelist()).isEmpty();
        }
    }

    @Test
    public void testCustomPathTakesPrecedenceOverDefaultPath() throws IOException
    {
        File directory = temporaryFolder.newFolder();
        givenFile(directory, "audit.yaml", "whitelist:\n  - DefaultUser\n");

        try (URLClassLoader classLoader = new URLClassLoader(new URL[]{ directory.toURI().toURL() }, null))
        {
            AuditYamlConfig config = loadWithContextClassLoader(getProperties("mock_configuration.yaml"), classLoader);

            assertThat(config.getWhitelist()).containsOnly("User1", "User2");
        }
    }

    @Test
    public void testNoConfigFileGivesConfigWithoutFile()
    {
        ClassLoader emptyClassLoader = new URLClassLoader(new URL[0], null);

        AuditYamlConfig config = loadWithContextClassLoader(new Properties(), emptyClassLoader);

        assertThat(config.isFromFile()).isFalse();
    }

    @Test
    public void testUnreadableDefaultConfigThrowsAssertionError()
    {
        IOException readFailure = new IOException("Read failure");
        ClassLoader classLoader = new ClassLoader(null)
        {
            @Override
            public URL getResource(String name)
            {
                return givenUnreadableUrl(readFailure);
            }
        };

        assertThatExceptionOfType(AssertionError.class)
        .isThrownBy(() -> loadWithContextClassLoader(new Properties(), classLoader))
        .withCause(readFailure);
    }

    private static AuditYamlConfig loadWithContextClassLoader(Properties properties, ClassLoader classLoader)
    {
        Thread thread = Thread.currentThread();
        ClassLoader original = thread.getContextClassLoader();
        thread.setContextClassLoader(classLoader);
        try
        {
            return AuditYamlConfigurationLoader.withProperties(properties).loadConfig();
        }
        finally
        {
            thread.setContextClassLoader(original);
        }
    }

    private static URL givenUnreadableUrl(IOException readFailure)
    {
        try
        {
            return new URL(null, "unreadable:audit.yaml", new URLStreamHandler()
            {
                @Override
                protected URLConnection openConnection(URL url)
                {
                    return new URLConnection(url)
                    {
                        @Override
                        public void connect()
                        {
                            // Nothing to connect
                        }

                        @Override
                        public InputStream getInputStream() throws IOException
                        {
                            throw readFailure;
                        }
                    };
                }
            });
        }
        catch (IOException e)
        {
            throw new AssertionError(e);
        }
    }

    private File givenFile(String fileName, String content) throws IOException
    {
        return givenFile(temporaryFolder.getRoot(), fileName, content);
    }

    private static File givenFile(File directory, String fileName, String content) throws IOException
    {
        File file = new File(directory, fileName);
        Files.write(file.toPath(), content.getBytes(StandardCharsets.UTF_8));
        return file;
    }

    private static String getPath(String fileName)
    {
        return TestAuditYamlConfigurationLoader.class.getResource("/" + fileName).getPath();
    }

    private AuditConfig givenLoadedConfig(Properties properties)
    {
        AuditYamlConfigurationLoader loader = AuditYamlConfigurationLoader.withProperties(properties);
        return new AuditConfig(loader);
    }

    private AuditConfig givenLoadedDefaultConfig()
    {
        AuditYamlConfigurationLoader loader = AuditYamlConfigurationLoader.withSystemProperties();
        return new AuditConfig(loader);
    }

    private static Properties getProperties(String fileName)
    {
        URL url = TestAuditYamlConfigurationLoader.class.getResource("/" + fileName);
        Properties properties = new Properties();
        properties.put(AuditYamlConfigurationLoader.PROPERTY_CONFIG_FILE, url.getPath());

        return properties;
    }
}