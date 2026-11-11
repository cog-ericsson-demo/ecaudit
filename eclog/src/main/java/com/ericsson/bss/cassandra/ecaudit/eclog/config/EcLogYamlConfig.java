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
package com.ericsson.bss.cassandra.ecaudit.eclog.config;

import java.time.DateTimeException;
import java.time.ZoneId;
import java.time.format.DateTimeFormatter;
import java.util.Collections;
import java.util.LinkedHashSet;
import java.util.Optional;
import java.util.Set;

@SuppressWarnings("PMD.FieldNamingConventions")
public class EcLogYamlConfig
{
    static final String DEFAULT_FORMAT = "{?${TIMESTAMP}?}{?|${CLIENT_IP}?}{?:${CLIENT_PORT}?}{?|${COORDINATOR_IP}?}{?|${USER}?}{?|${STATUS}?}{?|${BATCH_ID}?}{?|${OPERATION}?}";
    static final String DEFAULT_ESCAPE_CHARACTERS = "|";

    // Configuration parameters - has to be public for SnakeYaml to inject values
    public String log_format;
    public String time_format;
    public String time_zone;
    public String escape_characters;

    public String getLogFormat()
    {
        return log_format == null ? DEFAULT_FORMAT : log_format;
    }

    /**
     * Characters to escape with a backslash in USER, OPERATION and OPERATION_NAKED, in addition to control characters
     * which are always escaped. Defaults to the field separator of the default log format.
     *
     * @return the set of characters to escape
     */
    public Set<String> getEscapeCharacters()
    {
        String escape = escape_characters == null ? DEFAULT_ESCAPE_CHARACTERS : escape_characters;
        Set<String> escapeChars = new LinkedHashSet<>();
        for (String escapeChar : escape.split(","))
        {
            String trimmed = escapeChar.trim();
            if (!trimmed.isEmpty())
            {
                escapeChars.add(trimmed);
            }
        }
        return Collections.unmodifiableSet(escapeChars);
    }

    public Optional<DateTimeFormatter> getTimeFormatter()
    {
        return Optional.ofNullable(time_format)
                       .map(EcLogYamlConfig::createTimeFormatter)
                       .map(formatter -> formatter.withZone(resolveZoneId(time_zone)));
    }

    private static DateTimeFormatter createTimeFormatter(String format)
    {
        try
        {
            return DateTimeFormatter.ofPattern(format);
        }
        catch (IllegalArgumentException e)
        {
            throw new IllegalArgumentException("Invalid time format parameter: " + format, e);
        }
    }

    private ZoneId resolveZoneId(String timeZone) throws IllegalArgumentException
    {
        try
        {
            return Optional.ofNullable(timeZone)
                           .map(ZoneId::of)
                           .orElse(ZoneId.systemDefault());
        }
        catch (DateTimeException e)
        {
            throw new IllegalArgumentException("Invalid time zone parameter: " + timeZone, e);
        }
    }
}
