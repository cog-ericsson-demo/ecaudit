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
package com.ericsson.bss.cassandra.ecaudit.common.formatter;

import java.util.Collection;

/**
 * Escapes client controlled field values before they are written to a log or a terminal.
 * <p>
 * Control characters are always replaced with visible escape sequences so that a single record can never be
 * split into several lines or manipulate a terminal. CR and LF become {@code \r} and {@code \n}, other control
 * characters (C0 except tab, DEL, C1) and the Unicode line/paragraph separators become {@code \}{@code uXXXX}.
 * <p>
 * Optionally a set of additional characters (e.g. field separators) can be escaped with a backslash. In that case
 * backslash itself is escaped first, so that escaped output cannot be confused with literal input.
 */
public final class FieldEscaper
{
    private static final char BACKSLASH = '\\';

    private FieldEscaper()
    {
        // Utility class
    }

    /**
     * Escape the given characters with a backslash and then escape all control characters.
     *
     * @param value            the value to escape, may be {@code null}
     * @param escapeCharacters additional characters/strings to escape with a backslash
     * @return the escaped value, or {@code null} if value is {@code null}
     */
    public static String escape(String value, Collection<String> escapeCharacters)
    {
        if (value == null)
        {
            return null;
        }
        return escapeControlCharacters(escapeCharacters(value, escapeCharacters));
    }

    /**
     * Escape the given characters/strings with a backslash, escaping backslash itself as well.
     * The characters are matched literally, and every position where one of them starts is escaped,
     * so that overlapping escape strings are all escaped.
     *
     * @param value            the value to escape, may be {@code null}
     * @param escapeCharacters characters/strings to escape, if empty the value is returned unchanged
     * @return the escaped value, or {@code null} if value is {@code null}
     */
    public static String escapeCharacters(String value, Collection<String> escapeCharacters)
    {
        if (value == null || escapeCharacters == null || escapeCharacters.isEmpty())
        {
            return value;
        }
        StringBuilder builder = new StringBuilder(value.length() + 16);
        for (int i = 0; i < value.length(); i++)
        {
            char c = value.charAt(i);
            if (c == BACKSLASH || startsWithAny(value, i, escapeCharacters))
            {
                builder.append(BACKSLASH);
            }
            builder.append(c);
        }
        return builder.toString();
    }

    private static boolean startsWithAny(String value, int offset, Collection<String> candidates)
    {
        for (String candidate : candidates)
        {
            if (!candidate.isEmpty() && value.startsWith(candidate, offset))
            {
                return true;
            }
        }
        return false;
    }

    /**
     * Replace control characters with visible escape sequences.
     *
     * @param value the value to escape, may be {@code null}
     * @return the escaped value, or {@code null} if value is {@code null}
     */
    public static String escapeControlCharacters(String value)
    {
        if (value == null || !containsControlCharacter(value))
        {
            return value;
        }
        StringBuilder builder = new StringBuilder(value.length() + 16);
        for (int i = 0; i < value.length(); i++)
        {
            char c = value.charAt(i);
            if (c == '\n')
            {
                builder.append("\\n");
            }
            else if (c == '\r')
            {
                builder.append("\\r");
            }
            else if (isControlCharacter(c))
            {
                builder.append(String.format("\\u%04x", (int) c));
            }
            else
            {
                builder.append(c);
            }
        }
        return builder.toString();
    }

    private static boolean containsControlCharacter(String value)
    {
        for (int i = 0; i < value.length(); i++)
        {
            if (isControlCharacter(value.charAt(i)))
            {
                return true;
            }
        }
        return false;
    }

    private static boolean isControlCharacter(char c)
    {
        return (c < 0x20 && c != '\t')
               || (c >= 0x7F && c <= 0x9F)
               || c == '\u2028'
               || c == '\u2029';
    }
}
