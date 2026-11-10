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
package com.ericsson.bss.cassandra.ecaudit.obfuscator;

import java.util.Set;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import org.apache.cassandra.auth.IResource;
import org.apache.cassandra.auth.Permission;
import org.apache.cassandra.auth.RoleResource;

import com.ericsson.bss.cassandra.ecaudit.entry.AuditEntry;
import com.ericsson.bss.cassandra.ecaudit.common.record.SimpleAuditOperation;
import com.google.common.collect.ImmutableSet;
import com.google.common.collect.Sets;

/**
 * Implements an {@link AuditObfuscator} that obfuscated passwords,
 * if present, in the operation string of the {@link AuditEntry}.
 */
public class PasswordObfuscator implements AuditObfuscator
{
    private static final String PASSWORD_OBFUSCATED = "*****";
    private static final String QUOTED_PASSWORD_OBFUSCATED = "'" + PASSWORD_OBFUSCATED + "'";
    private static final String DOLLAR_QUOTED_PASSWORD_OBFUSCATED = "$$" + PASSWORD_OBFUSCATED + "$$";

    private static final String PASSWORD_KEYWORD = "password";

    private static final String GROUP_STRING = "string";
    private static final String GROUP_DOLLAR = "dollar";
    private static final String GROUP_IGNORABLE = "ignorable";
    private static final String GROUP_WORD = "word";
    private static final String GROUP_EQUALS = "equals";
    private static final String GROUP_STRING_END = "stringEnd";
    private static final String GROUP_DOLLAR_END = "dollarEnd";
    private static final String GROUP_IDENTIFIER_END = "identifierEnd";
    private static final String GROUP_COMMENT_END = "commentEnd";

    private static final String STRING_LITERAL_REGEX = "'(?:[^']++|'')*+" + namedGroup(GROUP_STRING_END, "'") + '?';
    private static final String DOLLAR_LITERAL_REGEX = "\\$\\$(?:.*?" + namedGroup(GROUP_DOLLAR_END, "\\$\\$") + "|.*+)";

    /**
     * Splits a CQL statement into tokens. String literals, dollar quoted literals, quoted identifiers
     * and comments are consumed as whole tokens so that their content is never mistaken for a keyword.
     * Unterminated literals, quoted identifiers and block comments extend to the end of the statement.
     */
    private static final Pattern TOKEN_PATTERN = Pattern.compile(
            namedGroup(GROUP_STRING, STRING_LITERAL_REGEX)
            + '|' + namedGroup(GROUP_DOLLAR, DOLLAR_LITERAL_REGEX)
            + '|' + namedGroup(GROUP_IGNORABLE,
                    "\\s++|--[^\\n]*+|//[^\\n]*+|/\\*(?:.*?" + namedGroup(GROUP_COMMENT_END, "\\*/") + "|.*+)")
            + '|' + namedGroup(GROUP_WORD, "\\w++")
            + '|' + namedGroup(GROUP_EQUALS, "=")
            + "|\"(?:[^\"]++|\"\")*+" + namedGroup(GROUP_IDENTIFIER_END, "\"") + '?'
            + "|.",
            Pattern.DOTALL);

    /**
     * Matches the PASSWORD keyword anywhere in a statement, including inside literals and identifiers,
     * when it is directly followed by a literal. Used as a fallback for statements with unbalanced quoting,
     * where the tokenized view may differ from what the author intended.
     */
    private static final Pattern RAW_PASSWORD_PATTERN =
            Pattern.compile("\\bpassword\\s*+=?\\s*+(?='|\\$\\$)", Pattern.CASE_INSENSITIVE);

    private static final Pattern LITERAL_PATTERN = Pattern.compile(
            namedGroup(GROUP_STRING, STRING_LITERAL_REGEX) + '|' + namedGroup(GROUP_DOLLAR, DOLLAR_LITERAL_REGEX),
            Pattern.DOTALL);

    private static final Set<Permission> PASSWORD_PERMISSIONS = ImmutableSet.of(Permission.CREATE, Permission.ALTER);

    @Override
    public AuditEntry obfuscate(AuditEntry entry)
    {
        if (shouldObfuscate(entry))
        {
            AuditEntry obfuscatedEntry = entry;

            String obfuscatedOperation = obfuscateOperation(entry.getOperation().getOperationString());
            if (!entry.getOperation().getOperationString().equals(obfuscatedOperation))
            {
                obfuscatedEntry = AuditEntry.newBuilder()
                        .basedOn(entry)
                        .operation(new SimpleAuditOperation(obfuscatedOperation))
                        .build();
            }
            return obfuscatedEntry;
        }

        return entry;
    }

    private boolean shouldObfuscate(AuditEntry entry)
    {
        return !entry.hasKnownOperation()
               || isRoleResource(entry.getResource()) && isPasswordPermission(entry.getPermissions());
    }

    private boolean isRoleResource(IResource resource)
    {
        return resource instanceof RoleResource;
    }

    private boolean isPasswordPermission(Set<Permission> permissions)
    {
        return !Sets.intersection(permissions, PASSWORD_PERMISSIONS).isEmpty();
    }

    /**
     * Obfuscate every password literal in the given query, if present.
     * A password literal is a string literal or dollar quoted literal following the PASSWORD keyword,
     * optionally separated by an equals sign. This covers both PASSWORD and HASHED PASSWORD options.
     *
     * <p>
     * If the statement ends in an unterminated literal, quoted identifier or block comment, the quoting is
     * unbalanced and the statement is rejected by Cassandra. For such statements every literal following
     * a PASSWORD keyword is also obfuscated regardless of quoting, possibly obfuscating more than the password.
     *
     * @param operation the query to obfuscate passwords in
     * @return a query with obfuscated passwords if present
     */
    private String obfuscateOperation(String operation)
    {
        String obfuscated = obfuscateTokenizedOperation(operation);
        return hasUnterminatedToken(operation) ? obfuscateRawOperation(obfuscated) : obfuscated;
    }

    private static boolean hasUnterminatedToken(String operation)
    {
        Matcher tokenMatcher = TOKEN_PATTERN.matcher(operation);
        boolean unterminated = false;
        while (tokenMatcher.find())
        {
            unterminated = isUnterminated(tokenMatcher);
        }
        return unterminated;
    }

    private static boolean isUnterminated(Matcher tokenMatcher)
    {
        String token = tokenMatcher.group();
        return token.startsWith("'") && tokenMatcher.group(GROUP_STRING_END) == null
               || token.startsWith("$$") && tokenMatcher.group(GROUP_DOLLAR_END) == null
               || token.startsWith("\"") && tokenMatcher.group(GROUP_IDENTIFIER_END) == null
               || token.startsWith("/*") && tokenMatcher.group(GROUP_COMMENT_END) == null;
    }

    private static String obfuscateTokenizedOperation(String operation)
    {
        StringBuilder obfuscated = new StringBuilder(operation.length());
        Matcher tokenMatcher = TOKEN_PATTERN.matcher(operation);
        boolean passwordExpected = false;
        boolean modified = false;

        while (tokenMatcher.find())
        {
            String token = tokenMatcher.group();
            if (passwordExpected && tokenMatcher.group(GROUP_STRING) != null)
            {
                obfuscated.append(QUOTED_PASSWORD_OBFUSCATED);
                modified = true;
                passwordExpected = false;
            }
            else if (passwordExpected && tokenMatcher.group(GROUP_DOLLAR) != null)
            {
                obfuscated.append(DOLLAR_QUOTED_PASSWORD_OBFUSCATED);
                modified = true;
                passwordExpected = false;
            }
            else
            {
                obfuscated.append(token);
                passwordExpected = isPasswordPrefix(tokenMatcher, passwordExpected);
            }
        }

        return modified ? obfuscated.toString() : operation;
    }

    private static String obfuscateRawOperation(String operation)
    {
        StringBuilder obfuscated = new StringBuilder(operation.length());
        Matcher keywordMatcher = RAW_PASSWORD_PATTERN.matcher(operation);
        Matcher literalMatcher = LITERAL_PATTERN.matcher(operation);
        int copied = 0;

        while (keywordMatcher.find())
        {
            int literalStart = keywordMatcher.end();
            literalMatcher.region(literalStart, operation.length());
            if (!literalMatcher.lookingAt())
            {
                continue;
            }

            if (literalStart >= copied)
            {
                obfuscated.append(operation, copied, literalStart)
                          .append(literalMatcher.group(GROUP_DOLLAR) == null
                                  ? QUOTED_PASSWORD_OBFUSCATED
                                  : DOLLAR_QUOTED_PASSWORD_OBFUSCATED);
            }
            copied = Math.max(copied, literalMatcher.end());
        }

        if (copied == 0)
        {
            return operation;
        }

        return obfuscated.append(operation.substring(copied)).toString();
    }

    private static String namedGroup(String name, String regex)
    {
        return "(?<" + name + ">" + regex + ")";
    }

    private static boolean isPasswordPrefix(Matcher tokenMatcher, boolean passwordExpected)
    {
        if (tokenMatcher.group(GROUP_WORD) != null)
        {
            return PASSWORD_KEYWORD.equalsIgnoreCase(tokenMatcher.group());
        }

        boolean separator = tokenMatcher.group(GROUP_IGNORABLE) != null || tokenMatcher.group(GROUP_EQUALS) != null;
        return passwordExpected && separator;
    }
}
