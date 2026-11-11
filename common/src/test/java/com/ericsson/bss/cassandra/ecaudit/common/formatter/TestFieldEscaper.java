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

import java.util.Arrays;
import java.util.Collections;

import org.junit.Test;

import static org.assertj.core.api.Assertions.assertThat;

public class TestFieldEscaper
{
    @Test
    public void testNullIsKeptNull()
    {
        assertThat(FieldEscaper.escape(null, Collections.singleton("|"))).isNull();
        assertThat(FieldEscaper.escapeControlCharacters(null)).isNull();
        assertThat(FieldEscaper.escapeCharacters(null, Collections.singleton("|"))).isNull();
    }

    @Test
    public void testPlainValueIsUnchanged()
    {
        String value = "select * from ks.tbl where a = 'b\\c'\tand d = 'é'";
        assertThat(FieldEscaper.escape(value, Collections.emptySet())).isSameAs(value);
    }

    @Test
    public void testNewlinesAndCarriageReturnsAreEscaped()
    {
        assertThat(FieldEscaper.escapeControlCharacters("a\nclient:'1.2.3.4'|user:'bob'\r\n"))
        .isEqualTo("a\\nclient:'1.2.3.4'|user:'bob'\\r\\n");
    }

    @Test
    public void testOtherControlCharactersAreEscaped()
    {
        assertThat(FieldEscaper.escapeControlCharacters("x\u0000\u001b[8m\u007f\u0085\u009b\u2028\u2029\ty"))
        .isEqualTo("x\\u0000\\u001b[8m\\u007f\\u0085\\u009b\\u2028\\u2029\ty");
    }

    @Test
    public void testEscapeCharactersAreMatchedLiterally()
    {
        assertThat(FieldEscaper.escapeCharacters("a|b", Collections.singleton("|"))).isEqualTo("a\\|b");
        assertThat(FieldEscaper.escapeCharacters("a.b*c", Arrays.asList(".", "*"))).isEqualTo("a\\.b\\*c");
    }

    @Test
    public void testBackslashIsEscapedFirstWhenEscapingCharacters()
    {
        assertThat(FieldEscaper.escapeCharacters("a\\|b", Collections.singleton("|"))).isEqualTo("a\\\\\\|b");
        assertThat(FieldEscaper.escapeCharacters("a\\b", Collections.singleton("\\"))).isEqualTo("a\\\\b");
    }

    @Test
    public void testEscapeCombinesCharactersAndControlCharacters()
    {
        assertThat(FieldEscaper.escape("x\n1|2\u001b", Collections.singleton("|"))).isEqualTo("x\\n1\\|2\\u001b");
    }

    @Test
    public void testOverlappingEscapeCharactersAreAllEscaped()
    {
        assertThat(FieldEscaper.escapeCharacters("ab", Arrays.asList("ab", "a"))).isEqualTo("\\ab");
        assertThat(FieldEscaper.escapeCharacters("ab", Arrays.asList("a", "ab"))).isEqualTo("\\ab");
        assertThat(FieldEscaper.escapeCharacters("x|bob", Arrays.asList("x|", "|"))).isEqualTo("\\x\\|bob");
        assertThat(FieldEscaper.escapeCharacters("aab", Collections.singleton("ab"))).isEqualTo("a\\ab");
    }
}
