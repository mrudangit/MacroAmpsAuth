package com.example.ampsauth.auth;

import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;

class LogSanitizerTest {

    @Test
    void nullAndEmptyBecomeDash() {
        assertThat(LogSanitizer.clean(null)).isEqualTo("-");
        assertThat(LogSanitizer.clean("")).isEqualTo("-");
    }

    @Test
    void ordinaryValuesPassThrough() {
        assertThat(LogSanitizer.clean("trader1")).isEqualTo("trader1");
        assertThat(LogSanitizer.clean("jdoe@corp.example.com")).isEqualTo("jdoe@corp.example.com");
        assertThat(LogSanitizer.clean("MacroDesktop-jdoe")).isEqualTo("MacroDesktop-jdoe");
        assertThat(LogSanitizer.clean("händler-日本")).isEqualTo("händler-日本");
    }

    @Test
    void equalsSignCannotForgeAnotherToken() {
        assertThat(LogSanitizer.clean("uid=x,ou=people")).isEqualTo("uid_x,ou_people");
        assertThat(LogSanitizer.clean("evil outcome=SUCCESS")).isEqualTo("evil_outcome_SUCCESS");
    }

    @Test
    void whitespaceAndControlCharactersAreNeutralised() {
        assertThat(LogSanitizer.clean("a\tb c d")).isEqualTo("a_b_c_d");
        assertThat(LogSanitizer.clean("a\r\nINJECTED")).isEqualTo("a__INJECTED");
        assertThat(LogSanitizer.clean("abc")).isEqualTo("a_b_c");
    }

    @Test
    void unicodeLineSeparatorsAreNeutralised() {
        assertThat(LogSanitizer.clean("a b c")).isEqualTo("a_b_c");
    }

    @Test
    void formatAndBidiCharactersAreNeutralised() {
        // right-to-left override, zero-width space, left-to-right isolate, soft hyphen
        assertThat(LogSanitizer.clean("a‮b​c⁦d­e")).isEqualTo("a_b_c_d_e");
    }

    @Test
    void longValuesAreTruncatedWithEllipsis() {
        String value = "x".repeat(200);

        assertThat(LogSanitizer.clean(value)).hasSize(LogSanitizer.DEFAULT_MAX_LENGTH + 3).endsWith("...");
        assertThat(LogSanitizer.clean("x".repeat(128))).hasSize(128).doesNotEndWith("...");
        assertThat(LogSanitizer.clean(value, 10)).isEqualTo("xxxxxxxxxx...");
    }

    @Test
    void truncationDoesNotSplitASurrogatePair() {
        String value = "ab😀cd"; // ab, U+1F600 (grinning face), cd

        assertThat(LogSanitizer.clean(value, 3)).isEqualTo("ab...");
        assertThat(LogSanitizer.clean(value, 4)).isEqualTo("ab😀...");
    }
}
