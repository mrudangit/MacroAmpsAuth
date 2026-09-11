package com.example.ampsauth;

import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.Optional;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.NullAndEmptySource;
import org.junit.jupiter.params.provider.ValueSource;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

class BasicAuthorizationParserTest {

    private final BasicAuthorizationParser parser = new BasicAuthorizationParser();

    private static String basic(String pair) {
        return "Basic " + Base64.getEncoder().encodeToString(pair.getBytes(StandardCharsets.UTF_8));
    }

    @Test
    void validHeader() {
        Optional<BasicCredentials> credentials = parser.parse(basic("trader1:secret"));

        assertThat(credentials).contains(new BasicCredentials("trader1", "secret"));
    }

    @Test
    void passwordMayContainColons() {
        assertThat(parser.parse(basic("trader1:se:cr:et"))).contains(new BasicCredentials("trader1", "se:cr:et"));
    }

    @Test
    void nonAsciiUtf8UsernameAndPassword() {
        assertThat(parser.parse(basic("händleré:päss€wörd日本")))
                .contains(new BasicCredentials("händleré", "päss€wörd日本"));
    }

    @ParameterizedTest
    @NullAndEmptySource
    @ValueSource(strings = {" ", "\t", "   "})
    void missingOrBlankHeaderMeansNoCredentials(String header) {
        assertThat(parser.parse(header)).isEmpty();
    }

    @Test
    void bearerSchemeIsMalformed() {
        assertThatThrownBy(() -> parser.parse("Bearer abc.def.ghi"))
                .isInstanceOf(MalformedCredentialsException.class)
                .hasMessage("unsupported-scheme");
    }

    @ParameterizedTest
    @ValueSource(strings = {"basic", "BASIC", "bAsIc"})
    void schemeIsCaseInsensitive(String scheme) {
        String token = Base64.getEncoder().encodeToString("trader1:secret".getBytes(StandardCharsets.UTF_8));

        assertThat(parser.parse(scheme + " " + token)).contains(new BasicCredentials("trader1", "secret"));
    }

    @Test
    void schemeWithoutTokenIsMalformed() {
        assertThatThrownBy(() -> parser.parse("Basic")).isInstanceOf(MalformedCredentialsException.class);
        assertThatThrownBy(() -> parser.parse("Basic   ")).isInstanceOf(MalformedCredentialsException.class);
    }

    @ParameterizedTest
    @ValueSource(strings = {
            "Basic !!!not-base64!!!",          // characters outside the alphabet
            "Basic dHJhZGVy MTpzZWNyZXQ=",     // whitespace inside the token
            "Basic dHJhZGVyMTpzZWNyZXQ=x",     // data after the padding
            "Basic dHJhZGVyMTpz-WNyZXQ_"       // URL-safe alphabet ('-' and '_') is not accepted
    })
    void invalidBase64IsMalformed(String header) {
        assertThatThrownBy(() -> parser.parse(header))
                .isInstanceOf(MalformedCredentialsException.class)
                .hasMessage("invalid-base64");
    }

    @Test
    void missingPaddingIsToleratedByTheStandardDecoder() {
        // "dHJhZGVyMTpzZWNyZXQ" is "trader1:secret" without its trailing "="; the JDK decoder accepts it.
        assertThat(parser.parse("Basic dHJhZGVyMTpzZWNyZXQ")).contains(new BasicCredentials("trader1", "secret"));
    }

    @Test
    void urlSafeBase64AlphabetIsRejected() {
        // '-' and '_' belong to the URL-safe alphabet only; the standard decoder must reject them.
        assertThatThrownBy(() -> parser.parse("Basic dHJhZGVyMTpz-WNyZXQ_"))
                .isInstanceOf(MalformedCredentialsException.class)
                .hasMessage("invalid-base64");
    }

    @Test
    void invalidUtf8IsMalformed() {
        String token = Base64.getEncoder().encodeToString(new byte[] {'a', ':', (byte) 0xC3, (byte) 0x28});

        assertThatThrownBy(() -> parser.parse("Basic " + token))
                .isInstanceOf(MalformedCredentialsException.class)
                .hasMessage("invalid-utf8");
    }

    @Test
    void missingColonIsMalformed() {
        assertThatThrownBy(() -> parser.parse(basic("trader1")))
                .isInstanceOf(MalformedCredentialsException.class)
                .hasMessage("missing-colon");
    }

    @Test
    void emptyUsernameIsMalformed() {
        assertThatThrownBy(() -> parser.parse(basic(":secret")))
                .isInstanceOf(MalformedCredentialsException.class)
                .hasMessage("empty-username");
    }

    @Test
    void emptyPasswordIsMalformed() {
        assertThatThrownBy(() -> parser.parse(basic("trader1:")))
                .isInstanceOf(MalformedCredentialsException.class)
                .hasMessage("empty-password");
    }

    @Test
    void surroundingSpacesArePreservedNotTrimmed() {
        assertThat(parser.parse(basic(" trader1 : secret ")))
                .contains(new BasicCredentials(" trader1 ", " secret "));
    }

    @Test
    void whitespaceOnlyPasswordIsNotEmpty() {
        assertThat(parser.parse(basic("trader1:   "))).contains(new BasicCredentials("trader1", "   "));
    }

    @Test
    void headerWhitespaceAroundSchemeAndTokenIsTolerated() {
        String token = Base64.getEncoder().encodeToString("trader1:secret".getBytes(StandardCharsets.UTF_8));

        assertThat(parser.parse("  Basic   " + token + "  ")).contains(new BasicCredentials("trader1", "secret"));
    }

    @Test
    void exceptionMessagesNeverContainHeaderContent() {
        String header = "Bearer super-secret-token-value";

        assertThatThrownBy(() -> parser.parse(header))
                .isInstanceOf(MalformedCredentialsException.class)
                .satisfies(e -> assertThat(e.getMessage()).doesNotContain("super-secret"));
    }

    @Test
    void credentialsToStringMasksPassword() {
        assertThat(new BasicCredentials("trader1", "hunter2").toString())
                .contains("trader1")
                .doesNotContain("hunter2");
    }
}
