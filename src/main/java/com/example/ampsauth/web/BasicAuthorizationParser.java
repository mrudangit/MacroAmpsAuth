package com.example.ampsauth.web;

import java.nio.ByteBuffer;
import java.nio.charset.CharacterCodingException;
import java.nio.charset.CodingErrorAction;
import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.Optional;

import org.springframework.stereotype.Component;

/**
 * Parses an {@code Authorization: Basic <base64(username:password)>} header.
 * <ul>
 *   <li>null or blank header: {@link Optional#empty()} (no credentials at all)</li>
 *   <li>scheme compared case-insensitively; anything but {@code Basic} is malformed</li>
 *   <li>standard (not URL-safe) base64, decoded as strict UTF-8</li>
 *   <li>split at the <em>first</em> colon; passwords may contain colons</li>
 *   <li>nothing is trimmed: surrounding spaces in username or password are preserved</li>
 *   <li>empty username or empty password is malformed (never reaches a backend)</li>
 * </ul>
 * Exception messages are reason codes only and never include header content.
 */
@Component
public class BasicAuthorizationParser {

    private static final String BASIC = "Basic";
    private static final char SPACE = ' ';
    private static final char COLON = ':';

    public Optional<BasicCredentials> parse(String header) {
        if (header == null || header.isBlank()) {
            return Optional.empty();
        }
        String value = header.strip();
        int space = value.indexOf(SPACE);
        String scheme = space < 0 ? value : value.substring(0, space);
        if (!BASIC.equalsIgnoreCase(scheme)) {
            throw new MalformedCredentialsException("unsupported-scheme");
        }
        if (space < 0) {
            throw new MalformedCredentialsException("missing-token");
        }
        String token = value.substring(space + 1).strip();
        if (token.isEmpty()) {
            throw new MalformedCredentialsException("missing-token");
        }

        byte[] decoded;
        try {
            decoded = Base64.getDecoder().decode(token);
        } catch (IllegalArgumentException e) {
            throw new MalformedCredentialsException("invalid-base64");
        }

        String pair;
        try {
            pair = StandardCharsets.UTF_8.newDecoder()
                    .onMalformedInput(CodingErrorAction.REPORT)
                    .onUnmappableCharacter(CodingErrorAction.REPORT)
                    .decode(ByteBuffer.wrap(decoded))
                    .toString();
        } catch (CharacterCodingException e) {
            throw new MalformedCredentialsException("invalid-utf8");
        }

        int colon = pair.indexOf(COLON);
        if (colon < 0) {
            throw new MalformedCredentialsException("missing-colon");
        }
        String username = pair.substring(0, colon);
        String password = pair.substring(colon + 1);
        if (username.isEmpty()) {
            throw new MalformedCredentialsException("empty-username");
        }
        if (password.isEmpty()) {
            throw new MalformedCredentialsException("empty-password");
        }
        return Optional.of(new BasicCredentials(username, password));
    }
}
