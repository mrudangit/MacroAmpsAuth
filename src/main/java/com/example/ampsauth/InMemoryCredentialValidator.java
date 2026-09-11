package com.example.ampsauth;

import java.util.HashMap;
import java.util.Locale;
import java.util.Map;
import java.util.UUID;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.crypto.password.PasswordEncoder;

/**
 * Users from {@code amps.auth.inmemory.users[]}, passwords in Spring's delegating-encoder format
 * ({@code {bcrypt}$2a$10$...} or, when {@code allow-plaintext=true}, {@code {noop}plaintext}).
 * <ul>
 *   <li>username lookup is case-insensitive</li>
 *   <li>unknown users still pay for one bcrypt comparison against a dummy hash, so response time does
 *       not reveal whether a user exists</li>
 *   <li>construction fails fast on {@code {noop}} without opt-in, duplicate usernames, blank values,
 *       unknown encoder ids and malformed bcrypt hashes</li>
 * </ul>
 */
final class InMemoryCredentialValidator implements CredentialValidator {

    private static final Logger log = LoggerFactory.getLogger(InMemoryCredentialValidator.class);

    private static final Pattern ENCODED_FORMAT = Pattern.compile("^\\{(?<id>[^{}]+)\\}(?<value>.+)$", Pattern.DOTALL);
    /** Same shape Spring's BCryptPasswordEncoder accepts; anything else could never be verified. */
    private static final Pattern BCRYPT_HASH = Pattern.compile("^\\$2[aby]?\\$\\d{2}\\$[./A-Za-z0-9]{53}$");
    private static final String NOOP = "noop";
    private static final String BCRYPT = "bcrypt";

    private final PasswordEncoder encoder;
    /** lower-cased username -> encoded password */
    private final Map<String, String> users;
    private final String dummyHash;

    public InMemoryCredentialValidator(AmpsProperties.InMemory config, PasswordEncoder encoder) {
        this.encoder = encoder;
        this.users = Map.copyOf(index(config, encoder));
        // A real hash in the same format as the configured ones; compared against for unknown users.
        this.dummyHash = encoder.encode("dummy-" + UUID.randomUUID());
        log.info("in-memory credential backend active with {} user(s)", users.size());
    }

    @Override
    public ValidationResult validate(String username, String password) {
        if (username == null || username.isEmpty() || password == null || password.isEmpty()) {
            return ValidationResult.INVALID;
        }
        String stored = users.get(normalize(username));
        if (stored == null) {
            // Same cost as a real comparison so timing does not reveal whether the user exists.
            encoder.matches(password, dummyHash);
            return ValidationResult.INVALID;
        }
        return encoder.matches(password, stored) ? ValidationResult.VALID : ValidationResult.INVALID;
    }

    private static Map<String, String> index(AmpsProperties.InMemory config, PasswordEncoder encoder) {
        Map<String, String> index = new HashMap<>();
        if (config.users() == null) {
            return index;
        }
        int i = 0;
        for (AmpsProperties.User user : config.users()) {
            String where = "amps.auth.inmemory.users[" + i++ + "]";
            if (user == null || user.username() == null || user.username().isBlank()) {
                throw new IllegalStateException(where + ".username must not be blank");
            }
            if (user.password() == null || user.password().isBlank()) {
                throw new IllegalStateException(where + ".password must not be blank (user '" + user.username() + "')");
            }
            checkEncoding(where, user, config.allowPlaintext(), encoder);
            String key = normalize(user.username());
            if (index.putIfAbsent(key, user.password()) != null) {
                throw new IllegalStateException(where + ": duplicate username '" + user.username()
                        + "' (usernames are compared case-insensitively)");
            }
        }
        return index;
    }

    private static void checkEncoding(String where, AmpsProperties.User user, boolean allowPlaintext,
            PasswordEncoder encoder) {
        Matcher matcher = ENCODED_FORMAT.matcher(user.password());
        if (!matcher.matches()) {
            throw new IllegalStateException(where + ".password for user '" + user.username()
                    + "' must start with an encoder id such as {bcrypt}; generate one with --hash-password");
        }
        String id = matcher.group("id");
        if (NOOP.equals(id) && !allowPlaintext) {
            throw new IllegalStateException(where + ".password for user '" + user.username()
                    + "' is plaintext ({noop}); hash it with --hash-password or set "
                    + "amps.auth.inmemory.allow-plaintext=true (local profile only)");
        }
        if (BCRYPT.equals(id) && !BCRYPT_HASH.matcher(matcher.group("value")).matches()) {
            throw new IllegalStateException(where + ".password for user '" + user.username()
                    + "' is not a valid bcrypt hash; generate one with --hash-password");
        }
        try {
            // Rejects unknown encoder ids ("There is no PasswordEncoder mapped for the id ...").
            encoder.matches("startup-probe", user.password());
        } catch (IllegalArgumentException e) {
            throw new IllegalStateException(where + ".password for user '" + user.username()
                    + "' uses an unsupported encoder id {" + id + "}", e);
        }
    }

    private static String normalize(String username) {
        return username.toLowerCase(Locale.ROOT);
    }
}
