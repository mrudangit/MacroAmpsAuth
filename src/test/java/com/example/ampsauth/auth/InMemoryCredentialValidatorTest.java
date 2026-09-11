package com.example.ampsauth.auth;

import java.util.List;

import com.example.ampsauth.config.AmpsProperties;

import org.junit.jupiter.api.Test;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.factory.PasswordEncoderFactories;
import org.springframework.security.crypto.password.PasswordEncoder;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.spy;
import static org.mockito.Mockito.verify;

class InMemoryCredentialValidatorTest {

    /** A real bcrypt hash of "correct horse" (low cost so the tests stay fast; the cost is encoded in the hash). */
    private static final String BCRYPT_HASH = "{bcrypt}" + new BCryptPasswordEncoder(4).encode("correct horse");

    private final PasswordEncoder encoder = PasswordEncoderFactories.createDelegatingPasswordEncoder();

    private static AmpsProperties.InMemory users(boolean allowPlaintext, AmpsProperties.User... users) {
        return new AmpsProperties.InMemory(allowPlaintext, List.of(users));
    }

    private static AmpsProperties.User user(String name, String password) {
        return new AmpsProperties.User(name, password);
    }

    @Test
    void validBcryptPassword() {
        var validator = new InMemoryCredentialValidator(users(false, user("trader1", BCRYPT_HASH)), encoder);

        assertThat(validator.validate("trader1", "correct horse")).isEqualTo(ValidationResult.VALID);
    }

    @Test
    void validNoopPasswordWhenPlaintextAllowed() {
        var validator = new InMemoryCredentialValidator(users(true, user("trader1", "{noop}secret")), encoder);

        assertThat(validator.validate("trader1", "secret")).isEqualTo(ValidationResult.VALID);
    }

    @Test
    void wrongPasswordIsInvalid() {
        var validator = new InMemoryCredentialValidator(users(false, user("trader1", BCRYPT_HASH)), encoder);

        assertThat(validator.validate("trader1", "wrong")).isEqualTo(ValidationResult.INVALID);
        assertThat(validator.validate("trader1", "correct horse ")).isEqualTo(ValidationResult.INVALID);
    }

    @Test
    void unknownUserIsInvalid() {
        var validator = new InMemoryCredentialValidator(users(false, user("trader1", BCRYPT_HASH)), encoder);

        assertThat(validator.validate("nobody", "correct horse")).isEqualTo(ValidationResult.INVALID);
    }

    @Test
    void unknownUserStillPaysForAHashComparison() {
        PasswordEncoder spied = spy(encoder);
        var validator = new InMemoryCredentialValidator(users(false, user("trader1", BCRYPT_HASH)), spied);

        validator.validate("nobody", "whatever");

        verify(spied).matches(eq("whatever"), anyString());
    }

    @Test
    void usernameLookupIsCaseInsensitive() {
        var validator = new InMemoryCredentialValidator(users(false, user("Trader1", BCRYPT_HASH)), encoder);

        assertThat(validator.validate("TRADER1", "correct horse")).isEqualTo(ValidationResult.VALID);
        assertThat(validator.validate("trader1", "correct horse")).isEqualTo(ValidationResult.VALID);
    }

    @Test
    void emptyUsernameOrPasswordIsInvalidWithoutHashing() {
        var validator = new InMemoryCredentialValidator(users(true, user("trader1", "{noop}secret")), encoder);

        assertThat(validator.validate("", "secret")).isEqualTo(ValidationResult.INVALID);
        assertThat(validator.validate("trader1", "")).isEqualTo(ValidationResult.INVALID);
        assertThat(validator.validate(null, null)).isEqualTo(ValidationResult.INVALID);
    }

    @Test
    void startupRejectsNoopWhenPlaintextNotAllowed() {
        assertThatThrownBy(() -> new InMemoryCredentialValidator(users(false, user("trader1", "{noop}secret")), encoder))
                .isInstanceOf(IllegalStateException.class)
                .hasMessageContaining("trader1")
                .hasMessageContaining("allow-plaintext")
                .satisfies(e -> assertThat(e.getMessage()).doesNotContain("secret"));
    }

    @Test
    void startupRejectsDuplicateUsernamesIgnoringCase() {
        assertThatThrownBy(() -> new InMemoryCredentialValidator(
                users(false, user("trader1", BCRYPT_HASH), user("TRADER1", BCRYPT_HASH)), encoder))
                .isInstanceOf(IllegalStateException.class)
                .hasMessageContaining("duplicate username");
    }

    @Test
    void startupRejectsPasswordWithoutEncoderId() {
        assertThatThrownBy(() -> new InMemoryCredentialValidator(users(true, user("trader1", "secret")), encoder))
                .isInstanceOf(IllegalStateException.class)
                .hasMessageContaining("encoder id")
                .satisfies(e -> assertThat(e.getMessage()).doesNotContain("secret"));
    }

    @Test
    void startupRejectsMalformedBcryptHash() {
        assertThatThrownBy(() -> new InMemoryCredentialValidator(
                users(false, user("trader2", "{bcrypt}$2a$10$REPLACE_WITH_HASH_FROM_TOOL")), encoder))
                .isInstanceOf(IllegalStateException.class)
                .hasMessageContaining("not a valid bcrypt hash");
    }

    @Test
    void startupRejectsUnknownEncoderId() {
        assertThatThrownBy(() -> new InMemoryCredentialValidator(users(true, user("trader1", "{rot13}frperg")), encoder))
                .isInstanceOf(IllegalStateException.class)
                .hasMessageContaining("unsupported encoder id");
    }

    @Test
    void startupRejectsBlankUsernameOrPassword() {
        assertThatThrownBy(() -> new InMemoryCredentialValidator(users(true, user(" ", "{noop}x")), encoder))
                .isInstanceOf(IllegalStateException.class)
                .hasMessageContaining("username");
        assertThatThrownBy(() -> new InMemoryCredentialValidator(users(true, user("trader1", " ")), encoder))
                .isInstanceOf(IllegalStateException.class)
                .hasMessageContaining("password");
    }

    @Test
    void noUsersIsAllowedAndRejectsEverything() {
        var validator = new InMemoryCredentialValidator(new AmpsProperties.InMemory(false, List.of()), encoder);

        assertThat(validator.validate("trader1", "secret")).isEqualTo(ValidationResult.INVALID);
    }
}
