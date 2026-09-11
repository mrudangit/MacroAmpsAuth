package com.example.ampsauth;

import java.time.Duration;
import java.util.ArrayList;
import java.util.List;

import javax.naming.AuthenticationException;
import javax.naming.CommunicationException;
import javax.naming.NamingException;
import javax.naming.ServiceUnavailableException;
import javax.naming.directory.DirContext;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.springframework.boot.test.system.CapturedOutput;
import org.springframework.boot.test.system.OutputCaptureExtension;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;

@ExtendWith(OutputCaptureExtension.class)
class LdapCredentialValidatorTest {

    private static final String URL = "ldaps://ldap.example.com:636";
    private static final String SECRET = "pw-never-logged-7f3a";

    /** Records every bind and either returns a context or throws the configured exception. */
    static final class FakeDirContextFactory implements DirContextFactory {
        final List<String> principals = new ArrayList<>();
        final List<String> passwords = new ArrayList<>();
        DirContext context = mock(DirContext.class);
        NamingException failure;
        RuntimeException runtimeFailure;

        @Override
        public DirContext bind(String principal, String password) throws NamingException {
            principals.add(principal);
            passwords.add(password);
            if (failure != null) {
                throw failure;
            }
            if (runtimeFailure != null) {
                throw runtimeFailure;
            }
            return context;
        }
    }

    private static AmpsProperties.Ldap config(String pattern) {
        return new AmpsProperties.Ldap(URL, pattern, Duration.ofMillis(1000), Duration.ofMillis(2000), true);
    }

    @Test
    void successfulBindIsValidAndContextIsClosed() throws NamingException {
        var factory = new FakeDirContextFactory();
        var validator = new LdapCredentialValidator(config("{0}@corp.example.com"), factory);

        assertThat(validator.validate("jdoe", "pw")).isEqualTo(ValidationResult.VALID);

        verify(factory.context).close();
        assertThat(factory.passwords).containsExactly("pw");
    }

    @Test
    void closeFailureAfterSuccessfulBindIsStillValid() throws NamingException {
        var factory = new FakeDirContextFactory();
        doThrow(new NamingException("close failed")).when(factory.context).close();
        var validator = new LdapCredentialValidator(config("{0}@corp.example.com"), factory);

        assertThat(validator.validate("jdoe", "pw")).isEqualTo(ValidationResult.VALID);
    }

    @Test
    void authenticationExceptionIsInvalid() {
        var factory = new FakeDirContextFactory();
        factory.failure = new AuthenticationException("[LDAP: error code 49 - 80090308: LdapErr: DSID-0C09044E, data 52e]");
        var validator = new LdapCredentialValidator(config("{0}@corp.example.com"), factory);

        assertThat(validator.validate("jdoe", "wrong")).isEqualTo(ValidationResult.INVALID);
    }

    @Test
    void communicationExceptionIsBackendUnavailable() {
        var factory = new FakeDirContextFactory();
        factory.failure = new CommunicationException("ldap.example.com:636");
        var validator = new LdapCredentialValidator(config("{0}@corp.example.com"), factory);

        assertThat(validator.validate("jdoe", "pw")).isEqualTo(ValidationResult.BACKEND_UNAVAILABLE);
    }

    @Test
    void genericNamingExceptionIsBackendUnavailable() {
        var factory = new FakeDirContextFactory();
        factory.failure = new NamingException("LDAP response read timed out, timeout used: 2000 ms.");
        var validator = new LdapCredentialValidator(config("{0}@corp.example.com"), factory);

        assertThat(validator.validate("jdoe", "pw")).isEqualTo(ValidationResult.BACKEND_UNAVAILABLE);
    }

    @Test
    void namingExceptionSubclassesOtherThanAuthenticationAreBackendUnavailable() {
        var factory = new FakeDirContextFactory();
        factory.failure = new ServiceUnavailableException("server shutting down");
        var validator = new LdapCredentialValidator(config("{0}@corp.example.com"), factory);

        assertThat(validator.validate("jdoe", "pw")).isEqualTo(ValidationResult.BACKEND_UNAVAILABLE);
    }

    @Test
    void runtimeExceptionIsBackendUnavailable() {
        var factory = new FakeDirContextFactory();
        factory.runtimeFailure = new IllegalStateException("boom");
        var validator = new LdapCredentialValidator(config("{0}@corp.example.com"), factory);

        assertThat(validator.validate("jdoe", "pw")).isEqualTo(ValidationResult.BACKEND_UNAVAILABLE);
    }

    @Test
    void principalPatternSubstitutesUsernameForUpn() {
        var factory = new FakeDirContextFactory();
        var validator = new LdapCredentialValidator(config("{0}@corp.example.com"), factory);

        validator.validate("jdoe", "pw");

        assertThat(factory.principals).containsExactly("jdoe@corp.example.com");
    }

    @Test
    void principalPatternSubstitutesUsernameForDn() {
        var factory = new FakeDirContextFactory();
        var validator = new LdapCredentialValidator(config("uid={0},ou=people,dc=example,dc=com"), factory);

        validator.validate("o'brien", "pw");

        assertThat(factory.principals).containsExactly("uid=o'brien,ou=people,dc=example,dc=com");
    }

    @Test
    void emptyPasswordNeverReachesTheFactory() {
        var factory = new FakeDirContextFactory();
        var validator = new LdapCredentialValidator(config("{0}@corp.example.com"), factory);

        assertThat(validator.validate("jdoe", "")).isEqualTo(ValidationResult.INVALID);
        assertThat(validator.validate("jdoe", null)).isEqualTo(ValidationResult.INVALID);
        assertThat(validator.validate("", "pw")).isEqualTo(ValidationResult.INVALID);

        assertThat(factory.principals).isEmpty();
    }

    @Test
    void backendFailureIsLoggedAtErrorWithStackTraceButWithoutThePassword(CapturedOutput output) {
        var factory = new FakeDirContextFactory();
        factory.failure = new CommunicationException("ldap.example.com:636");
        var validator = new LdapCredentialValidator(config("{0}@corp.example.com"), factory);

        validator.validate("jdoe", SECRET);

        assertThat(output.getAll())
                .contains("ERROR")
                .contains("LDAP server unreachable url=" + URL + " principal=jdoe@corp.example.com")
                .contains("javax.naming.CommunicationException")
                .doesNotContain(SECRET);
    }

    @Test
    void rejectedBindIsLoggedAtDebugWithTheServerReasonButWithoutThePassword(CapturedOutput output) {
        var factory = new FakeDirContextFactory();
        factory.failure = new AuthenticationException("[LDAP: error code 49 - data 52e]");
        var validator = new LdapCredentialValidator(config("{0}@corp.example.com"), factory);

        // The effective level depends on which tests ran earlier in this JVM; pin it for this check.
        ch.qos.logback.classic.Logger logger =
                (ch.qos.logback.classic.Logger) org.slf4j.LoggerFactory.getLogger(LdapCredentialValidator.class);
        ch.qos.logback.classic.Level previous = logger.getLevel();
        logger.setLevel(ch.qos.logback.classic.Level.DEBUG);
        try {
            validator.validate("jdoe", SECRET);
        } finally {
            logger.setLevel(previous);
        }

        // The server diagnostic goes through the log sanitiser, so whitespace is rendered as '_'.
        assertThat(output.getAll())
                .contains("LDAP bind rejected principal=jdoe@corp.example.com reason=[LDAP:_error_code_49_-_data_52e]")
                .doesNotContain(SECRET)
                .doesNotContain("ERROR");
    }

    @Test
    void plainLdapUrlLogsAWarningLdapsDoesNot(CapturedOutput output) {
        new LdapCredentialValidator(
                new AmpsProperties.Ldap("ldap://ldap.example.com:389", "{0}@corp.example.com",
                        Duration.ofSeconds(1), Duration.ofSeconds(2), true), new FakeDirContextFactory());
        assertThat(output.getAll()).contains("WARN").contains("clear text");

        long warningsBefore = output.getAll().lines().filter(l -> l.contains("clear text")).count();
        new LdapCredentialValidator(config("{0}@corp.example.com"), new FakeDirContextFactory());
        assertThat(output.getAll().lines().filter(l -> l.contains("clear text")).count()).isEqualTo(warningsBefore);
    }

    @Test
    void constructorRejectsPatternWithoutPlaceholder() {
        assertThatThrownBy(() -> new LdapCredentialValidator(config("jdoe@corp.example.com"), new FakeDirContextFactory()))
                .isInstanceOf(IllegalStateException.class)
                .hasMessageContaining("user-principal-pattern");
    }

    @Test
    void constructorRejectsMissingUrl() {
        var config = new AmpsProperties.Ldap(" ", "{0}@corp.example.com", Duration.ofSeconds(1), Duration.ofSeconds(2), true);

        assertThatThrownBy(() -> new LdapCredentialValidator(config, new FakeDirContextFactory()))
                .isInstanceOf(IllegalStateException.class)
                .hasMessageContaining("amps.auth.ldap.url");
    }
}
