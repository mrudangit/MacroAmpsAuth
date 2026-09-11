package com.example.ampsauth.auth;

import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.util.Base64;
import java.util.List;
import java.util.Optional;

import com.example.ampsauth.config.AmpsProperties;
import com.example.ampsauth.web.BasicAuthorizationParser;

import io.micrometer.core.instrument.Meter;
import io.micrometer.core.instrument.Tag;
import io.micrometer.core.instrument.simple.SimpleMeterRegistry;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
class LogonServiceTest {

    private static final RequestMetadata META = new RequestMetadata("MacroDesktop-jdoe", "10.1.2.3", "json-tcp-17");

    @Mock
    private CredentialValidator validator;

    private SimpleMeterRegistry registry;

    private LogonService service;

    private static AmpsProperties properties(boolean usernamePathMustMatch) {
        return new AmpsProperties(
                new AmpsProperties.Auth(AmpsProperties.Backend.INMEMORY, usernamePathMustMatch,
                        new AmpsProperties.InMemory(false, List.of()),
                        new AmpsProperties.Ldap(null, null, Duration.ofSeconds(1), Duration.ofSeconds(2), true)),
                new AmpsProperties.Permissions("classpath:amps/permissions-logon-only.json"));
    }

    private static String basic(String pair) {
        return "Basic " + Base64.getEncoder().encodeToString(pair.getBytes(StandardCharsets.UTF_8));
    }

    @BeforeEach
    void setUp() {
        registry = new SimpleMeterRegistry();
        service = new LogonService(new BasicAuthorizationParser(), validator, properties(true), registry);
    }

    private double attempts(LogonOutcome outcome) {
        return registry.get(LogonService.ATTEMPTS_METRIC).tag(LogonService.OUTCOME_TAG, outcome.name()).counter().count();
    }

    private long timed(LogonOutcome outcome) {
        return registry.get(LogonService.DURATION_METRIC).tag(LogonService.OUTCOME_TAG, outcome.name()).timer().count();
    }

    @Test
    void missingHeaderIsNoCredentials() {
        assertThat(service.logon(Optional.of("trader1"), null, META)).isEqualTo(LogonOutcome.NO_CREDENTIALS);
        assertThat(service.logon(Optional.of("trader1"), "  ", META)).isEqualTo(LogonOutcome.NO_CREDENTIALS);

        verifyNoInteractions(validator);
        assertThat(attempts(LogonOutcome.NO_CREDENTIALS)).isEqualTo(2);
        assertThat(timed(LogonOutcome.NO_CREDENTIALS)).isEqualTo(2);
    }

    @Test
    void nonBasicSchemeIsMalformed() {
        assertThat(service.logon(Optional.of("trader1"), "Bearer abc", META)).isEqualTo(LogonOutcome.MALFORMED);
        assertThat(service.logon(Optional.of("trader1"), "Digest username=\"trader1\"", META)).isEqualTo(LogonOutcome.MALFORMED);

        verifyNoInteractions(validator);
        assertThat(attempts(LogonOutcome.MALFORMED)).isEqualTo(2);
    }

    @Test
    void invalidBase64OrMissingColonIsMalformed() {
        assertThat(service.logon(Optional.of("trader1"), "Basic ***", META)).isEqualTo(LogonOutcome.MALFORMED);
        assertThat(service.logon(Optional.of("trader1"), basic("trader1"), META)).isEqualTo(LogonOutcome.MALFORMED);

        verifyNoInteractions(validator);
    }

    @Test
    void emptyUsernameOrPasswordIsMalformedBeforeAnyBackendCall() {
        assertThat(service.logon(Optional.of("trader1"), basic("trader1:"), META)).isEqualTo(LogonOutcome.MALFORMED);
        assertThat(service.logon(Optional.empty(), basic(":secret"), META)).isEqualTo(LogonOutcome.MALFORMED);

        verifyNoInteractions(validator);
        assertThat(attempts(LogonOutcome.MALFORMED)).isEqualTo(2);
    }

    @Test
    void pathUsernameMismatchIsRejectedBeforeAnyBackendCall() {
        assertThat(service.logon(Optional.of("other"), basic("trader1:secret"), META))
                .isEqualTo(LogonOutcome.USERNAME_MISMATCH);

        verifyNoInteractions(validator);
        assertThat(attempts(LogonOutcome.USERNAME_MISMATCH)).isEqualTo(1);
    }

    @Test
    void pathUsernameComparisonIsCaseInsensitive() {
        when(validator.validate("trader1", "secret")).thenReturn(ValidationResult.VALID);

        assertThat(service.logon(Optional.of("TRADER1"), basic("trader1:secret"), META)).isEqualTo(LogonOutcome.SUCCESS);
    }

    @Test
    void pathUsernameCheckCanBeDisabled() {
        service = new LogonService(new BasicAuthorizationParser(), validator, properties(false), registry);
        when(validator.validate("trader1", "secret")).thenReturn(ValidationResult.VALID);

        assertThat(service.logon(Optional.of("other"), basic("trader1:secret"), META)).isEqualTo(LogonOutcome.SUCCESS);
    }

    @Test
    void noPathUsernameSkipsTheCrossCheck() {
        when(validator.validate("trader1", "secret")).thenReturn(ValidationResult.VALID);

        assertThat(service.logon(Optional.empty(), basic("trader1:secret"), META)).isEqualTo(LogonOutcome.SUCCESS);
        assertThat(service.logon(null, basic("trader1:secret"), META)).isEqualTo(LogonOutcome.SUCCESS);
    }

    @Test
    void invalidCredentialsAreInvalid() {
        when(validator.validate("trader1", "wrong")).thenReturn(ValidationResult.INVALID);

        assertThat(service.logon(Optional.of("trader1"), basic("trader1:wrong"), META)).isEqualTo(LogonOutcome.INVALID);
        assertThat(attempts(LogonOutcome.INVALID)).isEqualTo(1);
        assertThat(timed(LogonOutcome.INVALID)).isEqualTo(1);
    }

    @Test
    void validCredentialsAreSuccess() {
        when(validator.validate("trader1", "se:cr:et")).thenReturn(ValidationResult.VALID);

        assertThat(service.logon(Optional.of("trader1"), basic("trader1:se:cr:et"), META)).isEqualTo(LogonOutcome.SUCCESS);

        verify(validator).validate("trader1", "se:cr:et");
        assertThat(attempts(LogonOutcome.SUCCESS)).isEqualTo(1);
        assertThat(attempts(LogonOutcome.INVALID)).isZero();
    }

    @Test
    void backendUnavailableIsPropagated() {
        when(validator.validate("trader1", "secret")).thenReturn(ValidationResult.BACKEND_UNAVAILABLE);

        assertThat(service.logon(Optional.of("trader1"), basic("trader1:secret"), META))
                .isEqualTo(LogonOutcome.BACKEND_UNAVAILABLE);
        assertThat(attempts(LogonOutcome.BACKEND_UNAVAILABLE)).isEqualTo(1);
    }

    @Test
    void backendExceptionIsBackendUnavailable() {
        when(validator.validate(anyString(), anyString())).thenThrow(new IllegalStateException("ldap exploded"));

        assertThat(service.logon(Optional.of("trader1"), basic("trader1:secret"), META))
                .isEqualTo(LogonOutcome.BACKEND_UNAVAILABLE);
        assertThat(attempts(LogonOutcome.BACKEND_UNAVAILABLE)).isEqualTo(1);
    }

    @Test
    void backendReturningNullIsBackendUnavailable() {
        when(validator.validate("trader1", "secret")).thenReturn(null);

        assertThat(service.logon(Optional.of("trader1"), basic("trader1:secret"), META))
                .isEqualTo(LogonOutcome.BACKEND_UNAVAILABLE);
    }

    @Test
    void nullMetadataIsTolerated() {
        when(validator.validate("trader1", "secret")).thenReturn(ValidationResult.VALID);

        assertThat(service.logon(Optional.of("trader1"), basic("trader1:secret"), null)).isEqualTo(LogonOutcome.SUCCESS);
    }

    @Test
    void metersAreRegisteredForEveryOutcomeAndTaggedOnlyWithOutcome() {
        for (LogonOutcome outcome : LogonOutcome.values()) {
            assertThat(attempts(outcome)).isZero();
            assertThat(timed(outcome)).isZero();
        }
        List<Meter> meters = registry.getMeters();
        assertThat(meters).isNotEmpty();
        for (Meter meter : meters) {
            assertThat(meter.getId().getTags()).extracting(Tag::getKey).containsOnly(LogonService.OUTCOME_TAG);
        }
    }
}
