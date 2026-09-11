package com.example.ampsauth.auth;

import java.util.EnumMap;
import java.util.Map;
import java.util.Optional;
import java.util.concurrent.TimeUnit;

import com.example.ampsauth.config.AmpsProperties;
import com.example.ampsauth.web.BasicAuthorizationParser;
import com.example.ampsauth.web.BasicCredentials;
import com.example.ampsauth.web.MalformedCredentialsException;

import io.micrometer.core.instrument.Counter;
import io.micrometer.core.instrument.MeterRegistry;
import io.micrometer.core.instrument.Timer;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;

/**
 * Orchestrates one logon attempt: guards (in the order of the response table) -> credential
 * validator -> {@link LogonOutcome}. Records the {@code amps.logon.attempts} counter and the
 * {@code amps.logon.duration} timer (both tagged only with {@code outcome}) and writes exactly one
 * INFO line per attempt. The password never reaches a log, a metric tag or an exception message.
 */
@Service
public class LogonService {

    public static final String ATTEMPTS_METRIC = "amps.logon.attempts";
    public static final String DURATION_METRIC = "amps.logon.duration";
    public static final String OUTCOME_TAG = "outcome";

    private static final Logger log = LoggerFactory.getLogger(LogonService.class);

    private final BasicAuthorizationParser parser;
    private final CredentialValidator validator;
    private final boolean usernamePathMustMatch;
    private final Map<LogonOutcome, Counter> attempts = new EnumMap<>(LogonOutcome.class);
    private final Map<LogonOutcome, Timer> durations = new EnumMap<>(LogonOutcome.class);

    public LogonService(BasicAuthorizationParser parser, CredentialValidator validator,
            AmpsProperties properties, MeterRegistry meterRegistry) {
        this.parser = parser;
        this.validator = validator;
        this.usernamePathMustMatch = properties.auth().usernamePathMustMatch();
        for (LogonOutcome outcome : LogonOutcome.values()) {
            attempts.put(outcome, Counter.builder(ATTEMPTS_METRIC)
                    .description("Logon attempts by outcome")
                    .tag(OUTCOME_TAG, outcome.name())
                    .register(meterRegistry));
            durations.put(outcome, Timer.builder(DURATION_METRIC)
                    .description("Logon handling time including the credential backend")
                    .tag(OUTCOME_TAG, outcome.name())
                    .register(meterRegistry));
        }
    }

    /**
     * @param pathUsername        the {@code {username}} path variable, if the request had one
     * @param authorizationHeader the raw {@code Authorization} header, or {@code null}
     * @param metadata            optional {@code X-AMPS-*} headers, for the log line only
     */
    public LogonOutcome logon(Optional<String> pathUsername, String authorizationHeader, RequestMetadata metadata) {
        long start = System.nanoTime();
        RequestMetadata meta = metadata == null ? RequestMetadata.EMPTY : metadata;
        String username = null;
        LogonOutcome outcome;
        try {
            Optional<BasicCredentials> credentials = parser.parse(authorizationHeader);
            if (credentials.isEmpty()) {
                outcome = LogonOutcome.NO_CREDENTIALS;
            } else {
                username = credentials.get().username();
                outcome = authenticate(credentials.get(), pathUsername == null ? Optional.empty() : pathUsername);
            }
        } catch (MalformedCredentialsException e) {
            log.debug("malformed Authorization header: {}", e.getMessage());
            outcome = LogonOutcome.MALFORMED;
        }
        long elapsedNanos = System.nanoTime() - start;
        attempts.get(outcome).increment();
        durations.get(outcome).record(elapsedNanos, TimeUnit.NANOSECONDS);
        log.info("logon user={} outcome={} client={} remote={} conn={} ms={}",
                LogSanitizer.clean(username), outcome, LogSanitizer.clean(meta.clientName()),
                LogSanitizer.clean(meta.remoteAddress()), LogSanitizer.clean(meta.connectionName()),
                TimeUnit.NANOSECONDS.toMillis(elapsedNanos));
        return outcome;
    }

    private LogonOutcome authenticate(BasicCredentials credentials, Optional<String> pathUsername) {
        if (usernamePathMustMatch && pathUsername.isPresent()
                && !pathUsername.get().equalsIgnoreCase(credentials.username())) {
            return LogonOutcome.USERNAME_MISMATCH;
        }
        ValidationResult result;
        try {
            result = validator.validate(credentials.username(), credentials.password());
        } catch (RuntimeException e) {
            log.error("credential backend threw for user={}", LogSanitizer.clean(credentials.username()), e);
            return LogonOutcome.BACKEND_UNAVAILABLE;
        }
        if (result == null) {
            log.error("credential backend returned null for user={}", LogSanitizer.clean(credentials.username()));
            return LogonOutcome.BACKEND_UNAVAILABLE;
        }
        return switch (result) {
            case VALID -> LogonOutcome.SUCCESS;
            case INVALID -> LogonOutcome.INVALID;
            case BACKEND_UNAVAILABLE -> LogonOutcome.BACKEND_UNAVAILABLE;
        };
    }
}
