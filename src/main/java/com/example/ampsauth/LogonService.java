package com.example.ampsauth;

import java.util.EnumMap;
import java.util.Map;
import java.util.concurrent.TimeUnit;

import io.micrometer.core.instrument.Counter;
import io.micrometer.core.instrument.MeterRegistry;
import io.micrometer.core.instrument.Timer;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;

/**
 * Orchestrates one logon attempt: guards -> {@link UserInfoAuthenticator} -> {@link LogonOutcome}.
 * Records the {@code amps.logon.attempts} counter and the {@code amps.logon.duration} timer (both
 * tagged only with {@code outcome}) and writes exactly one INFO line per attempt. The token never
 * reaches a log, a metric tag or an exception message.
 */
@Service
public class LogonService {

    public static final String ATTEMPTS_METRIC = "amps.logon.attempts";
    public static final String DURATION_METRIC = "amps.logon.duration";
    public static final String OUTCOME_TAG = "outcome";

    private static final Logger log = LoggerFactory.getLogger(LogonService.class);

    private final UserInfoAuthenticator authenticator;
    private final Map<LogonOutcome, Counter> attempts = new EnumMap<>(LogonOutcome.class);
    private final Map<LogonOutcome, Timer> durations = new EnumMap<>(LogonOutcome.class);

    LogonService(UserInfoAuthenticator authenticator, MeterRegistry meterRegistry) {
        this.authenticator = authenticator;
        for (LogonOutcome outcome : LogonOutcome.values()) {
            attempts.put(outcome, Counter.builder(ATTEMPTS_METRIC)
                    .description("Logon attempts by outcome")
                    .tag(OUTCOME_TAG, outcome.name())
                    .register(meterRegistry));
            durations.put(outcome, Timer.builder(DURATION_METRIC)
                    .description("Logon handling time including the UserInfo call")
                    .tag(OUTCOME_TAG, outcome.name())
                    .register(meterRegistry));
        }
    }

    /**
     * @param username    the {@code {username}} path variable AMPS substituted for {@code {{USER_NAME}}}
     * @param accessToken the value of the password header (the AMPS logon password), or {@code null}
     * @param metadata    optional {@code X-AMPS-*} headers, for the log line only
     */
    public LogonOutcome logon(String username, String accessToken, RequestMetadata metadata) {
        long start = System.nanoTime();
        RequestMetadata meta = metadata == null ? RequestMetadata.EMPTY : metadata;
        LogonOutcome outcome;
        if (accessToken == null || accessToken.isBlank()) {
            outcome = LogonOutcome.NO_TOKEN;
        } else if (username == null || username.isBlank()) {
            // A blank path username can never equal a principal claim; do not call the endpoint for it.
            outcome = LogonOutcome.PRINCIPAL_MISMATCH;
        } else {
            outcome = authenticate(username, accessToken);
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

    private LogonOutcome authenticate(String username, String accessToken) {
        LogonOutcome outcome;
        try {
            outcome = authenticator.authenticate(username, accessToken);
        } catch (RuntimeException e) {
            log.error("authentication failed unexpectedly for user={}", LogSanitizer.clean(username), e);
            return LogonOutcome.BACKEND_UNAVAILABLE;
        }
        if (outcome == null) {
            log.error("authenticator returned null for user={}", LogSanitizer.clean(username));
            return LogonOutcome.BACKEND_UNAVAILABLE;
        }
        return outcome;
    }
}
