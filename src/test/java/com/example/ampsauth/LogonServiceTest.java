package com.example.ampsauth;

import java.io.IOException;
import java.time.Duration;
import java.util.List;

import io.micrometer.core.instrument.MeterRegistry;
import io.micrometer.core.instrument.simple.SimpleMeterRegistry;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.springframework.boot.test.system.CapturedOutput;
import org.springframework.boot.test.system.OutputCaptureExtension;

import static org.assertj.core.api.Assertions.assertThat;

@ExtendWith(OutputCaptureExtension.class)
class LogonServiceTest {

    private static final String USER = "U000001";
    private static final String TOKEN = "tok-unit-9a1b";

    private final MeterRegistry meterRegistry = new SimpleMeterRegistry();

    private static AmpsProperties.UserInfo config(String... enabledGroups) {
        return new AmpsProperties.UserInfo("https://login.example.com/oauth2/userinfo", "sub", "csgroups",
                List.of(enabledGroups), Duration.ofSeconds(1), Duration.ofSeconds(2), true);
    }

    private LogonService service(UserInfoAuthenticatorTest.FakeClient client) {
        return new LogonService(new UserInfoAuthenticator(config("amps-users"), client), meterRegistry);
    }

    private double count(LogonOutcome outcome) {
        return meterRegistry.get(LogonService.ATTEMPTS_METRIC).tag(LogonService.OUTCOME_TAG, outcome.name()).counter().count();
    }

    private long timed(LogonOutcome outcome) {
        return meterRegistry.get(LogonService.DURATION_METRIC).tag(LogonService.OUTCOME_TAG, outcome.name()).timer().count();
    }

    @Test
    void missingOrBlankTokenIsNoTokenAndNeverReachesTheEndpoint() {
        var client = new UserInfoAuthenticatorTest.FakeClient(200, "{\"sub\":\"" + USER + "\",\"csgroups\":[\"amps-users\"]}");
        LogonService service = service(client);

        assertThat(service.logon(USER, null, RequestMetadata.EMPTY)).isEqualTo(LogonOutcome.NO_TOKEN);
        assertThat(service.logon(USER, "", RequestMetadata.EMPTY)).isEqualTo(LogonOutcome.NO_TOKEN);
        assertThat(service.logon(USER, "   ", RequestMetadata.EMPTY)).isEqualTo(LogonOutcome.NO_TOKEN);
        assertThat(client.tokens).isEmpty();
        assertThat(count(LogonOutcome.NO_TOKEN)).isEqualTo(3.0);
    }

    @Test
    void blankUsernameIsAPrincipalMismatchAndNeverReachesTheEndpoint() {
        var client = new UserInfoAuthenticatorTest.FakeClient(200, "{\"sub\":\"" + USER + "\",\"csgroups\":[\"amps-users\"]}");
        LogonService service = service(client);

        assertThat(service.logon("  ", TOKEN, null)).isEqualTo(LogonOutcome.PRINCIPAL_MISMATCH);
        assertThat(service.logon(null, TOKEN, null)).isEqualTo(LogonOutcome.PRINCIPAL_MISMATCH);
        assertThat(client.tokens).isEmpty();
    }

    @Test
    void everyOutcomeIsCountedAndTimedUnderItsOwnTag() {
        assertThat(service(new UserInfoAuthenticatorTest.FakeClient(200, "{\"sub\":\"" + USER + "\",\"csgroups\":[\"amps-users\"]}"))
                .logon(USER, TOKEN, null)).isEqualTo(LogonOutcome.SUCCESS);
        assertThat(service(new UserInfoAuthenticatorTest.FakeClient(401, "{}"))
                .logon(USER, TOKEN, null)).isEqualTo(LogonOutcome.INVALID_TOKEN);
        assertThat(service(new UserInfoAuthenticatorTest.FakeClient(200, "{\"sub\":\"U999999\",\"csgroups\":[\"amps-users\"]}"))
                .logon(USER, TOKEN, null)).isEqualTo(LogonOutcome.PRINCIPAL_MISMATCH);
        assertThat(service(new UserInfoAuthenticatorTest.FakeClient(200, "{\"sub\":\"" + USER + "\",\"csgroups\":[\"other\"]}"))
                .logon(USER, TOKEN, null)).isEqualTo(LogonOutcome.NOT_ENTITLED);
        var down = new UserInfoAuthenticatorTest.FakeClient(200, "{}");
        down.ioFailure = new IOException("refused");
        assertThat(service(down).logon(USER, TOKEN, null)).isEqualTo(LogonOutcome.BACKEND_UNAVAILABLE);

        for (LogonOutcome outcome : List.of(LogonOutcome.SUCCESS, LogonOutcome.INVALID_TOKEN,
                LogonOutcome.PRINCIPAL_MISMATCH, LogonOutcome.NOT_ENTITLED, LogonOutcome.BACKEND_UNAVAILABLE)) {
            assertThat(count(outcome)).as("attempts %s", outcome).isEqualTo(1.0);
            assertThat(timed(outcome)).as("duration %s", outcome).isEqualTo(1L);
        }
        assertThat(count(LogonOutcome.NO_TOKEN)).isZero();
    }

    @Test
    void metersExistForEveryOutcomeBeforeTheFirstAttempt() {
        service(new UserInfoAuthenticatorTest.FakeClient(200, "{}"));

        for (LogonOutcome outcome : LogonOutcome.values()) {
            assertThat(count(outcome)).isZero();
            assertThat(timed(outcome)).isZero();
        }
    }

    @Test
    void anAuthenticatorThatThrowsIsBackendUnavailable(CapturedOutput output) {
        var client = new UserInfoAuthenticatorTest.FakeClient(200, "{}");
        UserInfoAuthenticator exploding = new UserInfoAuthenticator(config("amps-users"), client) {
            @Override
            LogonOutcome authenticate(String username, String accessToken) {
                throw new IllegalStateException("exploded for a reason unrelated to the token");
            }
        };
        LogonService service = new LogonService(exploding, meterRegistry);

        assertThat(service.logon(USER, TOKEN, null)).isEqualTo(LogonOutcome.BACKEND_UNAVAILABLE);
        assertThat(count(LogonOutcome.BACKEND_UNAVAILABLE)).isEqualTo(1.0);
        assertThat(output.getAll()).contains("ERROR").contains("exploded for a reason").doesNotContain(TOKEN);
    }

    @Test
    void oneInfoLinePerAttemptWithSanitisedMetadata(CapturedOutput output) {
        var client = new UserInfoAuthenticatorTest.FakeClient(200, "{\"sub\":\"" + USER + "\",\"csgroups\":[\"amps-users\"]}");
        LogonService service = service(client);

        service.logon(USER, TOKEN, new RequestMetadata("MacroDesktop-jdoe", "10.1.2.3", "json-tcp-17"));
        service.logon("evil outcome=SUCCESS", TOKEN, new RequestMetadata("forged outcome=SUCCESS", null, null));
        service.logon(USER, null, null);

        String all = output.getAll();
        assertThat(all).contains("logon user=" + USER + " outcome=SUCCESS client=MacroDesktop-jdoe remote=10.1.2.3 conn=json-tcp-17 ms=");
        assertThat(all).contains("logon user=evil_outcome_SUCCESS outcome=PRINCIPAL_MISMATCH client=forged_outcome_SUCCESS remote=- conn=- ms=");
        assertThat(all).contains("logon user=" + USER + " outcome=NO_TOKEN client=- remote=- conn=- ms=");
        assertThat(all).doesNotContain(TOKEN);
        assertThat(all.lines().filter(line -> line.contains("logon user=")).count()).isEqualTo(3);
    }
}
