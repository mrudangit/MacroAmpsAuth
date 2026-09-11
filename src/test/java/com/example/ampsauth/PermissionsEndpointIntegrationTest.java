package com.example.ampsauth;

import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.util.Base64;

import io.micrometer.core.instrument.Meter;
import io.micrometer.core.instrument.MeterRegistry;
import io.micrometer.core.instrument.Tag;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;

import tools.jackson.databind.json.JsonMapper;

import static org.assertj.core.api.Assertions.assertThat;

@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT, properties = {
        "amps.auth.backend=inmemory",
        "amps.auth.inmemory.allow-plaintext=true"
})
class PermissionsEndpointIntegrationTest {

    static final String TRADER1_PASSWORD = "s3cret:Pa55w0rd";
    static final String TRADER2_PASSWORD = "bcrypt-Pa55w0rd";
    static final String JANE_PASSWORD = "jane-Pa55w0rd";
    private static final String PATH = "/amps/v1/permissions";

    /**
     * All users live in this one property source: Spring's binder takes an indexed list from a
     * single source, so a bcrypt hash computed here cannot be mixed with users declared elsewhere.
     */
    @DynamicPropertySource
    static void users(DynamicPropertyRegistry registry) {
        registry.add("amps.auth.inmemory.users[0].username", () -> "trader1");
        registry.add("amps.auth.inmemory.users[0].password", () -> "{noop}" + TRADER1_PASSWORD);
        registry.add("amps.auth.inmemory.users[1].username", () -> "Trader2");
        registry.add("amps.auth.inmemory.users[1].password",
                () -> "{bcrypt}" + new BCryptPasswordEncoder(4).encode(TRADER2_PASSWORD));
        registry.add("amps.auth.inmemory.users[2].username", () -> "jane doe");
        registry.add("amps.auth.inmemory.users[2].password", () -> "{noop}" + JANE_PASSWORD);
    }

    @Value("${local.server.port}")
    private int port;

    @Autowired
    private PermissionsDocument document;

    @Autowired
    private MeterRegistry meterRegistry;

    private TestHttp http;

    @BeforeEach
    void setUp() {
        http = new TestHttp(port);
    }

    @Test
    void validCredentialsReturnThePermissionsDocument() {
        HttpResponse<byte[]> response = http.get(PATH + "/trader1",
                "Authorization", TestHttp.basic("trader1", TRADER1_PASSWORD),
                "X-AMPS-Correlation-Id", "corr-123",
                "X-AMPS-Client-Name", "MacroDesktop-jdoe",
                "X-AMPS-Remote-Address", "10.1.2.3",
                "X-AMPS-Connection-Name", "json-tcp-17");

        assertThat(response.statusCode()).isEqualTo(200);
        assertThat(response.body()).isEqualTo(document.bytes());
        assertThat(JsonMapper.builder().build().readTree(response.body()))
                .isEqualTo(JsonMapper.builder().build().readTree(document.bytes()));
        assertThat(JsonMapper.builder().build().readTree(response.body()).get("logon").booleanValue()).isTrue();
        assertThat(response.headers().firstValue("Content-Type")).hasValueSatisfying(
                value -> assertThat(value).startsWith("application/json"));
        assertThat(response.headers().firstValue("Cache-Control")).hasValue("no-store");
        assertThat(response.headers().firstValue("X-AMPS-Correlation-Id")).hasValue("corr-123");
    }

    @Test
    void wrongPasswordIsForbiddenWithEmptyBody() {
        HttpResponse<byte[]> response = http.get(PATH + "/trader1",
                "Authorization", TestHttp.basic("trader1", "wrong"),
                "X-AMPS-Correlation-Id", "corr-403");

        assertThat(response.statusCode()).isEqualTo(403);
        assertThat(response.body()).isEmpty();
        assertThat(response.headers().firstValue("Cache-Control")).hasValue("no-store");
        assertThat(response.headers().firstValue("X-AMPS-Correlation-Id")).hasValue("corr-403");
        assertThat(response.headers().firstValue("WWW-Authenticate")).isEmpty();
    }

    @Test
    void unknownUserIsForbidden() {
        HttpResponse<byte[]> response = http.get(PATH + "/nobody", "Authorization", TestHttp.basic("nobody", "x"));

        assertThat(response.statusCode()).isEqualTo(403);
        assertThat(response.body()).isEmpty();
    }

    @Test
    void missingAuthorizationIsUnauthorizedWithBasicChallenge() {
        HttpResponse<byte[]> response = http.get(PATH + "/trader1", "X-AMPS-Correlation-Id", "corr-401");

        assertThat(response.statusCode()).isEqualTo(401);
        assertThat(response.body()).isEmpty();
        assertThat(response.headers().firstValue("WWW-Authenticate")).hasValue("Basic realm=\"amps\"");
        assertThat(response.headers().firstValue("Cache-Control")).hasValue("no-store");
        assertThat(response.headers().firstValue("X-AMPS-Correlation-Id")).hasValue("corr-401");
    }

    @Test
    void missingAuthorizationWinsOverPathMismatch() {
        HttpResponse<byte[]> response = http.get(PATH + "/other");

        assertThat(response.statusCode()).isEqualTo(401);
        assertThat(response.headers().firstValue("WWW-Authenticate")).hasValue("Basic realm=\"amps\"");
    }

    @Test
    void longCorrelationIdIsEchoedVerbatim() {
        String id = "c".repeat(300);

        HttpResponse<byte[]> response = http.get(PATH + "/trader1",
                "Authorization", TestHttp.basic("trader1", TRADER1_PASSWORD), "X-AMPS-Correlation-Id", id);

        assertThat(response.statusCode()).isEqualTo(200);
        assertThat(response.headers().firstValue("X-AMPS-Correlation-Id")).hasValue(id);
    }

    @Test
    void bearerSchemeIsForbidden() {
        HttpResponse<byte[]> response = http.get(PATH + "/trader1", "Authorization", "Bearer eyJhbGciOiJIUzI1NiJ9.e30.x");

        assertThat(response.statusCode()).isEqualTo(403);
        assertThat(response.body()).isEmpty();
        assertThat(response.headers().firstValue("WWW-Authenticate")).isEmpty();
    }

    @Test
    void malformedBase64IsForbidden() {
        HttpResponse<byte[]> response = http.get(PATH + "/trader1", "Authorization", "Basic !!not-base64!!");

        assertThat(response.statusCode()).isEqualTo(403);
        assertThat(response.body()).isEmpty();
    }

    @Test
    void missingColonIsForbidden() {
        String token = Base64.getEncoder().encodeToString("trader1".getBytes(StandardCharsets.UTF_8));

        HttpResponse<byte[]> response = http.get(PATH + "/trader1", "Authorization", "Basic " + token);

        assertThat(response.statusCode()).isEqualTo(403);
    }

    @Test
    void emptyPasswordIsForbidden() {
        HttpResponse<byte[]> response = http.get(PATH + "/trader1", "Authorization", TestHttp.basic("trader1", ""));

        assertThat(response.statusCode()).isEqualTo(403);
        assertThat(response.body()).isEmpty();
    }

    @Test
    void emptyUsernameIsForbidden() {
        HttpResponse<byte[]> response = http.get(PATH, "Authorization", TestHttp.basic("", TRADER1_PASSWORD));

        assertThat(response.statusCode()).isEqualTo(403);
    }

    @Test
    void pathUsernameMismatchIsForbidden() {
        HttpResponse<byte[]> response = http.get(PATH + "/other", "Authorization", TestHttp.basic("trader1", TRADER1_PASSWORD));

        assertThat(response.statusCode()).isEqualTo(403);
        assertThat(response.body()).isEmpty();
    }

    @Test
    void pathUsernameIsComparedCaseInsensitively() {
        HttpResponse<byte[]> response = http.get(PATH + "/TRADER1", "Authorization", TestHttp.basic("trader1", TRADER1_PASSWORD));

        assertThat(response.statusCode()).isEqualTo(200);
    }

    @Test
    void pathUsernameIsUrlDecodedBeforeComparison() {
        HttpResponse<byte[]> response = http.get(PATH + "/jane%20doe", "Authorization", TestHttp.basic("jane doe", JANE_PASSWORD));

        assertThat(response.statusCode()).isEqualTo(200);
    }

    @Test
    void endpointWithoutPathVariableWorks() {
        HttpResponse<byte[]> response = http.get(PATH, "Authorization", TestHttp.basic("trader1", TRADER1_PASSWORD));

        assertThat(response.statusCode()).isEqualTo(200);
        assertThat(response.body()).isEqualTo(document.bytes());
        assertThat(response.headers().firstValue("Content-Type")).hasValueSatisfying(
                value -> assertThat(value).startsWith("application/json"));
    }

    @Test
    void bcryptUserCanLogOnWithCaseInsensitiveUsername() {
        assertThat(http.get(PATH + "/trader2", "Authorization", TestHttp.basic("trader2", TRADER2_PASSWORD)).statusCode())
                .isEqualTo(200);
        assertThat(http.get(PATH + "/Trader2", "Authorization", TestHttp.basic("TRADER2", TRADER2_PASSWORD)).statusCode())
                .isEqualTo(200);
        assertThat(http.get(PATH + "/trader2", "Authorization", TestHttp.basic("trader2", "nope")).statusCode())
                .isEqualTo(403);
    }

    @Test
    void sameCredentialsAlwaysProduceTheSameAnswer() {
        for (int i = 0; i < 3; i++) {
            assertThat(http.get(PATH + "/trader1", "Authorization", TestHttp.basic("trader1", TRADER1_PASSWORD)).statusCode())
                    .isEqualTo(200);
            assertThat(http.get(PATH + "/trader1", "Authorization", TestHttp.basic("trader1", "wrong")).statusCode())
                    .isEqualTo(403);
        }
    }

    @Test
    void unknownPathIsNotFoundWithoutDetails() {
        HttpResponse<byte[]> response = http.get("/amps/v1/other", "Authorization", TestHttp.basic("trader1", TRADER1_PASSWORD));

        assertThat(response.statusCode()).isEqualTo(404);
        assertThat(TestHttp.body(response)).doesNotContain("trace").doesNotContain("Exception");
    }

    @Test
    void trailingSlashIsNotARoute() {
        HttpResponse<byte[]> response = http.get(PATH + "/trader1/", "Authorization", TestHttp.basic("trader1", TRADER1_PASSWORD));

        assertThat(response.statusCode()).isEqualTo(404);
    }

    @Test
    void postIsNotAllowed() {
        HttpResponse<byte[]> response = http.send("POST", PATH + "/trader1", "Authorization", TestHttp.basic("trader1", TRADER1_PASSWORD));

        assertThat(response.statusCode()).isEqualTo(405);
    }

    @Test
    void healthAndProbesAreExposedWithoutDetails() {
        HttpResponse<byte[]> health = http.get("/actuator/health");
        assertThat(health.statusCode()).isEqualTo(200);
        assertThat(TestHttp.body(health)).contains("\"status\":\"UP\"").doesNotContain("diskSpace");

        assertThat(http.get("/actuator/health/liveness").statusCode()).isEqualTo(200);
        assertThat(http.get("/actuator/health/readiness").statusCode()).isEqualTo(200);
        assertThat(http.get("/actuator/info").statusCode()).isEqualTo(200);
    }

    @Test
    void onlyTheDocumentedActuatorRoutesExist() {
        assertThat(http.get("/actuator").statusCode()).isEqualTo(404);
        assertThat(http.get("/actuator/env").statusCode()).isEqualTo(404);
        assertThat(http.get("/actuator/configprops").statusCode()).isEqualTo(404);
        assertThat(http.get("/actuator/loggers").statusCode()).isEqualTo(404);
    }

    @Test
    void logonMetricsAreTaggedByOutcomeOnly() {
        http.get(PATH + "/trader1", "Authorization", TestHttp.basic("trader1", TRADER1_PASSWORD));
        http.get(PATH + "/trader1", "Authorization", TestHttp.basic("trader1", "wrong"));

        assertThat(meterRegistry.get(LogonService.ATTEMPTS_METRIC)
                .tag(LogonService.OUTCOME_TAG, LogonOutcome.SUCCESS.name()).counter().count()).isPositive();
        assertThat(meterRegistry.get(LogonService.ATTEMPTS_METRIC)
                .tag(LogonService.OUTCOME_TAG, LogonOutcome.INVALID.name()).counter().count()).isPositive();
        assertThat(meterRegistry.get(LogonService.DURATION_METRIC)
                .tag(LogonService.OUTCOME_TAG, LogonOutcome.SUCCESS.name()).timer().count()).isPositive();
        for (Meter meter : meterRegistry.getMeters()) {
            if (meter.getId().getName().startsWith("amps.")) {
                assertThat(meter.getId().getTags()).extracting(Tag::getKey).containsOnly(LogonService.OUTCOME_TAG);
            }
        }

        HttpResponse<byte[]> metrics = http.get("/actuator/metrics/" + LogonService.ATTEMPTS_METRIC + "?tag=outcome:INVALID");
        assertThat(metrics.statusCode()).isEqualTo(200);
        assertThat(TestHttp.body(metrics)).contains(LogonService.ATTEMPTS_METRIC).doesNotContain("trader1");
    }
}
