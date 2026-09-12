package com.example.ampsauth;

import java.net.http.HttpResponse;

import io.micrometer.core.instrument.Meter;
import io.micrometer.core.instrument.MeterRegistry;
import io.micrometer.core.instrument.Tag;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;

import tools.jackson.databind.json.JsonMapper;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * End to end: the service against a stub UserInfo endpoint. AMPS puts the username in the path and
 * the access token in the {@code X-AMPS-Password} header (see application.yml).
 */
@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT)
class PermissionsEndpointIntegrationTest {

    static final String PATH = "/amps/v1/permissions";
    static final String TOKEN_HEADER = "X-AMPS-Password";
    static final String USER = StubUserInfoServer.USER;

    private static StubUserInfoServer stub;

    static synchronized StubUserInfoServer stub() {
        if (stub == null) {
            stub = StubUserInfoServer.start();
        }
        return stub;
    }

    @DynamicPropertySource
    static void userInfoEndpoint(DynamicPropertyRegistry registry) {
        registry.add("amps.auth.userinfo.url", () -> stub().url());
        registry.add("amps.auth.userinfo.enabled-groups", () -> "amps-users,amps-admins");
        registry.add("amps.auth.userinfo.read-timeout", () -> "500ms");
    }

    @AfterAll
    static void stopStub() {
        if (stub != null) {
            stub.close();
            stub = null;
        }
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
    void validTokenReturnsThePermissionsDocument() {
        int before = stub().authorizationHeaders.size();

        HttpResponse<byte[]> response = http.get(PATH + "/" + USER,
                TOKEN_HEADER, StubUserInfoServer.GOOD,
                "X-AMPS-Correlation-Id", "corr-123",
                "X-AMPS-Client-Name", "MacroDesktop-jdoe",
                "X-AMPS-Remote-Address", "10.1.2.3",
                "X-AMPS-Connection-Name", "json-tcp-17");

        assertThat(response.statusCode()).isEqualTo(200);
        assertThat(response.body()).isEqualTo(document.bytes());
        assertThat(JsonMapper.builder().build().readTree(response.body()).get("logon").booleanValue()).isTrue();
        assertThat(response.headers().firstValue("Content-Type")).hasValueSatisfying(
                value -> assertThat(value).startsWith("application/json"));
        assertThat(response.headers().firstValue("Cache-Control")).hasValue("no-store");
        assertThat(response.headers().firstValue("X-AMPS-Correlation-Id")).hasValue("corr-123");
        // The token went to the UserInfo endpoint as a bearer token, exactly once.
        assertThat(stub().authorizationHeaders.subList(before, stub().authorizationHeaders.size()))
                .containsExactly("Bearer " + StubUserInfoServer.GOOD);
    }

    @Test
    void pathUsernameIsComparedCaseInsensitivelyWithThePrincipalClaim() {
        assertThat(http.get(PATH + "/" + USER.toLowerCase(), TOKEN_HEADER, StubUserInfoServer.GOOD).statusCode()).isEqualTo(200);
    }

    @Test
    void pathUsernameIsUrlDecoded() {
        // "U000001" percent-encoded still matches the principal claim.
        assertThat(http.get(PATH + "/%55000001", TOKEN_HEADER, StubUserInfoServer.GOOD).statusCode()).isEqualTo(200);
    }

    @Test
    void missingTokenIsChallengedWithoutCallingTheEndpoint() {
        int before = stub().authorizationHeaders.size();

        HttpResponse<byte[]> response = http.get(PATH + "/" + USER, "X-AMPS-Correlation-Id", "corr-401");

        // The AMPS module probes without credentials first; the Basic challenge makes it retry with
        // its credentials and the configured headers.
        assertThat(response.statusCode()).isEqualTo(401);
        assertThat(response.body()).isEmpty();
        assertThat(response.headers().firstValue("WWW-Authenticate")).hasValue("Basic realm=\"amps\"");
        assertThat(response.headers().firstValue("Cache-Control")).hasValue("no-store");
        assertThat(response.headers().firstValue("X-AMPS-Correlation-Id")).hasValue("corr-401");
        assertThat(http.get(PATH + "/" + USER, TOKEN_HEADER, "   ").statusCode()).isEqualTo(401);
        assertThat(stub().authorizationHeaders).hasSize(before);
    }

    @Test
    void authorizationHeaderIsIgnoredOnlyThePasswordHeaderCounts() {
        // The old Basic flow is gone: Basic or Bearer credentials in Authorization do not log anyone on...
        assertThat(http.get(PATH + "/" + USER, "Authorization", "Basic dTAwMDAwMTp0b2stZ29vZC04ZjMxYzI=").statusCode())
                .isEqualTo(401);
        assertThat(http.get(PATH + "/" + USER, "Authorization", "Bearer " + StubUserInfoServer.GOOD).statusCode())
                .isEqualTo(401);
        // ...and do not get in the way when the password header is present (the module's retry sends both).
        assertThat(http.get(PATH + "/" + USER, "Authorization", "Basic dTAwMDAwMTp3aGF0ZXZlcg==",
                TOKEN_HEADER, StubUserInfoServer.GOOD).statusCode()).isEqualTo(200);
    }

    @Test
    void tokenRejectedByTheIdentityProviderIsForbidden() {
        HttpResponse<byte[]> response = http.get(PATH + "/" + USER, TOKEN_HEADER, StubUserInfoServer.EXPIRED);

        assertThat(response.statusCode()).isEqualTo(403);
        assertThat(response.body()).isEmpty();
        assertThat(response.headers().firstValue("WWW-Authenticate")).isEmpty();
    }

    @Test
    void anotherUsersTokenIsForbidden() {
        assertThat(http.get(PATH + "/" + USER, TOKEN_HEADER, StubUserInfoServer.MISMATCH).statusCode()).isEqualTo(403);
        // ... and the same token is accepted under its own username.
        assertThat(http.get(PATH + "/" + StubUserInfoServer.OTHER_USER, TOKEN_HEADER, StubUserInfoServer.MISMATCH).statusCode())
                .isEqualTo(200);
    }

    @Test
    void userOutsideTheEnabledGroupsIsForbidden() {
        assertThat(http.get(PATH + "/" + USER, TOKEN_HEADER, StubUserInfoServer.NO_GROUP).statusCode()).isEqualTo(403);
    }

    @Test
    void tokenWithControlCharactersIsForbiddenWithoutCallingTheEndpoint() {
        int before = stub().authorizationHeaders.size();

        assertThat(http.get(PATH + "/" + USER, TOKEN_HEADER, "tok\tbad").statusCode()).isEqualTo(403);
        assertThat(stub().authorizationHeaders).hasSize(before);
    }

    @Test
    void identityProviderErrorIsServiceUnavailableWithEmptyBody() {
        HttpResponse<byte[]> response = http.get(PATH + "/" + USER, TOKEN_HEADER, StubUserInfoServer.BOOM,
                "X-AMPS-Correlation-Id", "corr-503");

        assertThat(response.statusCode()).isEqualTo(503);
        assertThat(response.body()).isEmpty();
        assertThat(response.headers().firstValue("Cache-Control")).hasValue("no-store");
        assertThat(response.headers().firstValue("X-AMPS-Correlation-Id")).hasValue("corr-503");
    }

    @Test
    void garbageAndTimeoutsAreServiceUnavailable() {
        assertThat(http.get(PATH + "/" + USER, TOKEN_HEADER, StubUserInfoServer.GARBAGE).statusCode()).isEqualTo(503);
        assertThat(http.get(PATH + "/" + USER, TOKEN_HEADER, StubUserInfoServer.SLOW).statusCode()).isEqualTo(503);
    }

    @Test
    void sameTokenAlwaysProducesTheSameAnswer() {
        for (int i = 0; i < 3; i++) {
            assertThat(http.get(PATH + "/" + USER, TOKEN_HEADER, StubUserInfoServer.GOOD).statusCode()).isEqualTo(200);
            assertThat(http.get(PATH + "/" + USER, TOKEN_HEADER, StubUserInfoServer.EXPIRED).statusCode()).isEqualTo(403);
        }
    }

    @Test
    void onlyThePathVariableRouteExists() {
        assertThat(http.get(PATH, TOKEN_HEADER, StubUserInfoServer.GOOD).statusCode()).isEqualTo(404);
        assertThat(http.get(PATH + "/" + USER + "/", TOKEN_HEADER, StubUserInfoServer.GOOD).statusCode()).isEqualTo(404);
        HttpResponse<byte[]> other = http.get("/amps/v1/other", TOKEN_HEADER, StubUserInfoServer.GOOD);
        assertThat(other.statusCode()).isEqualTo(404);
        assertThat(TestHttp.body(other)).doesNotContain("trace").doesNotContain("Exception");
        assertThat(http.send("POST", PATH + "/" + USER, TOKEN_HEADER, StubUserInfoServer.GOOD).statusCode()).isEqualTo(405);
    }

    @Test
    void healthAndProbesAreExposedWithoutDetails() {
        HttpResponse<byte[]> health = http.get("/actuator/health");
        assertThat(health.statusCode()).isEqualTo(200);
        assertThat(TestHttp.body(health)).contains("\"status\":\"UP\"").doesNotContain("userInfo").doesNotContain("url");

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
        assertThat(http.get("/swagger-ui/index.html").statusCode()).isEqualTo(404);
        assertThat(http.get("/v3/api-docs").statusCode()).isEqualTo(404);
    }

    @Test
    void logonMetricsAreTaggedByOutcomeOnly() {
        http.get(PATH + "/" + USER, TOKEN_HEADER, StubUserInfoServer.GOOD);
        http.get(PATH + "/" + USER, TOKEN_HEADER, StubUserInfoServer.EXPIRED);

        assertThat(meterRegistry.get(LogonService.ATTEMPTS_METRIC)
                .tag(LogonService.OUTCOME_TAG, LogonOutcome.SUCCESS.name()).counter().count()).isPositive();
        assertThat(meterRegistry.get(LogonService.ATTEMPTS_METRIC)
                .tag(LogonService.OUTCOME_TAG, LogonOutcome.INVALID_TOKEN.name()).counter().count()).isPositive();
        assertThat(meterRegistry.get(LogonService.DURATION_METRIC)
                .tag(LogonService.OUTCOME_TAG, LogonOutcome.SUCCESS.name()).timer().count()).isPositive();
        for (Meter meter : meterRegistry.getMeters()) {
            if (meter.getId().getName().startsWith("amps.")) {
                assertThat(meter.getId().getTags()).extracting(Tag::getKey).containsOnly(LogonService.OUTCOME_TAG);
            }
        }

        HttpResponse<byte[]> metrics = http.get("/actuator/metrics/" + LogonService.ATTEMPTS_METRIC + "?tag=outcome:INVALID_TOKEN");
        assertThat(metrics.statusCode()).isEqualTo(200);
        assertThat(TestHttp.body(metrics)).contains(LogonService.ATTEMPTS_METRIC).doesNotContain(USER);
    }

    /** The header name is configurable; the default name is then ignored. */
    @Nested
    @SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT,
            properties = "amps.auth.password-header=X-Access-Token")
    class CustomHeaderName {

        @DynamicPropertySource
        static void userInfoEndpoint(DynamicPropertyRegistry registry) {
            registry.add("amps.auth.userinfo.url", () -> stub().url());
            registry.add("amps.auth.userinfo.enabled-groups", () -> "amps-users");
        }

        @Value("${local.server.port}")
        private int nestedPort;

        @Test
        void theConfiguredHeaderCarriesTheToken() {
            TestHttp nested = new TestHttp(nestedPort);

            assertThat(nested.get(PATH + "/" + USER, "X-Access-Token", StubUserInfoServer.GOOD).statusCode()).isEqualTo(200);
            assertThat(nested.get(PATH + "/" + USER, TOKEN_HEADER, StubUserInfoServer.GOOD).statusCode()).isEqualTo(401);
        }
    }
}
