package com.example.ampsauth;

import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.logging.LogLevel;
import org.springframework.boot.logging.LoggingSystem;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.system.CapturedOutput;
import org.springframework.boot.test.system.OutputCaptureExtension;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Drives every outcome with DEBUG logging enabled for the service and Spring MVC, then asserts that
 * no access token ever reached the output, that there is exactly one INFO line per attempt, and
 * that request-supplied values cannot forge log tokens.
 */
@ExtendWith(OutputCaptureExtension.class)
@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT, properties = {
        "logging.level.org.springframework.web=DEBUG"
})
class TokenNeverLoggedIntegrationTest {

    private static final String PATH = "/amps/v1/permissions";
    private static final String TOKEN_HEADER = "X-AMPS-Password";
    private static final String USER = StubUserInfoServer.USER;
    private static final String CLIENT = "MacroDesktop-jdoe";
    private static final String PACKAGE = AmpsAuthConfiguration.class.getPackageName();

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
        registry.add("amps.auth.userinfo.enabled-groups", () -> "amps-users");
        registry.add("amps.auth.userinfo.read-timeout", () -> "500ms");
    }

    @AfterAll
    static void stopStub() {
        if (stub != null) {
            stub.close();
            stub = null;
        }
    }

    @Autowired
    private LoggingSystem loggingSystem;

    @Value("${local.server.port}")
    private int port;

    @BeforeEach
    void enableDebugForTheServicePackage() {
        // Set through the LoggingSystem (a property would arrive too late for the logging initialisation).
        loggingSystem.setLogLevel(PACKAGE, LogLevel.DEBUG);
    }

    @AfterEach
    void restoreLogLevel() {
        loggingSystem.setLogLevel(PACKAGE, null);
    }

    @Test
    void tokenNeverAppearsInLogOutput(CapturedOutput output) {
        TestHttp http = new TestHttp(port);

        assertThat(http.get(PATH + "/" + USER, TOKEN_HEADER, StubUserInfoServer.GOOD, "X-AMPS-Client-Name", CLIENT,
                "X-AMPS-Remote-Address", "10.1.2.3", "X-AMPS-Connection-Name", "json-tcp-17",
                "X-AMPS-Correlation-Id", "corr-log-1").statusCode()).isEqualTo(200);
        assertThat(http.get(PATH + "/" + USER, TOKEN_HEADER, StubUserInfoServer.EXPIRED).statusCode()).isEqualTo(403);
        assertThat(http.get(PATH + "/" + USER).statusCode()).isEqualTo(401);
        assertThat(http.get(PATH + "/" + USER, TOKEN_HEADER, StubUserInfoServer.MISMATCH).statusCode()).isEqualTo(403);
        assertThat(http.get(PATH + "/" + USER, TOKEN_HEADER, StubUserInfoServer.NO_GROUP).statusCode()).isEqualTo(403);
        assertThat(http.get(PATH + "/" + USER, TOKEN_HEADER, StubUserInfoServer.BOOM).statusCode()).isEqualTo(503);
        assertThat(http.get(PATH + "/" + USER, TOKEN_HEADER, StubUserInfoServer.GARBAGE).statusCode()).isEqualTo(503);
        assertThat(http.get(PATH + "/" + USER, TOKEN_HEADER, StubUserInfoServer.SLOW).statusCode()).isEqualTo(503);
        // A token that is itself a log-injection attempt (tab is the one control character a header may carry).
        assertThat(http.get(PATH + "/" + USER, TOKEN_HEADER, StubUserInfoServer.GOOD + "\tINJECTED").statusCode()).isEqualTo(403);
        // A username and a client name that try to forge the outcome token of the INFO line.
        assertThat(http.get(PATH + "/evil%20outcome=SUCCESS", TOKEN_HEADER, StubUserInfoServer.GOOD,
                "X-AMPS-Client-Name", "forged outcome=SUCCESS", "X-AMPS-Correlation-Id", "c1 corr=forged")
                .statusCode()).isEqualTo(403);

        String all = output.getAll();
        for (String token : StubUserInfoServer.ALL_TOKENS) {
            assertThat(all).doesNotContain(token);
        }
        assertThat(all).doesNotContain("INJECTED");
        assertThat(all).doesNotContainIgnoringCase("bearer ");
        assertThat(all).doesNotContainIgnoringCase(TOKEN_HEADER + ":");

        // DEBUG for the service package is really in effect (otherwise the leak checks above prove less).
        assertThat(all).contains("userinfo endpoint rejected the access token status=401 user=" + USER);

        // The single INFO line per attempt, with the metadata headers, is present for every outcome.
        assertThat(all).contains("logon user=" + USER + " outcome=SUCCESS client=" + CLIENT
                + " remote=10.1.2.3 conn=json-tcp-17 ms=");
        assertThat(all).contains("logon user=" + USER + " outcome=INVALID_TOKEN");
        assertThat(all).contains("logon user=" + USER + " outcome=NO_TOKEN");
        assertThat(all).contains("logon user=" + USER + " outcome=PRINCIPAL_MISMATCH");
        assertThat(all).contains("logon user=" + USER + " outcome=NOT_ENTITLED");
        assertThat(all).contains("logon user=" + USER + " outcome=BACKEND_UNAVAILABLE");
        assertThat(all).contains("corr=corr-log-1");
        assertThat(all).contains("principal does not match the logon username user=" + USER
                + " principal=" + StubUserInfoServer.OTHER_USER);
        assertThat(all).contains("userinfo endpoint returned status=500");

        // Forged tokens are neutralised.
        assertThat(all).doesNotContain("user=evil outcome=SUCCESS");
        assertThat(all).doesNotContain("client=forged outcome=SUCCESS");
        assertThat(all).doesNotContain("corr=c1 corr=forged");
        assertThat(all).contains("logon user=evil_outcome_SUCCESS outcome=PRINCIPAL_MISMATCH client=forged_outcome_SUCCESS");
        assertThat(all).contains("corr=c1_corr_forged");
    }
}
