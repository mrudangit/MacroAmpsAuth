package com.example.ampsauth.web;

import java.nio.charset.StandardCharsets;
import java.util.Base64;

import com.example.ampsauth.AmpsAuthApplication;
import com.example.ampsauth.TestHttp;
import com.example.ampsauth.auth.CredentialValidator;
import com.example.ampsauth.auth.ValidationResult;

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
import org.springframework.test.context.bean.override.mockito.MockitoBean;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.when;

/**
 * Drives every row of the response table with DEBUG logging enabled for the service and Spring MVC,
 * then asserts that neither the password nor the raw Authorization header ever reached the output,
 * and that request-supplied values cannot forge log tokens.
 */
@ExtendWith(OutputCaptureExtension.class)
@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT, properties = {
        "logging.level.org.springframework.web=DEBUG"
})
class PasswordNeverLoggedIntegrationTest {

    private static final String PATH = "/amps/v1/permissions";
    private static final String USER = "trader1";
    private static final String PASSWORD = "Zq7!vN2p-hidden-PW";
    private static final String CLIENT = "MacroDesktop-jdoe";
    private static final String PACKAGE = AmpsAuthApplication.class.getPackageName();

    @MockitoBean
    private CredentialValidator validator;

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
    void passwordNeverAppearsInLogOutput(CapturedOutput output) {
        when(validator.validate(anyString(), anyString())).thenReturn(ValidationResult.INVALID);
        when(validator.validate(eq(USER), eq(PASSWORD))).thenReturn(ValidationResult.VALID);
        when(validator.validate(eq(USER), eq("down-" + PASSWORD))).thenReturn(ValidationResult.BACKEND_UNAVAILABLE);
        when(validator.validate(eq(USER), eq("boom-" + PASSWORD)))
                .thenThrow(new IllegalStateException("backend exploded for a reason unrelated to the credentials"));

        TestHttp http = new TestHttp(port);
        String good = TestHttp.basic(USER, PASSWORD);

        assertThat(http.get(PATH + "/" + USER, "Authorization", good, "X-AMPS-Client-Name", CLIENT,
                "X-AMPS-Remote-Address", "10.1.2.3", "X-AMPS-Connection-Name", "json-tcp-17",
                "X-AMPS-Correlation-Id", "corr-log-1").statusCode()).isEqualTo(200);
        assertThat(http.get(PATH + "/" + USER, "Authorization", TestHttp.basic(USER, "wrong-" + PASSWORD)).statusCode()).isEqualTo(403);
        assertThat(http.get(PATH + "/" + USER).statusCode()).isEqualTo(401);
        assertThat(http.get(PATH + "/" + USER, "Authorization", "Bearer " + PASSWORD).statusCode()).isEqualTo(403);
        assertThat(http.get(PATH + "/" + USER, "Authorization", "Basic !!" + PASSWORD + "!!").statusCode()).isEqualTo(403);
        assertThat(http.get(PATH + "/" + USER, "Authorization", TestHttp.basic(USER, "")).statusCode()).isEqualTo(403);
        assertThat(http.get(PATH + "/other", "Authorization", good).statusCode()).isEqualTo(403);
        assertThat(http.get(PATH, "Authorization", good).statusCode()).isEqualTo(200);
        assertThat(http.get(PATH + "/" + USER, "Authorization", TestHttp.basic(USER, "down-" + PASSWORD)).statusCode()).isEqualTo(503);
        assertThat(http.get(PATH + "/" + USER, "Authorization", TestHttp.basic(USER, "boom-" + PASSWORD)).statusCode()).isEqualTo(503);
        // A password that is itself a control-character-laden log-injection attempt.
        assertThat(http.get(PATH + "/" + USER, "Authorization", TestHttp.basic(USER, PASSWORD + "\r\nINJECTED")).statusCode()).isEqualTo(403);
        // A username and a client name that try to forge the outcome token of the INFO line.
        assertThat(http.get(PATH, "Authorization", TestHttp.basic("evil outcome=SUCCESS", "x"),
                "X-AMPS-Client-Name", "forged outcome=SUCCESS", "X-AMPS-Correlation-Id", "c1 corr=forged")
                .statusCode()).isEqualTo(403);

        String all = output.getAll();
        assertThat(all).doesNotContain(PASSWORD);
        assertThat(all).doesNotContain(Base64.getEncoder().encodeToString((USER + ":" + PASSWORD).getBytes(StandardCharsets.UTF_8)));
        assertThat(all).doesNotContain(good);
        assertThat(all).doesNotContain("INJECTED");
        assertThat(all).doesNotContainIgnoringCase("authorization: basic");

        // DEBUG for the service package is really in effect (otherwise the leak checks above prove less).
        assertThat(all).contains("malformed Authorization header: unsupported-scheme");

        // The single INFO line per attempt, with the metadata headers, is present.
        assertThat(all).contains("logon user=" + USER + " outcome=SUCCESS client=" + CLIENT
                + " remote=10.1.2.3 conn=json-tcp-17 ms=");
        assertThat(all).contains("logon user=" + USER + " outcome=INVALID");
        assertThat(all).contains("logon user=- outcome=NO_CREDENTIALS");
        assertThat(all).contains("logon user=- outcome=MALFORMED");
        assertThat(all).contains("logon user=" + USER + " outcome=USERNAME_MISMATCH");
        assertThat(all).contains("logon user=" + USER + " outcome=BACKEND_UNAVAILABLE");
        assertThat(all).contains("corr=corr-log-1");
        assertThat(all).contains("backend exploded");

        // Forged tokens are neutralised.
        assertThat(all).doesNotContain("user=evil outcome=SUCCESS");
        assertThat(all).doesNotContain("client=forged outcome=SUCCESS");
        assertThat(all).doesNotContain("corr=c1 corr=forged");
        assertThat(all).contains("logon user=evil_outcome_SUCCESS outcome=INVALID client=forged_outcome_SUCCESS");
        assertThat(all).contains("corr=c1_corr_forged");
    }
}
