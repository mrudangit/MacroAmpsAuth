package com.example.ampsauth;

import java.io.IOException;
import java.io.OutputStream;
import java.net.InetSocketAddress;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.Map;

import com.sun.net.httpserver.HttpServer;

import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.system.CapturedOutput;
import org.springframework.boot.test.system.OutputCaptureExtension;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * End to end: the service configured with the {@code userinfo} backend against a stub UserInfo
 * endpoint. The AMPS password is the access token; every token used here must stay out of the log.
 */
@ExtendWith(OutputCaptureExtension.class)
@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT)
class UserInfoBackendIntegrationTest {

    private static final String PATH = "/amps/v1/permissions";
    private static final String GOOD = "tok-good-8f31c2";
    private static final String NO_GROUP = "tok-nogroup-77ab";
    private static final String MISMATCH = "tok-mismatch-19cd";
    private static final String EXPIRED = "tok-expired-5e0f";
    private static final String BOOM = "tok-boom-3a21";
    private static final String GARBAGE = "tok-garbage-9c44";
    private static final String SLOW = "tok-slow-b6d8";

    private static final Map<String, String> BODIES = Map.of(
            GOOD, "{\"sub\":\"1\",\"preferred_username\":\"trader1\",\"groups\":[\"everyone\",\"AMPS-Users\"]}",
            NO_GROUP, "{\"sub\":\"2\",\"preferred_username\":\"trader1\",\"groups\":[\"everyone\"]}",
            MISMATCH, "{\"sub\":\"3\",\"preferred_username\":\"someone-else\",\"groups\":[\"amps-users\"]}",
            GARBAGE, "<html>not json</html>");

    private static HttpServer server;

    private static synchronized HttpServer server() {
        if (server == null) {
            try {
                server = HttpServer.create(new InetSocketAddress("127.0.0.1", 0), 0);
            } catch (IOException e) {
                throw new java.io.UncheckedIOException(e);
            }
            server.createContext("/oauth2/userinfo", exchange -> {
                String auth = exchange.getRequestHeaders().getFirst("Authorization");
                String token = auth != null && auth.startsWith("Bearer ") ? auth.substring(7) : "";
                int status;
                String body;
                if (SLOW.equals(token)) {
                    try {
                        Thread.sleep(2000);
                    } catch (InterruptedException e) {
                        Thread.currentThread().interrupt();
                    }
                    status = 200;
                    body = BODIES.get(GOOD);
                } else if (BOOM.equals(token)) {
                    status = 500;
                    body = "{\"error\":\"server_error\"}";
                } else if (BODIES.containsKey(token)) {
                    status = 200;
                    body = BODIES.get(token);
                } else {
                    status = 401;
                    body = "{\"error\":\"invalid_token\"}";
                }
                byte[] bytes = body.getBytes(StandardCharsets.UTF_8);
                exchange.getResponseHeaders().add("Content-Type", "application/json");
                exchange.sendResponseHeaders(status, bytes.length);
                try (OutputStream out = exchange.getResponseBody()) {
                    out.write(bytes);
                }
            });
            // A pool, so the deliberately slow handler cannot block later requests (e.g. the health probe).
            server.setExecutor(java.util.concurrent.Executors.newCachedThreadPool());
            server.start();
        }
        return server;
    }

    @DynamicPropertySource
    static void userInfoBackend(DynamicPropertyRegistry registry) {
        registry.add("amps.auth.backend", () -> "userinfo");
        registry.add("amps.auth.userinfo.url", () -> "http://127.0.0.1:" + server().getAddress().getPort() + "/oauth2/userinfo");
        registry.add("amps.auth.userinfo.enabled-groups", () -> "amps-users,amps-admins");
        registry.add("amps.auth.userinfo.read-timeout", () -> "500ms");
    }

    @AfterAll
    static void stopServer() {
        if (server != null) {
            server.stop(0);
        }
    }

    @Value("${local.server.port}")
    private int port;

    @Test
    void accessTokenIsCheckedAgainstTheUserInfoEndpoint(CapturedOutput output) {
        TestHttp http = new TestHttp(port);

        HttpResponse<byte[]> ok = http.get(PATH + "/trader1", "Authorization", TestHttp.basic("trader1", GOOD));
        assertThat(ok.statusCode()).isEqualTo(200);
        assertThat(TestHttp.body(ok)).contains("\"logon\": true");

        assertThat(http.get(PATH + "/TRADER1", "Authorization", TestHttp.basic("Trader1", GOOD)).statusCode()).isEqualTo(200);
        assertThat(http.get(PATH, "Authorization", TestHttp.basic("trader1", GOOD)).statusCode()).isEqualTo(200);
        assertThat(http.get(PATH + "/trader1", "Authorization", TestHttp.basic("trader1", NO_GROUP)).statusCode()).isEqualTo(403);
        assertThat(http.get(PATH + "/trader1", "Authorization", TestHttp.basic("trader1", MISMATCH)).statusCode()).isEqualTo(403);
        assertThat(http.get(PATH + "/trader1", "Authorization", TestHttp.basic("trader1", EXPIRED)).statusCode()).isEqualTo(403);
        assertThat(http.get(PATH + "/trader1", "Authorization", TestHttp.basic("trader1", "")).statusCode()).isEqualTo(403);
        assertThat(http.get(PATH + "/trader1", "Authorization", TestHttp.basic("trader1", BOOM)).statusCode()).isEqualTo(503);
        assertThat(http.get(PATH + "/trader1", "Authorization", TestHttp.basic("trader1", GARBAGE)).statusCode()).isEqualTo(503);
        assertThat(http.get(PATH + "/trader1", "Authorization", TestHttp.basic("trader1", SLOW)).statusCode()).isEqualTo(503);

        // The stub is reachable, so the optional health component is UP and readiness is unaffected.
        assertThat(http.get("/actuator/health").statusCode()).isEqualTo(200);
        assertThat(http.get("/actuator/health/readiness").statusCode()).isEqualTo(200);

        String all = output.getAll();
        for (String token : new String[] {GOOD, NO_GROUP, MISMATCH, EXPIRED, BOOM, GARBAGE, SLOW}) {
            assertThat(all).doesNotContain(token);
            assertThat(all).doesNotContain(Base64.getEncoder().encodeToString(("trader1:" + token).getBytes(StandardCharsets.UTF_8)));
        }
        assertThat(all).contains("logon user=trader1 outcome=SUCCESS");
        assertThat(all).contains("logon user=trader1 outcome=INVALID");
        assertThat(all).contains("logon user=trader1 outcome=BACKEND_UNAVAILABLE");
        assertThat(all).contains("principal does not match the logon username user=trader1 principal=someone-else");
        assertThat(all).contains("userinfo credential backend active");
    }
}
