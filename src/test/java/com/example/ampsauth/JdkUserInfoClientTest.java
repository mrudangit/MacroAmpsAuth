package com.example.ampsauth;

import java.io.IOException;
import java.io.OutputStream;
import java.net.InetSocketAddress;
import java.net.http.HttpTimeoutException;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

import com.sun.net.httpserver.HttpServer;

import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.springframework.boot.test.system.CapturedOutput;
import org.springframework.boot.test.system.OutputCaptureExtension;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

/** Drives the real JDK client against a tiny local HTTP server. */
@ExtendWith(OutputCaptureExtension.class)
class JdkUserInfoClientTest {

    private static HttpServer server;
    private static final Map<String, List<String>> lastHeaders = new ConcurrentHashMap<>();

    @BeforeAll
    static void startServer() throws IOException {
        server = HttpServer.create(new InetSocketAddress("127.0.0.1", 0), 0);
        server.createContext("/userinfo", exchange -> {
            lastHeaders.clear();
            exchange.getRequestHeaders().forEach((k, v) -> lastHeaders.put(k.toLowerCase(), v));
            byte[] body = "{\"preferred_username\":\"trader1\",\"groups\":[\"amps-users\"]}".getBytes(StandardCharsets.UTF_8);
            int status = exchange.getRequestHeaders().containsKey("Authorization") ? 200 : 401;
            exchange.getResponseHeaders().add("Content-Type", "application/json");
            exchange.sendResponseHeaders(status, body.length);
            try (OutputStream out = exchange.getResponseBody()) {
                out.write(body);
            }
        });
        server.createContext("/slow", exchange -> {
            try {
                Thread.sleep(1500);
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
            }
            exchange.sendResponseHeaders(200, -1);
            exchange.close();
        });
        server.createContext("/redirect", exchange -> {
            exchange.getResponseHeaders().add("Location", "http://127.0.0.1:1/elsewhere");
            exchange.sendResponseHeaders(302, -1);
            exchange.close();
        });
        // A pool, so the deliberately slow handler cannot block later requests.
        server.setExecutor(java.util.concurrent.Executors.newCachedThreadPool());
        server.start();
    }

    @AfterAll
    static void stopServer() {
        server.stop(0);
    }

    private static String base() {
        return "http://127.0.0.1:" + server.getAddress().getPort();
    }

    private static AmpsProperties.UserInfo config(String url, Duration connect, Duration read) {
        return new AmpsProperties.UserInfo(url, "preferred_username", "groups", List.of("amps-users"), true,
                connect, read, true);
    }

    @Test
    void sendsTheBearerTokenAndReturnsStatusAndBody() throws Exception {
        var client = new JdkUserInfoClient(config(base() + "/userinfo", Duration.ofSeconds(2), Duration.ofSeconds(2)));

        UserInfoClient.UserInfoResponse response = client.fetch("tok-123");

        assertThat(response.statusCode()).isEqualTo(200);
        assertThat(response.body()).contains("\"preferred_username\":\"trader1\"");
        assertThat(lastHeaders.get("authorization")).containsExactly("Bearer tok-123");
        assertThat(lastHeaders.get("accept")).containsExactly("application/json");
    }

    @Test
    void probeSendsNoTokenAndReturnsTheStatus() throws Exception {
        var client = new JdkUserInfoClient(config(base() + "/userinfo", Duration.ofSeconds(2), Duration.ofSeconds(2)));

        assertThat(client.probe()).isEqualTo(401);
        assertThat(lastHeaders).doesNotContainKey("authorization");
    }

    @Test
    void readTimeoutIsEnforced() {
        var client = new JdkUserInfoClient(config(base() + "/slow", Duration.ofSeconds(2), Duration.ofMillis(200)));

        assertThatThrownBy(() -> client.fetch("tok")).isInstanceOf(HttpTimeoutException.class);
    }

    @Test
    void connectionRefusedIsAnIoException() {
        var client = new JdkUserInfoClient(config("http://127.0.0.1:1/userinfo", Duration.ofMillis(500), Duration.ofMillis(500)));

        assertThatThrownBy(() -> client.fetch("tok")).isInstanceOf(IOException.class);
    }

    @Test
    void redirectsAreNeverFollowed() throws Exception {
        var client = new JdkUserInfoClient(config(base() + "/redirect", Duration.ofSeconds(2), Duration.ofSeconds(2)));

        assertThat(client.fetch("tok").statusCode()).isEqualTo(302);
    }

    @Test
    void emptyTokenIsRefusedBeforeAnyRequest() {
        var client = new JdkUserInfoClient(config(base() + "/userinfo", Duration.ofSeconds(2), Duration.ofSeconds(2)));

        assertThatThrownBy(() -> client.fetch("")).isInstanceOf(IllegalArgumentException.class);
    }

    @Test
    void plainHttpLogsAWarningHttpsDoesNot(CapturedOutput output) {
        new JdkUserInfoClient(config(base() + "/userinfo", Duration.ofSeconds(1), Duration.ofSeconds(1)));
        assertThat(output.getAll()).contains("WARN").contains("clear text");

        long before = output.getAll().lines().filter(l -> l.contains("clear text")).count();
        new JdkUserInfoClient(config("https://login.example.com/userinfo", Duration.ofSeconds(1), Duration.ofSeconds(1)));
        assertThat(output.getAll().lines().filter(l -> l.contains("clear text")).count()).isEqualTo(before);
    }

    @Test
    void constructorRejectsBadConfiguration() {
        assertThatThrownBy(() -> new JdkUserInfoClient(config(" ", Duration.ofSeconds(1), Duration.ofSeconds(1))))
                .isInstanceOf(IllegalStateException.class).hasMessageContaining("amps.auth.userinfo.url");
        assertThatThrownBy(() -> new JdkUserInfoClient(config("ftp://login.example.com/userinfo", Duration.ofSeconds(1), Duration.ofSeconds(1))))
                .isInstanceOf(IllegalStateException.class).hasMessageContaining("http:// or https://");
        assertThatThrownBy(() -> new JdkUserInfoClient(config("/relative/userinfo", Duration.ofSeconds(1), Duration.ofSeconds(1))))
                .isInstanceOf(IllegalStateException.class).hasMessageContaining("http:// or https://");
        assertThatThrownBy(() -> new JdkUserInfoClient(config("https://login.example.com/userinfo", Duration.ZERO, Duration.ofSeconds(1))))
                .isInstanceOf(IllegalStateException.class).hasMessageContaining("connect-timeout");
        assertThatThrownBy(() -> new JdkUserInfoClient(config("https://login.example.com/userinfo", Duration.ofSeconds(1), Duration.ofMillis(-1))))
                .isInstanceOf(IllegalStateException.class).hasMessageContaining("read-timeout");
    }
}
