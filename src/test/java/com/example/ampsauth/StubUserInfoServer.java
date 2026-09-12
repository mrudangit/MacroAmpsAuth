package com.example.ampsauth;

import java.io.IOException;
import java.io.OutputStream;
import java.io.UncheckedIOException;
import java.net.InetSocketAddress;
import java.nio.charset.StandardCharsets;
import java.util.List;
import java.util.Map;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.concurrent.Executors;

import com.sun.net.httpserver.HttpServer;

/**
 * A UserInfo endpoint stub for integration tests. The bearer token selects the answer; every token
 * below must stay out of the service's log. The principal claim is {@code sub} and the groups claim
 * {@code csgroups}, matching application.yml.
 */
final class StubUserInfoServer implements AutoCloseable {

    static final String USER = "U000001";
    static final String OTHER_USER = "U999999";

    static final String GOOD = "tok-good-8f31c2";
    static final String NO_GROUP = "tok-nogroup-77ab";
    static final String MISMATCH = "tok-mismatch-19cd";
    static final String EXPIRED = "tok-expired-5e0f";
    static final String BOOM = "tok-boom-3a21";
    static final String GARBAGE = "tok-garbage-9c44";
    static final String SLOW = "tok-slow-b6d8";
    static final List<String> ALL_TOKENS = List.of(GOOD, NO_GROUP, MISMATCH, EXPIRED, BOOM, GARBAGE, SLOW);

    private static final Map<String, String> BODIES = Map.of(
            GOOD, "{\"sub\":\"" + USER + "\",\"csmail\":\"u000001@example.com\",\"csgroups\":[\"everyone\",\"AMPS-Users\"]}",
            NO_GROUP, "{\"sub\":\"" + USER + "\",\"csgroups\":[\"everyone\"]}",
            MISMATCH, "{\"sub\":\"" + OTHER_USER + "\",\"csgroups\":[\"amps-users\"]}",
            GARBAGE, "<html>not json</html>");

    private final HttpServer server;
    /** Every Authorization header value received, in order ({@code null} when absent). */
    final List<String> authorizationHeaders = new CopyOnWriteArrayList<>();

    private StubUserInfoServer(HttpServer server) {
        this.server = server;
    }

    static StubUserInfoServer start() {
        HttpServer server;
        try {
            server = HttpServer.create(new InetSocketAddress("127.0.0.1", 0), 0);
        } catch (IOException e) {
            throw new UncheckedIOException(e);
        }
        StubUserInfoServer stub = new StubUserInfoServer(server);
        server.createContext("/oauth2/userinfo", exchange -> {
            String auth = exchange.getRequestHeaders().getFirst("Authorization");
            stub.authorizationHeaders.add(auth == null ? "(none)" : auth);
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
        server.setExecutor(Executors.newCachedThreadPool());
        server.start();
        return stub;
    }

    String url() {
        return "http://127.0.0.1:" + server.getAddress().getPort() + "/oauth2/userinfo";
    }

    @Override
    public void close() {
        server.stop(0);
    }
}
