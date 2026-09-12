package com.example.ampsauth;

import java.io.IOException;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.time.Duration;

/**
 * Minimal HTTP client for integration tests, built on the JDK client so that any header value can
 * be sent verbatim and every status code is returned rather than thrown.
 */
public final class TestHttp {

    private final HttpClient client = HttpClient.newBuilder()
            .version(HttpClient.Version.HTTP_1_1)
            .connectTimeout(Duration.ofSeconds(5))
            .build();
    private final String baseUrl;

    public TestHttp(int port) {
        this.baseUrl = "http://localhost:" + port;
    }

    /** GET {@code path} with the given header name/value pairs. */
    public HttpResponse<byte[]> get(String path, String... headerPairs) {
        return send("GET", path, headerPairs);
    }

    public HttpResponse<byte[]> send(String method, String path, String... headerPairs) {
        HttpRequest.Builder request = HttpRequest.newBuilder(URI.create(baseUrl + path))
                .timeout(Duration.ofSeconds(10))
                .method(method, HttpRequest.BodyPublishers.noBody());
        for (int i = 0; i < headerPairs.length; i += 2) {
            request.header(headerPairs[i], headerPairs[i + 1]);
        }
        try {
            return client.send(request.build(), HttpResponse.BodyHandlers.ofByteArray());
        } catch (IOException e) {
            throw new IllegalStateException("request failed: " + method + " " + path, e);
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            throw new IllegalStateException("interrupted", e);
        }
    }

    public static String body(HttpResponse<byte[]> response) {
        return new String(response.body(), StandardCharsets.UTF_8);
    }
}
