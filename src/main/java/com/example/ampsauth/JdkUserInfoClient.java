package com.example.ampsauth;

import java.io.IOException;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.time.Duration;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Default {@link UserInfoClient}: the JDK HTTP client with explicit connect and read timeouts taken
 * from {@code amps.auth.userinfo.*}. Redirects are never followed, so the bearer token can only ever
 * be sent to the configured URL. TLS trust for {@code https://} comes from the JVM truststore.
 */
final class JdkUserInfoClient implements UserInfoClient, UserInfoProbe {

    private static final Logger log = LoggerFactory.getLogger(JdkUserInfoClient.class);
    private static final String ACCEPT_JSON = "application/json";

    private final URI url;
    private final Duration readTimeout;
    private final HttpClient client;

    JdkUserInfoClient(AmpsProperties.UserInfo config) {
        this.url = validUrl(config.url());
        if (config.connectTimeout() == null || config.connectTimeout().isNegative() || config.connectTimeout().isZero()) {
            throw new IllegalStateException("amps.auth.userinfo.connect-timeout must be positive");
        }
        if (config.readTimeout() == null || config.readTimeout().isNegative() || config.readTimeout().isZero()) {
            throw new IllegalStateException("amps.auth.userinfo.read-timeout must be positive");
        }
        this.readTimeout = config.readTimeout();
        this.client = HttpClient.newBuilder()
                .connectTimeout(config.connectTimeout())
                .followRedirects(HttpClient.Redirect.NEVER)
                .build();
        if (!"https".equalsIgnoreCase(url.getScheme())) {
            log.warn("amps.auth.userinfo.url={} is not https://; access tokens would be sent in clear text, "
                    + "use https:// outside isolated test environments", url);
        }
    }

    @Override
    public UserInfoResponse fetch(String accessToken) throws IOException, InterruptedException {
        if (accessToken == null || accessToken.isEmpty()) {
            throw new IllegalArgumentException("access token must not be empty");
        }
        HttpRequest request = HttpRequest.newBuilder(url)
                .timeout(readTimeout)
                .header("Authorization", "Bearer " + accessToken)
                .header("Accept", ACCEPT_JSON)
                .GET()
                .build();
        HttpResponse<String> response = client.send(request, HttpResponse.BodyHandlers.ofString(StandardCharsets.UTF_8));
        return new UserInfoResponse(response.statusCode(), response.body());
    }

    /** Unauthenticated GET used by the health indicator; any HTTP answer means the endpoint is reachable. */
    @Override
    public int probe() throws IOException, InterruptedException {
        HttpRequest request = HttpRequest.newBuilder(url)
                .timeout(readTimeout)
                .header("Accept", ACCEPT_JSON)
                .GET()
                .build();
        return client.send(request, HttpResponse.BodyHandlers.discarding()).statusCode();
    }

    String url() {
        return url.toString();
    }

    private static URI validUrl(String value) {
        if (value == null || value.isBlank()) {
            throw new IllegalStateException("amps.auth.userinfo.url must be set when amps.auth.backend=userinfo");
        }
        URI uri;
        try {
            uri = URI.create(value.strip());
        } catch (IllegalArgumentException e) {
            throw new IllegalStateException("amps.auth.userinfo.url is not a valid URL", e);
        }
        String scheme = uri.getScheme();
        if (scheme == null || !(scheme.equalsIgnoreCase("http") || scheme.equalsIgnoreCase("https")) || uri.getHost() == null) {
            throw new IllegalStateException("amps.auth.userinfo.url must be an absolute http:// or https:// URL");
        }
        return uri;
    }
}
