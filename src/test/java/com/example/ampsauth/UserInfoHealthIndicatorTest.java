package com.example.ampsauth;

import java.io.IOException;
import java.net.http.HttpTimeoutException;

import org.junit.jupiter.api.Test;
import org.springframework.boot.health.contributor.Health;
import org.springframework.boot.health.contributor.Status;

import static org.assertj.core.api.Assertions.assertThat;

class UserInfoHealthIndicatorTest {

    private static final String URL = "https://login.example.com/oauth2/userinfo";

    @Test
    void anyHttpAnswerMeansReachable() {
        Health health = new UserInfoHealthIndicator(() -> 401, URL).health();

        assertThat(health.getStatus()).isEqualTo(Status.UP);
        assertThat(health.getDetails()).containsEntry("url", URL).containsEntry("status", 401);
        assertThat(new UserInfoHealthIndicator(() -> 500, URL).health().getStatus()).isEqualTo(Status.UP);
    }

    @Test
    void unreachableOrTimedOutIsDown() {
        UserInfoProbe refused = () -> {
            throw new IOException("refused");
        };
        UserInfoProbe slow = () -> {
            throw new HttpTimeoutException("timed out");
        };

        assertThat(new UserInfoHealthIndicator(refused, URL).health().getStatus()).isEqualTo(Status.DOWN);
        Health health = new UserInfoHealthIndicator(slow, URL).health();
        assertThat(health.getStatus()).isEqualTo(Status.DOWN);
        assertThat(health.getDetails()).containsEntry("error", "HttpTimeoutException");
    }

    @Test
    void runtimeFailureIsDown() {
        UserInfoProbe broken = () -> {
            throw new IllegalStateException("bad url");
        };

        assertThat(new UserInfoHealthIndicator(broken, URL).health().getStatus()).isEqualTo(Status.DOWN);
    }
}
