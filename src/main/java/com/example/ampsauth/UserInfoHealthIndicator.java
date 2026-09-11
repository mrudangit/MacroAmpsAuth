package com.example.ampsauth;

import java.io.IOException;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.boot.health.contributor.Health;
import org.springframework.boot.health.contributor.HealthIndicator;

/**
 * Reports whether the UserInfo endpoint is reachable (unauthenticated GET, no token). Any HTTP answer,
 * typically 401, counts as UP; only a connection failure or timeout is DOWN. Contributes to
 * {@code /actuator/health} as component {@code userInfo}; never part of the readiness group.
 */
final class UserInfoHealthIndicator implements HealthIndicator {

    private static final Logger log = LoggerFactory.getLogger(UserInfoHealthIndicator.class);

    private final UserInfoProbe probe;
    private final String url;

    UserInfoHealthIndicator(UserInfoProbe probe, String url) {
        this.probe = probe;
        this.url = url;
    }

    @Override
    public Health health() {
        try {
            int status = probe.probe();
            return Health.up().withDetail("url", url).withDetail("status", status).build();
        } catch (IOException e) {
            log.warn("userinfo health check: endpoint unreachable url={} ({})", url, e.getClass().getSimpleName());
            return down(e);
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            return down(e);
        } catch (RuntimeException e) {
            log.warn("userinfo health check failed url={} ({})", url, e.getClass().getSimpleName());
            return down(e);
        }
    }

    private Health down(Exception e) {
        return Health.down().withDetail("url", url).withDetail("error", e.getClass().getSimpleName()).build();
    }
}
