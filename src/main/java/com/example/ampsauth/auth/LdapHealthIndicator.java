package com.example.ampsauth.auth;

import javax.naming.CommunicationException;
import javax.naming.NamingException;
import javax.naming.NamingSecurityException;
import javax.naming.OperationNotSupportedException;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.boot.health.contributor.Health;
import org.springframework.boot.health.contributor.HealthIndicator;

/**
 * Reports whether the LDAP server is reachable (anonymous connect, no credentials). Contributes to
 * {@code /actuator/health} as component {@code ldap}; it is deliberately not part of the readiness
 * group. A server that is reachable but refuses anonymous binds counts as UP.
 */
public final class LdapHealthIndicator implements HealthIndicator {

    private static final Logger log = LoggerFactory.getLogger(LdapHealthIndicator.class);

    private final LdapProbe probe;
    private final String url;

    public LdapHealthIndicator(LdapProbe probe, String url) {
        this.probe = probe;
        this.url = url;
    }

    @Override
    public Health health() {
        try {
            probe.probe();
            return Health.up().withDetail("url", url).build();
        } catch (CommunicationException e) {
            log.warn("LDAP health check: server unreachable url={} ({})", url, e.getClass().getSimpleName());
            return down(e);
        } catch (NamingSecurityException | OperationNotSupportedException e) {
            // Reachable: the server answered, it just does not allow anonymous binds.
            return Health.up().withDetail("url", url).withDetail("note", "anonymous bind refused").build();
        } catch (NamingException | RuntimeException e) {
            log.warn("LDAP health check failed url={} ({})", url, e.getClass().getSimpleName());
            return down(e);
        }
    }

    private Health down(Exception e) {
        return Health.down().withDetail("url", url).withDetail("error", e.getClass().getSimpleName()).build();
    }
}
