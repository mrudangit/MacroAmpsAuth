package com.example.ampsauth.auth;

import javax.naming.AuthenticationException;
import javax.naming.CommunicationException;
import javax.naming.NamingException;
import javax.naming.OperationNotSupportedException;

import org.junit.jupiter.api.Test;
import org.springframework.boot.health.contributor.Health;
import org.springframework.boot.health.contributor.Status;

import static org.assertj.core.api.Assertions.assertThat;

class LdapHealthIndicatorTest {

    private static final String URL = "ldaps://ldap.example.com:636";

    private static LdapProbe failing(NamingException e) {
        return () -> {
            throw e;
        };
    }

    @Test
    void reachableServerIsUp() {
        Health health = new LdapHealthIndicator(() -> { }, URL).health();

        assertThat(health.getStatus()).isEqualTo(Status.UP);
        assertThat(health.getDetails()).containsEntry("url", URL);
    }

    @Test
    void unreachableServerIsDown() {
        Health health = new LdapHealthIndicator(failing(new CommunicationException("refused")), URL).health();

        assertThat(health.getStatus()).isEqualTo(Status.DOWN);
        assertThat(health.getDetails()).containsEntry("error", "CommunicationException");
    }

    @Test
    void serverRefusingAnonymousBindIsStillUp() {
        assertThat(new LdapHealthIndicator(failing(new AuthenticationException("no anonymous")), URL).health().getStatus())
                .isEqualTo(Status.UP);
        assertThat(new LdapHealthIndicator(failing(new OperationNotSupportedException("unwilling")), URL).health().getStatus())
                .isEqualTo(Status.UP);
    }

    @Test
    void otherNamingFailuresAreDown() {
        Health health = new LdapHealthIndicator(failing(new NamingException("read timed out")), URL).health();

        assertThat(health.getStatus()).isEqualTo(Status.DOWN);
    }

    @Test
    void runtimeFailuresAreDown() {
        LdapProbe probe = () -> {
            throw new IllegalStateException("bad url");
        };

        assertThat(new LdapHealthIndicator(probe, URL).health().getStatus()).isEqualTo(Status.DOWN);
    }
}
