package com.example.ampsauth;

import java.time.Duration;

import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThatThrownBy;

class JndiDirContextFactoryTest {

    private static AmpsProperties.Ldap config(String url, Duration connect, Duration read) {
        return new AmpsProperties.Ldap(url, "{0}@corp.example.com", connect, read, true);
    }

    @Test
    void refusesEmptyPasswordBeforeTouchingTheNetwork() {
        var factory = new JndiDirContextFactory(config("ldap://192.0.2.1:389", Duration.ofMillis(200), Duration.ofMillis(200)));

        assertThatThrownBy(() -> factory.bind("jdoe@corp.example.com", ""))
                .isInstanceOf(IllegalArgumentException.class);
        assertThatThrownBy(() -> factory.bind("", "pw"))
                .isInstanceOf(IllegalArgumentException.class);
    }

    @Test
    void constructorRejectsMissingUrlAndNonPositiveTimeouts() {
        assertThatThrownBy(() -> new JndiDirContextFactory(config(" ", Duration.ofSeconds(1), Duration.ofSeconds(1))))
                .isInstanceOf(IllegalStateException.class)
                .hasMessageContaining("amps.auth.ldap.url");
        assertThatThrownBy(() -> new JndiDirContextFactory(config("ldap://h:389", Duration.ZERO, Duration.ofSeconds(1))))
                .isInstanceOf(IllegalStateException.class)
                .hasMessageContaining("connect-timeout");
        assertThatThrownBy(() -> new JndiDirContextFactory(config("ldap://h:389", Duration.ofSeconds(1), Duration.ofMillis(-1))))
                .isInstanceOf(IllegalStateException.class)
                .hasMessageContaining("read-timeout");
    }
}
