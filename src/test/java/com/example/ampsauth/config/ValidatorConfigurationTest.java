package com.example.ampsauth.config;

import java.time.Duration;

import com.example.ampsauth.auth.CredentialValidator;
import com.example.ampsauth.auth.InMemoryCredentialValidator;
import com.example.ampsauth.auth.JndiDirContextFactory;
import com.example.ampsauth.auth.LdapCredentialValidator;
import com.example.ampsauth.auth.LdapHealthIndicator;

import org.junit.jupiter.api.Test;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.boot.test.context.runner.ApplicationContextRunner;

import static org.assertj.core.api.Assertions.assertThat;

class ValidatorConfigurationTest {

    @EnableConfigurationProperties(AmpsProperties.class)
    static class PropertiesConfiguration {
    }

    private final ApplicationContextRunner runner = new ApplicationContextRunner()
            .withUserConfiguration(PropertiesConfiguration.class, ValidatorConfiguration.class);

    private static String failureMessages(Throwable failure) {
        StringBuilder messages = new StringBuilder();
        for (Throwable t = failure; t != null; t = t.getCause()) {
            messages.append(t.getMessage()).append('\n');
        }
        return messages.toString();
    }

    @Test
    void inMemoryIsTheDefaultBackend() {
        runner.run(context -> {
            assertThat(context).hasSingleBean(CredentialValidator.class);
            assertThat(context).hasSingleBean(InMemoryCredentialValidator.class);
            assertThat(context).doesNotHaveBean(LdapCredentialValidator.class);
            assertThat(context).doesNotHaveBean(JndiDirContextFactory.class);
            assertThat(context).doesNotHaveBean(LdapHealthIndicator.class);
        });
    }

    @Test
    void inMemoryBackendIsSelectedCaseInsensitively() {
        runner.withPropertyValues("amps.auth.backend=INMEMORY").run(context -> {
            assertThat(context).hasSingleBean(InMemoryCredentialValidator.class);
            assertThat(context.getBean(AmpsProperties.class).auth().backend()).isEqualTo(AmpsProperties.Backend.INMEMORY);
        });
    }

    @Test
    void ldapBackendWiresValidatorFactoryAndHealthIndicator() {
        runner.withPropertyValues(
                "amps.auth.backend=ldap",
                "amps.auth.ldap.url=ldaps://ldap.example.com:636",
                "amps.auth.ldap.user-principal-pattern={0}@corp.example.com",
                "amps.auth.ldap.connect-timeout=250ms",
                "amps.auth.ldap.read-timeout=750ms")
                .run(context -> {
                    assertThat(context).hasSingleBean(CredentialValidator.class);
                    assertThat(context).hasSingleBean(LdapCredentialValidator.class);
                    assertThat(context).hasSingleBean(JndiDirContextFactory.class);
                    assertThat(context).hasSingleBean(LdapHealthIndicator.class);
                    assertThat(context).doesNotHaveBean(InMemoryCredentialValidator.class);
                    AmpsProperties.Ldap ldap = context.getBean(AmpsProperties.class).auth().ldap();
                    assertThat(ldap.connectTimeout()).isEqualTo(Duration.ofMillis(250));
                    assertThat(ldap.readTimeout()).isEqualTo(Duration.ofMillis(750));
                    assertThat(ldap.healthIndicatorEnabled()).isTrue();
                });
    }

    @Test
    void ldapHealthIndicatorCanBeDisabled() {
        runner.withPropertyValues(
                "amps.auth.backend=ldap",
                "amps.auth.ldap.url=ldaps://ldap.example.com:636",
                "amps.auth.ldap.user-principal-pattern={0}@corp.example.com",
                "amps.auth.ldap.health-indicator-enabled=false")
                .run(context -> {
                    assertThat(context).hasSingleBean(LdapCredentialValidator.class);
                    assertThat(context).doesNotHaveBean(LdapHealthIndicator.class);
                });
    }

    @Test
    void ldapTimeoutsHaveDefaults() {
        runner.withPropertyValues(
                "amps.auth.backend=ldap",
                "amps.auth.ldap.url=ldaps://ldap.example.com:636",
                "amps.auth.ldap.user-principal-pattern=uid={0},ou=people,dc=example,dc=com")
                .run(context -> {
                    AmpsProperties.Ldap ldap = context.getBean(AmpsProperties.class).auth().ldap();
                    assertThat(ldap.connectTimeout()).isEqualTo(Duration.ofMillis(1000));
                    assertThat(ldap.readTimeout()).isEqualTo(Duration.ofMillis(2000));
                });
    }

    @Test
    void ldapBackendWithoutUrlFailsStartup() {
        runner.withPropertyValues("amps.auth.backend=ldap", "amps.auth.ldap.url=",
                "amps.auth.ldap.user-principal-pattern={0}@corp.example.com")
                .run(context -> {
                    assertThat(context).hasFailed();
                    assertThat(failureMessages(context.getStartupFailure())).contains("amps.auth.ldap.url");
                });
    }

    @Test
    void unknownBackendFailsStartupWithClearMessage() {
        runner.withPropertyValues("amps.auth.backend=kerberos").run(context -> {
            assertThat(context).hasFailed();
            assertThat(failureMessages(context.getStartupFailure())).contains("amps.auth.backend");
        });
    }

    @Test
    void backendSpellingThatBindsButMatchesNoConditionFailsStartupWithClearMessage() {
        // Relaxed binding accepts "in-memory" for INMEMORY, but no validator condition matches it.
        runner.withPropertyValues("amps.auth.backend=in-memory").run(context -> {
            assertThat(context).hasFailed();
            assertThat(failureMessages(context.getStartupFailure()))
                    .contains("Unsupported amps.auth.backend value 'in-memory'")
                    .contains("inmemory, ldap");
        });
    }

    @Test
    void plaintextPasswordWithoutOptInFailsStartup() {
        runner.withPropertyValues(
                "amps.auth.inmemory.users[0].username=trader1",
                "amps.auth.inmemory.users[0].password={noop}secret")
                .run(context -> {
                    assertThat(context).hasFailed();
                    String messages = failureMessages(context.getStartupFailure());
                    assertThat(messages).contains("allow-plaintext");
                    assertThat(messages).doesNotContain("secret");
                });
    }

    @Test
    void plaintextPasswordWithOptInStarts() {
        runner.withPropertyValues(
                "amps.auth.inmemory.allow-plaintext=true",
                "amps.auth.inmemory.users[0].username=trader1",
                "amps.auth.inmemory.users[0].password={noop}secret")
                .run(context -> {
                    assertThat(context).hasNotFailed();
                    assertThat(context.getBean(CredentialValidator.class).validate("TRADER1", "secret"))
                            .isEqualTo(com.example.ampsauth.auth.ValidationResult.VALID);
                });
    }

    @Test
    void blankUsernameFailsValidation() {
        runner.withPropertyValues(
                "amps.auth.inmemory.allow-plaintext=true",
                "amps.auth.inmemory.users[0].username=",
                "amps.auth.inmemory.users[0].password={noop}secret")
                .run(context -> assertThat(context).hasFailed());
    }

    @Test
    void userToStringMasksPassword() {
        assertThat(new AmpsProperties.User("trader1", "{noop}secret").toString())
                .contains("trader1")
                .doesNotContain("secret");
    }
}
