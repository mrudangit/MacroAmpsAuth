package com.example.ampsauth;

import java.time.Duration;

import io.micrometer.core.instrument.MeterRegistry;
import io.micrometer.core.instrument.simple.SimpleMeterRegistry;
import org.junit.jupiter.api.Test;
import org.springframework.boot.test.context.runner.ApplicationContextRunner;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * {@link AmpsAuthConfiguration} is the only class a host application has to import; these tests
 * boot it on its own (plus the {@link MeterRegistry} the logon service needs).
 */
class AmpsAuthConfigurationTest {

    private final ApplicationContextRunner runner = new ApplicationContextRunner()
            .withBean(MeterRegistry.class, SimpleMeterRegistry::new)
            .withUserConfiguration(AmpsAuthConfiguration.class);

    private static String failureMessages(Throwable failure) {
        StringBuilder messages = new StringBuilder();
        for (Throwable t = failure; t != null; t = t.getCause()) {
            messages.append(t.getMessage()).append('\n');
        }
        return messages.toString();
    }

    @Test
    void theConfigurationAloneWiresTheWholeFeature() {
        runner.run(context -> {
            assertThat(context).hasNotFailed();
            assertThat(context).hasSingleBean(AmpsProperties.class);
            assertThat(context).hasSingleBean(PermissionsController.class);
            assertThat(context).hasSingleBean(LogonService.class);
            assertThat(context).hasSingleBean(BasicAuthorizationParser.class);
            assertThat(context).hasSingleBean(CorrelationIdFilter.class);
            assertThat(context).hasSingleBean(PermissionsDocument.class);
            assertThat(context).hasSingleBean(CredentialValidator.class);
        });
    }

    @Test
    void inMemoryIsTheDefaultBackend() {
        runner.run(context -> {
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
    void userInfoBackendWiresClientValidatorAndHealthIndicator() {
        runner.withPropertyValues(
                "amps.auth.backend=userinfo",
                "amps.auth.userinfo.url=https://login.example.com/oauth2/userinfo",
                "amps.auth.userinfo.enabled-groups=amps-users,amps-admins",
                "amps.auth.userinfo.groups-claim=realm_access.roles")
                .run(context -> {
                    assertThat(context).hasSingleBean(CredentialValidator.class);
                    assertThat(context).hasSingleBean(UserInfoCredentialValidator.class);
                    assertThat(context).hasSingleBean(JdkUserInfoClient.class);
                    assertThat(context).hasSingleBean(UserInfoHealthIndicator.class);
                    assertThat(context).doesNotHaveBean(InMemoryCredentialValidator.class);
                    assertThat(context).doesNotHaveBean(LdapCredentialValidator.class);
                    AmpsProperties.UserInfo userinfo = context.getBean(AmpsProperties.class).auth().userinfo();
                    assertThat(userinfo.enabledGroups()).containsExactly("amps-users", "amps-admins");
                    assertThat(userinfo.principalClaim()).isEqualTo("preferred_username");
                    assertThat(userinfo.groupsClaim()).isEqualTo("realm_access.roles");
                    assertThat(userinfo.principalMustMatch()).isTrue();
                    assertThat(userinfo.connectTimeout()).isEqualTo(Duration.ofMillis(1000));
                    assertThat(userinfo.readTimeout()).isEqualTo(Duration.ofMillis(2000));
                });
    }

    @Test
    void userInfoHealthIndicatorCanBeDisabled() {
        runner.withPropertyValues(
                "amps.auth.backend=userinfo",
                "amps.auth.userinfo.url=https://login.example.com/oauth2/userinfo",
                "amps.auth.userinfo.enabled-groups=amps-users",
                "amps.auth.userinfo.health-indicator-enabled=false")
                .run(context -> {
                    assertThat(context).hasSingleBean(UserInfoCredentialValidator.class);
                    assertThat(context).doesNotHaveBean(UserInfoHealthIndicator.class);
                });
    }

    @Test
    void userInfoBackendWithoutUrlOrGroupsFailsStartup() {
        runner.withPropertyValues("amps.auth.backend=userinfo", "amps.auth.userinfo.enabled-groups=amps-users")
                .run(context -> {
                    assertThat(context).hasFailed();
                    assertThat(failureMessages(context.getStartupFailure())).contains("amps.auth.userinfo.url");
                });
        runner.withPropertyValues("amps.auth.backend=userinfo",
                "amps.auth.userinfo.url=https://login.example.com/oauth2/userinfo")
                .run(context -> {
                    assertThat(context).hasFailed();
                    assertThat(failureMessages(context.getStartupFailure())).contains("enabled-groups");
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
                    .contains("inmemory, ldap, userinfo");
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
                            .isEqualTo(ValidationResult.VALID);
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
    void missingPermissionsTemplateFailsStartup() {
        runner.withPropertyValues("amps.permissions.template=classpath:amps/does-not-exist.json")
                .run(context -> {
                    assertThat(context).hasFailed();
                    assertThat(failureMessages(context.getStartupFailure())).contains("permissions template not found");
                });
    }

    @Test
    void userToStringMasksPassword() {
        assertThat(new AmpsProperties.User("trader1", "{noop}secret").toString())
                .contains("trader1")
                .doesNotContain("secret");
    }
}
