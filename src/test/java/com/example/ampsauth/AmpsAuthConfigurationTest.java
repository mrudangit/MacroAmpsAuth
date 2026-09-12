package com.example.ampsauth;

import java.time.Duration;

import io.micrometer.core.instrument.MeterRegistry;
import io.micrometer.core.instrument.simple.SimpleMeterRegistry;
import org.junit.jupiter.api.Test;
import org.springframework.boot.test.context.runner.ApplicationContextRunner;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * {@link AmpsAuthConfiguration} is the only class a host application has to import; these tests
 * boot it on its own (plus the {@link MeterRegistry} the logon service needs). No application.yml
 * is loaded here, so the values seen are the record defaults.
 */
class AmpsAuthConfigurationTest {

    private static final String URL = "https://login.example.com/oauth2/userinfo";

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
        runner.withPropertyValues("amps.auth.userinfo.url=" + URL, "amps.auth.userinfo.enabled-groups=amps-users")
                .run(context -> {
                    assertThat(context).hasNotFailed();
                    assertThat(context).hasSingleBean(AmpsProperties.class);
                    assertThat(context).hasSingleBean(PermissionsController.class);
                    assertThat(context).hasSingleBean(LogonService.class);
                    assertThat(context).hasSingleBean(CorrelationIdFilter.class);
                    assertThat(context).hasSingleBean(PermissionsDocument.class);
                    assertThat(context).hasSingleBean(JdkUserInfoClient.class);
                    assertThat(context).hasSingleBean(UserInfoAuthenticator.class);
                    assertThat(context).hasSingleBean(UserInfoHealthIndicator.class);
                });
    }

    @Test
    void defaultsAreTheDocumentedOnes() {
        runner.withPropertyValues("amps.auth.userinfo.url=" + URL).run(context -> {
            AmpsProperties properties = context.getBean(AmpsProperties.class);
            assertThat(properties.auth().passwordHeader()).isEqualTo("X-AMPS-Password");
            AmpsProperties.UserInfo userinfo = properties.auth().userinfo();
            assertThat(userinfo.principalClaim()).isEqualTo("sub");
            assertThat(userinfo.groupsClaim()).isEqualTo("groups");
            assertThat(userinfo.enabledGroups()).isEmpty();
            assertThat(userinfo.connectTimeout()).isEqualTo(Duration.ofMillis(1000));
            assertThat(userinfo.readTimeout()).isEqualTo(Duration.ofMillis(2000));
            assertThat(userinfo.healthIndicatorEnabled()).isTrue();
            assertThat(properties.permissions().template()).isEqualTo("classpath:amps/permissions-logon-only.json");
        });
    }

    @Test
    void everyPropertyCanBeOverridden() {
        runner.withPropertyValues(
                "amps.auth.password-header=X-Token",
                "amps.auth.userinfo.url=" + URL,
                "amps.auth.userinfo.principal-claim=preferred_username",
                "amps.auth.userinfo.groups-claim=realm_access.roles",
                "amps.auth.userinfo.enabled-groups=amps-users,amps-admins",
                "amps.auth.userinfo.connect-timeout=250ms",
                "amps.auth.userinfo.read-timeout=750ms")
                .run(context -> {
                    AmpsProperties properties = context.getBean(AmpsProperties.class);
                    assertThat(properties.auth().passwordHeader()).isEqualTo("X-Token");
                    AmpsProperties.UserInfo userinfo = properties.auth().userinfo();
                    assertThat(userinfo.principalClaim()).isEqualTo("preferred_username");
                    assertThat(userinfo.groupsClaim()).isEqualTo("realm_access.roles");
                    assertThat(userinfo.enabledGroups()).containsExactly("amps-users", "amps-admins");
                    assertThat(userinfo.connectTimeout()).isEqualTo(Duration.ofMillis(250));
                    assertThat(userinfo.readTimeout()).isEqualTo(Duration.ofMillis(750));
                });
    }

    @Test
    void healthIndicatorCanBeDisabled() {
        runner.withPropertyValues("amps.auth.userinfo.url=" + URL, "amps.auth.userinfo.health-indicator-enabled=false")
                .run(context -> {
                    assertThat(context).hasSingleBean(UserInfoAuthenticator.class);
                    assertThat(context).doesNotHaveBean(UserInfoHealthIndicator.class);
                });
    }

    @Test
    void missingUserInfoUrlFailsStartup() {
        runner.run(context -> {
            assertThat(context).hasFailed();
            assertThat(failureMessages(context.getStartupFailure())).contains("userinfo.url");
        });
        runner.withPropertyValues("amps.auth.userinfo.url=ftp://login.example.com/userinfo").run(context -> {
            assertThat(context).hasFailed();
            assertThat(failureMessages(context.getStartupFailure())).contains("http:// or https://");
        });
    }

    @Test
    void blankPasswordHeaderOrClaimNamesFailStartup() {
        runner.withPropertyValues("amps.auth.userinfo.url=" + URL, "amps.auth.password-header=").run(context -> {
            assertThat(context).hasFailed();
            assertThat(failureMessages(context.getStartupFailure())).contains("passwordHeader");
        });
        runner.withPropertyValues("amps.auth.userinfo.url=" + URL, "amps.auth.userinfo.principal-claim= ").run(context -> {
            assertThat(context).hasFailed();
            assertThat(failureMessages(context.getStartupFailure())).contains("principalClaim");
        });
    }

    @Test
    void badPermissionsTemplateFailsStartup() {
        runner.withPropertyValues("amps.auth.userinfo.url=" + URL,
                "amps.permissions.template=classpath:amps-test/invalid.json").run(context -> {
            assertThat(context).hasFailed();
            assertThat(failureMessages(context.getStartupFailure())).contains("not valid JSON");
        });
        runner.withPropertyValues("amps.auth.userinfo.url=" + URL,
                "amps.permissions.template=classpath:amps-test/does-not-exist.json").run(context -> {
            assertThat(context).hasFailed();
            assertThat(failureMessages(context.getStartupFailure())).contains("not found");
        });
    }
}
