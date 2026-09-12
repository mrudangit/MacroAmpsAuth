package com.example.ampsauth;

import org.springframework.boot.autoconfigure.condition.ConditionalOnBooleanProperty;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.ComponentScan;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.io.ResourceLoader;

/**
 * The single integration point of the AMPS authentication feature: the {@code amps.*} properties,
 * the components of this package (controller, logon service, correlation filter), the permissions
 * document, the UserInfo client and the authenticator built on it.
 * <p>
 * When this package sits below the host application's root package it is picked up by the normal
 * component scan; otherwise add {@code @Import(AmpsAuthConfiguration.class)} to a configuration
 * class of the host.
 */
@Configuration(proxyBeanMethods = false)
@EnableConfigurationProperties(AmpsProperties.class)
@ComponentScan(basePackageClasses = AmpsAuthConfiguration.class)
public class AmpsAuthConfiguration {

    static final String USERINFO_HEALTH_PROPERTY = "amps.auth.userinfo.health-indicator-enabled";

    /** Loads the permissions document from {@code amps.permissions.template} once, at startup. */
    @Bean
    PermissionsDocument permissionsDocument(AmpsProperties properties, ResourceLoader resourceLoader) {
        return new PermissionsDocument(properties.permissions().template(), resourceLoader);
    }

    @Bean
    JdkUserInfoClient jdkUserInfoClient(AmpsProperties properties) {
        return new JdkUserInfoClient(properties.auth().userinfo());
    }

    @Bean
    UserInfoAuthenticator userInfoAuthenticator(AmpsProperties properties, UserInfoClient userInfoClient) {
        return new UserInfoAuthenticator(properties.auth().userinfo(), userInfoClient);
    }

    /**
     * Optional UserInfo reachability indicator. It contributes to {@code /actuator/health} only; the
     * liveness and readiness groups never include it, so a flapping identity provider cannot take
     * the service out of a load balancer.
     */
    @Bean
    @ConditionalOnBooleanProperty(name = USERINFO_HEALTH_PROPERTY, matchIfMissing = true)
    UserInfoHealthIndicator userInfoHealthIndicator(AmpsProperties properties, UserInfoProbe userInfoProbe) {
        return new UserInfoHealthIndicator(userInfoProbe, properties.auth().userinfo().url());
    }
}
