package com.example.ampsauth;

import org.springframework.boot.autoconfigure.condition.ConditionalOnBooleanProperty;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.ComponentScan;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Import;
import org.springframework.core.env.Environment;
import org.springframework.core.io.ResourceLoader;
import org.springframework.security.crypto.factory.PasswordEncoderFactories;

/**
 * The single integration point of the AMPS authentication feature. Everything the feature needs is
 * registered from here: the {@code amps.*} properties, the components of this package (controller,
 * logon service, parser, filter), the permissions document and exactly one
 * {@link CredentialValidator} selected by {@code amps.auth.backend}
 * ({@code inmemory} | {@code ldap} | {@code userinfo}).
 * <p>
 * When this package sits below the host application's root package it is picked up by the normal
 * component scan; otherwise add {@code @Import(AmpsAuthConfiguration.class)} to a configuration
 * class of the host. Scanning the package twice is harmless (Spring skips duplicate definitions).
 * <p>
 * Any other backend value fails startup with a clear message: the property binds to
 * {@link AmpsProperties.Backend} (rejecting unknown names) and the guard bean at the bottom catches
 * anything that binds but matches neither condition.
 */
@Configuration(proxyBeanMethods = false)
@EnableConfigurationProperties(AmpsProperties.class)
@ComponentScan(basePackageClasses = AmpsAuthConfiguration.class)
public class AmpsAuthConfiguration {

    static final String BACKEND_PROPERTY = "amps.auth.backend";
    static final String LDAP_HEALTH_PROPERTY = "amps.auth.ldap.health-indicator-enabled";
    static final String USERINFO_HEALTH_PROPERTY = "amps.auth.userinfo.health-indicator-enabled";

    /** Loads the permissions document from {@code amps.permissions.template} once, at startup. */
    @Bean
    PermissionsDocument permissionsDocument(AmpsProperties properties, ResourceLoader resourceLoader) {
        return new PermissionsDocument(properties.permissions().template(), resourceLoader);
    }

    @Bean
    @ConditionalOnProperty(name = BACKEND_PROPERTY, havingValue = "inmemory", matchIfMissing = true)
    InMemoryCredentialValidator inMemoryCredentialValidator(AmpsProperties properties) {
        return new InMemoryCredentialValidator(properties.auth().inmemory(),
                PasswordEncoderFactories.createDelegatingPasswordEncoder());
    }

    @Bean
    @ConditionalOnProperty(name = BACKEND_PROPERTY, havingValue = "ldap")
    JndiDirContextFactory jndiDirContextFactory(AmpsProperties properties) {
        return new JndiDirContextFactory(properties.auth().ldap());
    }

    @Bean
    @ConditionalOnProperty(name = BACKEND_PROPERTY, havingValue = "ldap")
    LdapCredentialValidator ldapCredentialValidator(AmpsProperties properties, DirContextFactory dirContextFactory) {
        return new LdapCredentialValidator(properties.auth().ldap(), dirContextFactory);
    }

    /**
     * Optional LDAP reachability indicator. It contributes to {@code /actuator/health} only; the
     * liveness and readiness groups never include it, so a flapping LDAP cannot take the service out
     * of a load balancer.
     */
    @Bean
    @ConditionalOnProperty(name = BACKEND_PROPERTY, havingValue = "ldap")
    @ConditionalOnBooleanProperty(name = LDAP_HEALTH_PROPERTY, matchIfMissing = true)
    LdapHealthIndicator ldapHealthIndicator(AmpsProperties properties, LdapProbe ldapProbe) {
        return new LdapHealthIndicator(ldapProbe, properties.auth().ldap().url());
    }

    @Bean
    @ConditionalOnProperty(name = BACKEND_PROPERTY, havingValue = "userinfo")
    JdkUserInfoClient jdkUserInfoClient(AmpsProperties properties) {
        return new JdkUserInfoClient(properties.auth().userinfo());
    }

    @Bean
    @ConditionalOnProperty(name = BACKEND_PROPERTY, havingValue = "userinfo")
    UserInfoCredentialValidator userInfoCredentialValidator(AmpsProperties properties, UserInfoClient userInfoClient) {
        return new UserInfoCredentialValidator(properties.auth().userinfo(), userInfoClient);
    }

    /** Optional UserInfo reachability indicator; like the LDAP one it never joins the readiness group. */
    @Bean
    @ConditionalOnProperty(name = BACKEND_PROPERTY, havingValue = "userinfo")
    @ConditionalOnBooleanProperty(name = USERINFO_HEALTH_PROPERTY, matchIfMissing = true)
    UserInfoHealthIndicator userInfoHealthIndicator(AmpsProperties properties, UserInfoProbe userInfoProbe) {
        return new UserInfoHealthIndicator(userInfoProbe, properties.auth().userinfo().url());
    }

    /** Declared last on purpose: only reached when no backend condition above matched. */
    @Bean
    @ConditionalOnMissingBean(CredentialValidator.class)
    CredentialValidator unsupportedCredentialBackend(Environment environment) {
        throw new IllegalStateException("Unsupported " + BACKEND_PROPERTY + " value '"
                + environment.getProperty(BACKEND_PROPERTY) + "'; expected one of: inmemory, ldap, userinfo");
    }
}
