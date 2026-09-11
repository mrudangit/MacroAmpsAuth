package com.example.ampsauth.config;

import com.example.ampsauth.auth.CredentialValidator;
import com.example.ampsauth.auth.DirContextFactory;
import com.example.ampsauth.auth.InMemoryCredentialValidator;
import com.example.ampsauth.auth.JndiDirContextFactory;
import com.example.ampsauth.auth.LdapCredentialValidator;
import com.example.ampsauth.auth.LdapHealthIndicator;
import com.example.ampsauth.auth.LdapProbe;

import org.springframework.boot.autoconfigure.condition.ConditionalOnBooleanProperty;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.env.Environment;
import org.springframework.security.crypto.factory.PasswordEncoderFactories;

/**
 * Selects exactly one {@link CredentialValidator} from {@code amps.auth.backend}
 * ({@code inmemory} | {@code ldap}). Any other value fails startup with a clear message: the
 * property binds to {@link AmpsProperties.Backend} (rejecting unknown names) and the guard bean at the
 * bottom catches anything that binds but matches neither condition.
 */
@Configuration(proxyBeanMethods = false)
public class ValidatorConfiguration {

    static final String BACKEND_PROPERTY = "amps.auth.backend";
    static final String LDAP_HEALTH_PROPERTY = "amps.auth.ldap.health-indicator-enabled";

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

    /** Declared last on purpose: only reached when neither backend condition above matched. */
    @Bean
    @ConditionalOnMissingBean(CredentialValidator.class)
    CredentialValidator unsupportedCredentialBackend(Environment environment) {
        throw new IllegalStateException("Unsupported " + BACKEND_PROPERTY + " value '"
                + environment.getProperty(BACKEND_PROPERTY) + "'; expected one of: inmemory, ldap");
    }
}
