package com.example.ampsauth;

import java.time.Duration;
import java.util.List;

import jakarta.validation.Valid;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotNull;

import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.boot.context.properties.bind.DefaultValue;
import org.springframework.validation.annotation.Validated;

/**
 * All {@code amps.*} configuration, bound at startup and validated. Unknown values (for example an
 * unknown {@code amps.auth.backend}) fail startup with a binding error naming the property.
 */
@ConfigurationProperties(prefix = "amps")
@Validated
public record AmpsProperties(@Valid @DefaultValue Auth auth, @Valid @DefaultValue Permissions permissions) {

    /** {@code amps.auth.*} */
    public record Auth(@NotNull @DefaultValue("inmemory") Backend backend,
                       @DefaultValue("true") boolean usernamePathMustMatch,
                       @Valid @DefaultValue InMemory inmemory,
                       @Valid @DefaultValue Ldap ldap,
                       @Valid @DefaultValue UserInfo userinfo) {
    }

    /**
     * Credential backends. The property value is matched case-insensitively
     * ({@code inmemory | ldap | userinfo}).
     */
    public enum Backend {
        INMEMORY,
        LDAP,
        USERINFO
    }

    /**
     * {@code amps.auth.userinfo.*}: the AMPS "password" is an OAuth2/OIDC access token, checked by
     * calling the UserInfo endpoint with it. Only validated when the {@code userinfo} backend is
     * selected.
     */
    public record UserInfo(String url,
                           @DefaultValue("preferred_username") String principalClaim,
                           @DefaultValue("groups") String groupsClaim,
                           @DefaultValue List<String> enabledGroups,
                           @DefaultValue("true") boolean principalMustMatch,
                           @DefaultValue("1000ms") Duration connectTimeout,
                           @DefaultValue("2000ms") Duration readTimeout,
                           @DefaultValue("true") boolean healthIndicatorEnabled) {
    }

    /** {@code amps.auth.inmemory.*} */
    public record InMemory(@DefaultValue("false") boolean allowPlaintext,
                           @DefaultValue List<@Valid User> users) {
    }

    /** One in-memory user. {@code password} is in Spring's delegating-encoder format ({@code {bcrypt}...}). */
    public record User(@NotBlank String username, @NotBlank String password) {

        /** Never print the (possibly plaintext) password. */
        @Override
        public String toString() {
            return "User[username=" + username + ", password=****]";
        }
    }

    /** {@code amps.auth.ldap.*}. Only validated when the {@code ldap} backend is selected. */
    public record Ldap(String url,
                       String userPrincipalPattern,
                       @DefaultValue("1000ms") Duration connectTimeout,
                       @DefaultValue("2000ms") Duration readTimeout,
                       @DefaultValue("true") boolean healthIndicatorEnabled) {
    }

    /** {@code amps.permissions.*} */
    public record Permissions(@NotBlank @DefaultValue("classpath:amps/permissions-logon-only.json") String template) {
    }
}
