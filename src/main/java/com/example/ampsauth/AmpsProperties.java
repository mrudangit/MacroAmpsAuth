package com.example.ampsauth;

import java.time.Duration;
import java.util.List;

import jakarta.validation.Valid;
import jakarta.validation.constraints.NotBlank;

import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.boot.context.properties.bind.DefaultValue;
import org.springframework.validation.annotation.Validated;

/**
 * All {@code amps.*} configuration, bound at startup and validated. A missing or blank required
 * value fails startup with a message naming the property.
 */
@ConfigurationProperties(prefix = "amps")
@Validated
public record AmpsProperties(@Valid @DefaultValue Auth auth, @Valid @DefaultValue Permissions permissions) {

    /** {@code amps.auth.*} */
    public record Auth(
            /** Request header AMPS puts the logon password (the access token) in. */
            @NotBlank @DefaultValue("X-AMPS-Password") String passwordHeader,
            @Valid @DefaultValue UserInfo userinfo) {
    }

    /** {@code amps.auth.userinfo.*}: the UserInfo endpoint the access token is checked against. */
    public record UserInfo(
            /** Absolute http(s) URL of the UserInfo endpoint. Required. */
            @NotBlank String url,
            /** Claim that must equal the username in the request path (case-insensitive). */
            @NotBlank @DefaultValue("sub") String principalClaim,
            /** Claim listing the user's groups: a JSON array of strings, or one delimited string. */
            @NotBlank @DefaultValue("groups") String groupsClaim,
            /** Groups that grant logon (any one suffices). Empty = no group check. */
            @DefaultValue List<String> enabledGroups,
            @DefaultValue("1000ms") Duration connectTimeout,
            @DefaultValue("2000ms") Duration readTimeout,
            @DefaultValue("true") boolean healthIndicatorEnabled) {
    }

    /** {@code amps.permissions.*} */
    public record Permissions(@NotBlank @DefaultValue("classpath:amps/permissions-logon-only.json") String template) {
    }
}
