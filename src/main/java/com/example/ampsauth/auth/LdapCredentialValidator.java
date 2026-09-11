package com.example.ampsauth.auth;

import javax.naming.AuthenticationException;
import javax.naming.CommunicationException;
import javax.naming.NamingException;
import javax.naming.directory.DirContext;

import com.example.ampsauth.config.AmpsProperties;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Authenticates by a simple LDAP bind <em>as the user</em> (no service account, no search). The bind
 * principal is {@code amps.auth.ldap.user-principal-pattern} with {@code {0}} replaced by the
 * username, e.g. {@code {0}@corp.example.com} (Active Directory UPN) or
 * {@code uid={0},ou=people,dc=example,dc=com}.
 * <p>
 * Mapping: bind succeeds -> VALID; {@link AuthenticationException} -> INVALID;
 * {@link CommunicationException}, any other {@link NamingException} or runtime exception ->
 * BACKEND_UNAVAILABLE (logged at ERROR with the exception, never with the password).
 */
public final class LdapCredentialValidator implements CredentialValidator {

    private static final Logger log = LoggerFactory.getLogger(LdapCredentialValidator.class);
    private static final String PLACEHOLDER = "{0}";
    private static final String LDAPS_SCHEME = "ldaps://";

    private final String principalPattern;
    private final String url;
    private final DirContextFactory contextFactory;

    public LdapCredentialValidator(AmpsProperties.Ldap config, DirContextFactory contextFactory) {
        if (config.url() == null || config.url().isBlank()) {
            throw new IllegalStateException("amps.auth.ldap.url must be set when amps.auth.backend=ldap");
        }
        if (config.userPrincipalPattern() == null || !config.userPrincipalPattern().contains(PLACEHOLDER)) {
            throw new IllegalStateException("amps.auth.ldap.user-principal-pattern must contain {0}");
        }
        this.url = config.url().strip();
        this.principalPattern = config.userPrincipalPattern();
        this.contextFactory = contextFactory;
        log.info("LDAP credential backend active url={} principal-pattern={}", url, principalPattern);
        if (!url.regionMatches(true, 0, LDAPS_SCHEME, 0, LDAPS_SCHEME.length())) {
            log.warn("amps.auth.ldap.url={} is not ldaps://; a simple bind sends the password in clear text, "
                    + "use ldaps:// outside isolated test environments", url);
        }
    }

    @Override
    public ValidationResult validate(String username, String password) {
        // Defence in depth: never attempt a bind with an empty password (anonymous bind).
        if (username == null || username.isEmpty() || password == null || password.isEmpty()) {
            return ValidationResult.INVALID;
        }
        String principal = principalPattern.replace(PLACEHOLDER, username);
        DirContext context = null;
        try {
            context = contextFactory.bind(principal, password);
            return ValidationResult.VALID;
        } catch (AuthenticationException e) {
            // The server's diagnostic (e.g. AD "data 52e" = wrong password, 775 = locked) helps operators;
            // it never contains the password.
            log.debug("LDAP bind rejected principal={} reason={}", LogSanitizer.clean(principal),
                    LogSanitizer.clean(e.getMessage(), 512));
            return ValidationResult.INVALID;
        } catch (CommunicationException e) {
            log.error("LDAP server unreachable url={} principal={}", url, LogSanitizer.clean(principal), e);
            return ValidationResult.BACKEND_UNAVAILABLE;
        } catch (NamingException | RuntimeException e) {
            log.error("LDAP bind failed url={} principal={}", url, LogSanitizer.clean(principal), e);
            return ValidationResult.BACKEND_UNAVAILABLE;
        } finally {
            if (context != null) {
                try {
                    context.close();
                } catch (NamingException e) {
                    log.debug("closing LDAP context failed", e);
                }
            }
        }
    }
}
