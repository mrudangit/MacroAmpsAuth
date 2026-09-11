package com.example.ampsauth;

import java.io.IOException;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Locale;
import java.util.Set;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import tools.jackson.core.JacksonException;
import tools.jackson.databind.JsonNode;
import tools.jackson.databind.json.JsonMapper;

/**
 * Treats the AMPS "password" as an OAuth2/OIDC <em>access token</em> (for example from a PKCE flow)
 * and checks it by calling the UserInfo endpoint with {@code Authorization: Bearer <token>}.
 * <p>
 * Mapping: HTTP 200 whose principal claim matches the logon username (case-insensitive, unless
 * {@code principal-must-match=false}) and whose groups claim contains at least one of
 * {@code enabled-groups} (case-insensitive) -> VALID; 200 without such a group, or with a different
 * principal, or HTTP 401/403 -> INVALID; any other status, a non-JSON body, a timeout or an I/O
 * failure -> BACKEND_UNAVAILABLE (logged at ERROR, never with the token).
 * <p>
 * Claims are looked up by exact name first (so namespaced names such as
 * {@code https://example.com/groups} work), then as a dotted path ({@code realm_access.roles}). The
 * groups claim may be a JSON array of strings or a single string of space- or comma-separated names.
 */
final class UserInfoCredentialValidator implements CredentialValidator {

    private static final Logger log = LoggerFactory.getLogger(UserInfoCredentialValidator.class);

    private final UserInfoClient client;
    private final String url;
    private final String principalClaim;
    private final String groupsClaim;
    private final Set<String> enabledGroups;
    private final boolean principalMustMatch;
    private final JsonMapper mapper = JsonMapper.builder().build();

    UserInfoCredentialValidator(AmpsProperties.UserInfo config, UserInfoClient client) {
        if (config.url() == null || config.url().isBlank()) {
            throw new IllegalStateException("amps.auth.userinfo.url must be set when amps.auth.backend=userinfo");
        }
        if (config.principalClaim() == null || config.principalClaim().isBlank()) {
            throw new IllegalStateException("amps.auth.userinfo.principal-claim must not be blank");
        }
        if (config.groupsClaim() == null || config.groupsClaim().isBlank()) {
            throw new IllegalStateException("amps.auth.userinfo.groups-claim must not be blank");
        }
        this.enabledGroups = normalise(config.enabledGroups());
        if (enabledGroups.isEmpty()) {
            throw new IllegalStateException("amps.auth.userinfo.enabled-groups must list at least one group "
                    + "when amps.auth.backend=userinfo");
        }
        this.client = client;
        this.url = config.url().strip();
        this.principalClaim = config.principalClaim();
        this.groupsClaim = config.groupsClaim();
        this.principalMustMatch = config.principalMustMatch();
        log.info("userinfo credential backend active url={} principal-claim={} groups-claim={} "
                + "principal-must-match={} enabled-groups={}", url, principalClaim, groupsClaim,
                principalMustMatch, enabledGroups);
    }

    @Override
    public ValidationResult validate(String username, String accessToken) {
        // Defence in depth: never call the endpoint without a token.
        if (username == null || username.isEmpty() || accessToken == null || accessToken.isEmpty()) {
            return ValidationResult.INVALID;
        }
        if (hasControlCharacters(accessToken)) {
            // Cannot be a real token and must never reach an HTTP header.
            log.debug("access token contains control characters user={}", LogSanitizer.clean(username));
            return ValidationResult.INVALID;
        }
        String user = LogSanitizer.clean(username);

        UserInfoClient.UserInfoResponse response;
        try {
            response = client.fetch(accessToken);
        } catch (IOException e) {
            log.error("userinfo endpoint unreachable or timed out url={} user={}", url, user, e);
            return ValidationResult.BACKEND_UNAVAILABLE;
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            log.error("interrupted while calling the userinfo endpoint url={} user={}", url, user);
            return ValidationResult.BACKEND_UNAVAILABLE;
        } catch (RuntimeException e) {
            log.error("userinfo call failed url={} user={}", url, user, e);
            return ValidationResult.BACKEND_UNAVAILABLE;
        }

        int status = response.statusCode();
        if (status == 401 || status == 403) {
            log.debug("userinfo endpoint rejected the access token status={} user={}", status, user);
            return ValidationResult.INVALID;
        }
        if (status != 200) {
            log.error("userinfo endpoint returned status={} url={} user={}", status, url, user);
            return ValidationResult.BACKEND_UNAVAILABLE;
        }

        JsonNode root;
        try {
            root = mapper.readTree(response.body() == null ? "" : response.body());
        } catch (JacksonException e) {
            log.error("userinfo response is not valid JSON url={} user={} ({})", url, user, e.getOriginalMessage());
            return ValidationResult.BACKEND_UNAVAILABLE;
        }
        if (root == null || !root.isObject()) {
            log.error("userinfo response is not a JSON object url={} user={}", url, user);
            return ValidationResult.BACKEND_UNAVAILABLE;
        }

        if (principalMustMatch) {
            String principal = stringOf(claim(root, principalClaim));
            if (principal == null || !principal.equalsIgnoreCase(username)) {
                log.warn("userinfo principal does not match the logon username user={} principal={} claim={}",
                        user, LogSanitizer.clean(principal), principalClaim);
                return ValidationResult.INVALID;
            }
        }

        Set<String> groups = groupsOf(claim(root, groupsClaim));
        if (groups.stream().noneMatch(enabledGroups::contains)) {
            log.debug("user={} is not in an enabled group (claim={} groups={})", user, groupsClaim, groups);
            return ValidationResult.INVALID;
        }
        return ValidationResult.VALID;
    }

    /** Exact key first (namespaced claims contain dots), then a dotted path into nested objects. */
    static JsonNode claim(JsonNode root, String name) {
        JsonNode direct = root.get(name);
        if (direct != null) {
            return direct;
        }
        JsonNode node = root;
        for (String part : name.split("\\.")) {
            if (node == null || !node.isObject()) {
                return null;
            }
            node = node.get(part);
        }
        return node;
    }

    private static String stringOf(JsonNode node) {
        if (node == null) {
            return null;
        }
        if (node.isString()) {
            return node.stringValue();
        }
        return node.isNumber() ? node.asString() : null;
    }

    /** Group names, trimmed and lower-cased: from a JSON array of strings or one delimited string. */
    static Set<String> groupsOf(JsonNode node) {
        Set<String> groups = new LinkedHashSet<>();
        if (node == null) {
            return groups;
        }
        if (node.isArray()) {
            for (JsonNode element : node) {
                if (element.isString()) {
                    addGroup(groups, element.stringValue());
                }
            }
        } else if (node.isString()) {
            for (String name : node.stringValue().split("[,\\s]+")) {
                addGroup(groups, name);
            }
        }
        return groups;
    }

    private static Set<String> normalise(List<String> names) {
        Set<String> groups = new LinkedHashSet<>();
        if (names != null) {
            names.forEach(name -> addGroup(groups, name));
        }
        return groups;
    }

    private static void addGroup(Set<String> groups, String name) {
        if (name != null && !name.isBlank()) {
            groups.add(name.strip().toLowerCase(Locale.ROOT));
        }
    }

    private static boolean hasControlCharacters(String value) {
        for (int i = 0; i < value.length(); i++) {
            if (Character.isISOControl(value.charAt(i))) {
                return true;
            }
        }
        return false;
    }
}
