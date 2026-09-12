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
 * Checks one logon. The AMPS "password" is an OAuth2/OIDC access token: it is sent to the UserInfo
 * endpoint as {@code Authorization: Bearer <token>}, and the response must be a JSON object whose
 * principal claim equals the username AMPS put in the request path (case-insensitive) and, when
 * {@code amps.auth.userinfo.enabled-groups} is set, whose groups claim contains one of those groups
 * (case-insensitive, trimmed).
 * <p>
 * Mapping: 200 + matching principal + group ok -> {@link LogonOutcome#SUCCESS}; 401/403 from the
 * endpoint or a token that cannot be a real token -> {@link LogonOutcome#INVALID_TOKEN}; 200 with
 * another principal -> {@link LogonOutcome#PRINCIPAL_MISMATCH}; 200 without an enabled group ->
 * {@link LogonOutcome#NOT_ENTITLED}; any other status, a non-JSON body, a timeout or an I/O failure
 * -> {@link LogonOutcome#BACKEND_UNAVAILABLE} (logged at ERROR, never with the token).
 * <p>
 * Claims are looked up by exact name first (so namespaced names such as
 * {@code https://example.com/groups} work), then as a dotted path ({@code realm_access.roles}).
 */
class UserInfoAuthenticator {

    private static final Logger log = LoggerFactory.getLogger(UserInfoAuthenticator.class);

    private final UserInfoClient client;
    private final String url;
    private final String principalClaim;
    private final String groupsClaim;
    private final Set<String> enabledGroups;
    private final JsonMapper mapper = JsonMapper.builder().build();

    UserInfoAuthenticator(AmpsProperties.UserInfo config, UserInfoClient client) {
        if (config.url() == null || config.url().isBlank()) {
            throw new IllegalStateException("amps.auth.userinfo.url must be set");
        }
        if (config.principalClaim() == null || config.principalClaim().isBlank()) {
            throw new IllegalStateException("amps.auth.userinfo.principal-claim must not be blank");
        }
        if (config.groupsClaim() == null || config.groupsClaim().isBlank()) {
            throw new IllegalStateException("amps.auth.userinfo.groups-claim must not be blank");
        }
        this.client = client;
        this.url = config.url().strip();
        this.principalClaim = config.principalClaim();
        this.groupsClaim = config.groupsClaim();
        this.enabledGroups = normalise(config.enabledGroups());
        log.info("userinfo authentication active url={} principal-claim={} groups-claim={} enabled-groups={}",
                url, principalClaim, groupsClaim, enabledGroups);
        if (enabledGroups.isEmpty()) {
            log.warn("amps.auth.userinfo.enabled-groups is empty: every user with a valid access token may log on");
        }
    }

    /**
     * @param username    the username from the request path; never null or blank
     * @param accessToken the value of the password header; never null or blank
     */
    LogonOutcome authenticate(String username, String accessToken) {
        String user = LogSanitizer.clean(username);
        if (hasControlCharacters(accessToken)) {
            // Cannot be a real token and must never reach an HTTP header.
            log.debug("access token contains control characters user={}", user);
            return LogonOutcome.INVALID_TOKEN;
        }

        UserInfoClient.UserInfoResponse response;
        try {
            response = client.fetch(accessToken);
        } catch (IOException e) {
            log.error("userinfo endpoint unreachable or timed out url={} user={}", url, user, e);
            return LogonOutcome.BACKEND_UNAVAILABLE;
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            log.error("interrupted while calling the userinfo endpoint url={} user={}", url, user);
            return LogonOutcome.BACKEND_UNAVAILABLE;
        } catch (RuntimeException e) {
            log.error("userinfo call failed url={} user={}", url, user, e);
            return LogonOutcome.BACKEND_UNAVAILABLE;
        }

        int status = response.statusCode();
        if (status == 401 || status == 403) {
            log.debug("userinfo endpoint rejected the access token status={} user={}", status, user);
            return LogonOutcome.INVALID_TOKEN;
        }
        if (status != 200) {
            log.error("userinfo endpoint returned status={} url={} user={}", status, url, user);
            return LogonOutcome.BACKEND_UNAVAILABLE;
        }

        JsonNode root;
        try {
            root = mapper.readTree(response.body() == null ? "" : response.body());
        } catch (JacksonException e) {
            log.error("userinfo response is not valid JSON url={} user={} ({})", url, user, e.getOriginalMessage());
            return LogonOutcome.BACKEND_UNAVAILABLE;
        }
        if (root == null || !root.isObject()) {
            log.error("userinfo response is not a JSON object url={} user={}", url, user);
            return LogonOutcome.BACKEND_UNAVAILABLE;
        }

        String principal = stringOf(claim(root, principalClaim));
        if (principal == null || !principal.equalsIgnoreCase(username)) {
            log.warn("userinfo principal does not match the logon username user={} principal={} claim={}",
                    user, LogSanitizer.clean(principal), principalClaim);
            return LogonOutcome.PRINCIPAL_MISMATCH;
        }

        if (!enabledGroups.isEmpty()) {
            Set<String> groups = groupsOf(claim(root, groupsClaim));
            if (groups.stream().noneMatch(enabledGroups::contains)) {
                log.debug("user={} is in none of the enabled groups (claim={} groups={})",
                        user, groupsClaim, LogSanitizer.clean(String.join(",", groups), 512));
                return LogonOutcome.NOT_ENTITLED;
            }
        }
        return LogonOutcome.SUCCESS;
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
