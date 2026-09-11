package com.example.ampsauth;

import java.io.IOException;
import java.time.Duration;
import java.util.ArrayList;
import java.util.List;

import com.example.ampsauth.UserInfoClient.UserInfoResponse;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.springframework.boot.test.system.CapturedOutput;
import org.springframework.boot.test.system.OutputCaptureExtension;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

@ExtendWith(OutputCaptureExtension.class)
class UserInfoCredentialValidatorTest {

    private static final String URL = "https://login.example.com/oauth2/userinfo";
    private static final String TOKEN = "eyJhbGciOiJSUzI1NiJ9.access-token-never-logged-4d2f";

    /** Records the tokens it was called with and answers with a fixed response (or throws). */
    static final class FakeClient implements UserInfoClient {
        final List<String> tokens = new ArrayList<>();
        UserInfoResponse response;
        IOException ioFailure;
        RuntimeException runtimeFailure;

        FakeClient(int status, String body) {
            this.response = new UserInfoResponse(status, body);
        }

        @Override
        public UserInfoResponse fetch(String accessToken) throws IOException {
            tokens.add(accessToken);
            if (ioFailure != null) {
                throw ioFailure;
            }
            if (runtimeFailure != null) {
                throw runtimeFailure;
            }
            return response;
        }
    }

    private static AmpsProperties.UserInfo config(String principalClaim, String groupsClaim, boolean mustMatch,
            String... enabledGroups) {
        return new AmpsProperties.UserInfo(URL, principalClaim, groupsClaim, List.of(enabledGroups), mustMatch,
                Duration.ofSeconds(1), Duration.ofSeconds(2), true);
    }

    private static AmpsProperties.UserInfo config() {
        return config("preferred_username", "groups", true, "amps-users", "AMPS-Admins");
    }

    private static UserInfoCredentialValidator validator(int status, String body) {
        return new UserInfoCredentialValidator(config(), new FakeClient(status, body));
    }

    @Test
    void matchingPrincipalInAnEnabledGroupIsValidAndTheTokenIsSentAsIs() {
        FakeClient client = new FakeClient(200,
                "{\"sub\":\"1234\",\"preferred_username\":\"trader1\",\"groups\":[\"other\",\"amps-users\"]}");
        var validator = new UserInfoCredentialValidator(config(), client);

        assertThat(validator.validate("trader1", TOKEN)).isEqualTo(ValidationResult.VALID);
        assertThat(client.tokens).containsExactly(TOKEN);
    }

    @Test
    void groupComparisonIsCaseInsensitiveAndTrimmed() {
        assertThat(validator(200, "{\"preferred_username\":\"trader1\",\"groups\":[\" Amps-Admins \"]}")
                .validate("trader1", TOKEN)).isEqualTo(ValidationResult.VALID);
    }

    @Test
    void groupsClaimMayBeASingleDelimitedString() {
        assertThat(validator(200, "{\"preferred_username\":\"trader1\",\"groups\":\"other amps-users\"}")
                .validate("trader1", TOKEN)).isEqualTo(ValidationResult.VALID);
        assertThat(validator(200, "{\"preferred_username\":\"trader1\",\"groups\":\"other,amps-users\"}")
                .validate("trader1", TOKEN)).isEqualTo(ValidationResult.VALID);
    }

    @Test
    void noEnabledGroupIsInvalid() {
        assertThat(validator(200, "{\"preferred_username\":\"trader1\",\"groups\":[\"other\",\"amps-users-old\"]}")
                .validate("trader1", TOKEN)).isEqualTo(ValidationResult.INVALID);
    }

    @Test
    void missingOrEmptyGroupsClaimIsInvalid() {
        assertThat(validator(200, "{\"preferred_username\":\"trader1\"}").validate("trader1", TOKEN))
                .isEqualTo(ValidationResult.INVALID);
        assertThat(validator(200, "{\"preferred_username\":\"trader1\",\"groups\":[]}").validate("trader1", TOKEN))
                .isEqualTo(ValidationResult.INVALID);
        assertThat(validator(200, "{\"preferred_username\":\"trader1\",\"groups\":42}").validate("trader1", TOKEN))
                .isEqualTo(ValidationResult.INVALID);
    }

    @Test
    void principalMismatchIsInvalidAndLoggedAtWarn(CapturedOutput output) {
        assertThat(validator(200, "{\"preferred_username\":\"someone-else\",\"groups\":[\"amps-users\"]}")
                .validate("trader1", TOKEN)).isEqualTo(ValidationResult.INVALID);

        assertThat(output.getAll())
                .contains("WARN")
                .contains("principal does not match the logon username user=trader1 principal=someone-else")
                .doesNotContain(TOKEN);
    }

    @Test
    void principalComparisonIsCaseInsensitive() {
        assertThat(validator(200, "{\"preferred_username\":\"Trader1\",\"groups\":[\"amps-users\"]}")
                .validate("TRADER1", TOKEN)).isEqualTo(ValidationResult.VALID);
    }

    @Test
    void missingPrincipalClaimIsInvalid() {
        assertThat(validator(200, "{\"sub\":\"1234\",\"groups\":[\"amps-users\"]}").validate("trader1", TOKEN))
                .isEqualTo(ValidationResult.INVALID);
    }

    @Test
    void principalCheckCanBeDisabled() {
        var validator = new UserInfoCredentialValidator(config("preferred_username", "groups", false, "amps-users"),
                new FakeClient(200, "{\"preferred_username\":\"someone-else\",\"groups\":[\"amps-users\"]}"));

        assertThat(validator.validate("trader1", TOKEN)).isEqualTo(ValidationResult.VALID);
    }

    @Test
    void numericPrincipalClaimIsCompared() {
        var validator = new UserInfoCredentialValidator(config("employee_id", "groups", true, "amps-users"),
                new FakeClient(200, "{\"employee_id\":1234,\"groups\":[\"amps-users\"]}"));

        assertThat(validator.validate("1234", TOKEN)).isEqualTo(ValidationResult.VALID);
    }

    @Test
    void dottedGroupsClaimWalksNestedObjects() {
        var validator = new UserInfoCredentialValidator(config("preferred_username", "realm_access.roles", true, "amps-users"),
                new FakeClient(200, "{\"preferred_username\":\"trader1\",\"realm_access\":{\"roles\":[\"amps-users\"]}}"));

        assertThat(validator.validate("trader1", TOKEN)).isEqualTo(ValidationResult.VALID);
    }

    @Test
    void namespacedClaimNameContainingDotsIsLookedUpExactly() {
        var validator = new UserInfoCredentialValidator(
                config("preferred_username", "https://example.com/groups", true, "amps-users"),
                new FakeClient(200, "{\"preferred_username\":\"trader1\",\"https://example.com/groups\":[\"amps-users\"]}"));

        assertThat(validator.validate("trader1", TOKEN)).isEqualTo(ValidationResult.VALID);
    }

    @Test
    void unauthorizedAndForbiddenMeanInvalidToken() {
        assertThat(validator(401, "{\"error\":\"invalid_token\"}").validate("trader1", TOKEN)).isEqualTo(ValidationResult.INVALID);
        assertThat(validator(403, "").validate("trader1", TOKEN)).isEqualTo(ValidationResult.INVALID);
    }

    @Test
    void otherStatusesAreBackendUnavailable(CapturedOutput output) {
        assertThat(validator(500, "oops").validate("trader1", TOKEN)).isEqualTo(ValidationResult.BACKEND_UNAVAILABLE);
        assertThat(validator(404, "").validate("trader1", TOKEN)).isEqualTo(ValidationResult.BACKEND_UNAVAILABLE);
        assertThat(validator(302, "").validate("trader1", TOKEN)).isEqualTo(ValidationResult.BACKEND_UNAVAILABLE);

        assertThat(output.getAll()).contains("ERROR").contains("status=500").doesNotContain(TOKEN);
    }

    @Test
    void unparseableOrNonObjectBodiesAreBackendUnavailable() {
        assertThat(validator(200, "not json").validate("trader1", TOKEN)).isEqualTo(ValidationResult.BACKEND_UNAVAILABLE);
        assertThat(validator(200, "[\"amps-users\"]").validate("trader1", TOKEN)).isEqualTo(ValidationResult.BACKEND_UNAVAILABLE);
        assertThat(validator(200, "").validate("trader1", TOKEN)).isEqualTo(ValidationResult.BACKEND_UNAVAILABLE);
        assertThat(validator(200, null).validate("trader1", TOKEN)).isEqualTo(ValidationResult.BACKEND_UNAVAILABLE);
    }

    @Test
    void ioFailureIsBackendUnavailableAndLoggedWithoutTheToken(CapturedOutput output) {
        FakeClient client = new FakeClient(200, "{}");
        client.ioFailure = new IOException("connection refused");
        var validator = new UserInfoCredentialValidator(config(), client);

        assertThat(validator.validate("trader1", TOKEN)).isEqualTo(ValidationResult.BACKEND_UNAVAILABLE);
        assertThat(output.getAll())
                .contains("ERROR")
                .contains("userinfo endpoint unreachable or timed out url=" + URL + " user=trader1")
                .contains("java.io.IOException: connection refused")
                .doesNotContain(TOKEN);
    }

    @Test
    void runtimeFailureIsBackendUnavailable() {
        FakeClient client = new FakeClient(200, "{}");
        client.runtimeFailure = new IllegalStateException("boom");

        assertThat(new UserInfoCredentialValidator(config(), client).validate("trader1", TOKEN))
                .isEqualTo(ValidationResult.BACKEND_UNAVAILABLE);
    }

    @Test
    void emptyOrUnusableCredentialsNeverReachTheEndpoint() {
        FakeClient client = new FakeClient(200, "{\"preferred_username\":\"trader1\",\"groups\":[\"amps-users\"]}");
        var validator = new UserInfoCredentialValidator(config(), client);

        assertThat(validator.validate("trader1", "")).isEqualTo(ValidationResult.INVALID);
        assertThat(validator.validate("trader1", null)).isEqualTo(ValidationResult.INVALID);
        assertThat(validator.validate("", TOKEN)).isEqualTo(ValidationResult.INVALID);
        assertThat(validator.validate("trader1", "tok\r\nen")).isEqualTo(ValidationResult.INVALID);

        assertThat(client.tokens).isEmpty();
    }

    @Test
    void constructorRejectsIncompleteConfiguration() {
        FakeClient client = new FakeClient(200, "{}");

        assertThatThrownBy(() -> new UserInfoCredentialValidator(new AmpsProperties.UserInfo(" ", "sub", "groups",
                List.of("g"), true, Duration.ofSeconds(1), Duration.ofSeconds(1), true), client))
                .isInstanceOf(IllegalStateException.class).hasMessageContaining("amps.auth.userinfo.url");
        assertThatThrownBy(() -> new UserInfoCredentialValidator(config("sub", "groups", true), client))
                .isInstanceOf(IllegalStateException.class).hasMessageContaining("enabled-groups");
        assertThatThrownBy(() -> new UserInfoCredentialValidator(config("sub", "groups", true, " ", ""), client))
                .isInstanceOf(IllegalStateException.class).hasMessageContaining("enabled-groups");
        assertThatThrownBy(() -> new UserInfoCredentialValidator(config(" ", "groups", true, "g"), client))
                .isInstanceOf(IllegalStateException.class).hasMessageContaining("principal-claim");
        assertThatThrownBy(() -> new UserInfoCredentialValidator(config("sub", "", true, "g"), client))
                .isInstanceOf(IllegalStateException.class).hasMessageContaining("groups-claim");
    }
}
