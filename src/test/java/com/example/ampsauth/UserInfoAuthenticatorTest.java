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
class UserInfoAuthenticatorTest {

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

    static AmpsProperties.UserInfo config(String principalClaim, String groupsClaim, String... enabledGroups) {
        return new AmpsProperties.UserInfo(URL, principalClaim, groupsClaim, List.of(enabledGroups),
                Duration.ofSeconds(1), Duration.ofSeconds(2), true);
    }

    private static AmpsProperties.UserInfo config() {
        return config("sub", "csgroups", "amps-users", "AMPS-Admins");
    }

    private static UserInfoAuthenticator authenticator(int status, String body) {
        return new UserInfoAuthenticator(config(), new FakeClient(status, body));
    }

    @Test
    void matchingPrincipalInAnEnabledGroupSucceedsAndTheTokenIsSentAsIs() {
        FakeClient client = new FakeClient(200, "{\"sub\":\"U000001\",\"csgroups\":[\"other\",\"amps-users\"]}");
        var authenticator = new UserInfoAuthenticator(config(), client);

        assertThat(authenticator.authenticate("U000001", TOKEN)).isEqualTo(LogonOutcome.SUCCESS);
        assertThat(client.tokens).containsExactly(TOKEN);
    }

    @Test
    void groupComparisonIsCaseInsensitiveAndTrimmed() {
        assertThat(authenticator(200, "{\"sub\":\"U000001\",\"csgroups\":[\" Amps-Admins \"]}")
                .authenticate("U000001", TOKEN)).isEqualTo(LogonOutcome.SUCCESS);
    }

    @Test
    void groupsClaimMayBeASingleDelimitedString() {
        assertThat(authenticator(200, "{\"sub\":\"U000001\",\"csgroups\":\"other amps-users\"}")
                .authenticate("U000001", TOKEN)).isEqualTo(LogonOutcome.SUCCESS);
        assertThat(authenticator(200, "{\"sub\":\"U000001\",\"csgroups\":\"other,amps-users\"}")
                .authenticate("U000001", TOKEN)).isEqualTo(LogonOutcome.SUCCESS);
    }

    @Test
    void noEnabledGroupIsNotEntitled() {
        assertThat(authenticator(200, "{\"sub\":\"U000001\",\"csgroups\":[\"other\",\"amps-users-old\"]}")
                .authenticate("U000001", TOKEN)).isEqualTo(LogonOutcome.NOT_ENTITLED);
    }

    @Test
    void missingOrEmptyGroupsClaimIsNotEntitled() {
        assertThat(authenticator(200, "{\"sub\":\"U000001\"}").authenticate("U000001", TOKEN))
                .isEqualTo(LogonOutcome.NOT_ENTITLED);
        assertThat(authenticator(200, "{\"sub\":\"U000001\",\"csgroups\":[]}").authenticate("U000001", TOKEN))
                .isEqualTo(LogonOutcome.NOT_ENTITLED);
        assertThat(authenticator(200, "{\"sub\":\"U000001\",\"csgroups\":42}").authenticate("U000001", TOKEN))
                .isEqualTo(LogonOutcome.NOT_ENTITLED);
    }

    @Test
    void emptyEnabledGroupsSkipsTheGroupCheckAndWarnsAtStartup(CapturedOutput output) {
        var authenticator = new UserInfoAuthenticator(config("sub", "csgroups"),
                new FakeClient(200, "{\"sub\":\"U000001\"}"));

        assertThat(output.getAll()).contains("WARN").contains("enabled-groups is empty");
        assertThat(authenticator.authenticate("U000001", TOKEN)).isEqualTo(LogonOutcome.SUCCESS);
    }

    @Test
    void principalMismatchIsLoggedAtWarnWithoutTheToken(CapturedOutput output) {
        assertThat(authenticator(200, "{\"sub\":\"U999999\",\"csgroups\":[\"amps-users\"]}")
                .authenticate("U000001", TOKEN)).isEqualTo(LogonOutcome.PRINCIPAL_MISMATCH);

        assertThat(output.getAll())
                .contains("WARN")
                .contains("principal does not match the logon username user=U000001 principal=U999999")
                .doesNotContain(TOKEN);
    }

    @Test
    void principalComparisonIsCaseInsensitive() {
        assertThat(authenticator(200, "{\"sub\":\"u000001\",\"csgroups\":[\"amps-users\"]}")
                .authenticate("U000001", TOKEN)).isEqualTo(LogonOutcome.SUCCESS);
    }

    @Test
    void missingPrincipalClaimIsAMismatch() {
        assertThat(authenticator(200, "{\"name\":\"x\",\"csgroups\":[\"amps-users\"]}").authenticate("U000001", TOKEN))
                .isEqualTo(LogonOutcome.PRINCIPAL_MISMATCH);
    }

    @Test
    void principalIsCheckedBeforeGroups() {
        assertThat(authenticator(200, "{\"sub\":\"U999999\",\"csgroups\":[\"nothing\"]}").authenticate("U000001", TOKEN))
                .isEqualTo(LogonOutcome.PRINCIPAL_MISMATCH);
    }

    @Test
    void numericPrincipalClaimIsCompared() {
        var authenticator = new UserInfoAuthenticator(config("employee_id", "csgroups", "amps-users"),
                new FakeClient(200, "{\"employee_id\":1234,\"csgroups\":[\"amps-users\"]}"));

        assertThat(authenticator.authenticate("1234", TOKEN)).isEqualTo(LogonOutcome.SUCCESS);
    }

    @Test
    void dottedGroupsClaimWalksNestedObjects() {
        var authenticator = new UserInfoAuthenticator(config("sub", "realm_access.roles", "amps-users"),
                new FakeClient(200, "{\"sub\":\"U000001\",\"realm_access\":{\"roles\":[\"amps-users\"]}}"));

        assertThat(authenticator.authenticate("U000001", TOKEN)).isEqualTo(LogonOutcome.SUCCESS);
    }

    @Test
    void namespacedClaimNameContainingDotsIsLookedUpExactly() {
        var authenticator = new UserInfoAuthenticator(config("sub", "https://example.com/groups", "amps-users"),
                new FakeClient(200, "{\"sub\":\"U000001\",\"https://example.com/groups\":[\"amps-users\"]}"));

        assertThat(authenticator.authenticate("U000001", TOKEN)).isEqualTo(LogonOutcome.SUCCESS);
    }

    @Test
    void unauthorizedAndForbiddenMeanInvalidToken() {
        assertThat(authenticator(401, "{\"error\":\"invalid_token\"}").authenticate("U000001", TOKEN))
                .isEqualTo(LogonOutcome.INVALID_TOKEN);
        assertThat(authenticator(403, "").authenticate("U000001", TOKEN)).isEqualTo(LogonOutcome.INVALID_TOKEN);
    }

    @Test
    void otherStatusesAreBackendUnavailable(CapturedOutput output) {
        assertThat(authenticator(500, "oops").authenticate("U000001", TOKEN)).isEqualTo(LogonOutcome.BACKEND_UNAVAILABLE);
        assertThat(authenticator(404, "").authenticate("U000001", TOKEN)).isEqualTo(LogonOutcome.BACKEND_UNAVAILABLE);
        assertThat(authenticator(302, "").authenticate("U000001", TOKEN)).isEqualTo(LogonOutcome.BACKEND_UNAVAILABLE);

        assertThat(output.getAll()).contains("ERROR").contains("status=500").doesNotContain(TOKEN);
    }

    @Test
    void unparseableOrNonObjectBodiesAreBackendUnavailable() {
        assertThat(authenticator(200, "not json").authenticate("U000001", TOKEN)).isEqualTo(LogonOutcome.BACKEND_UNAVAILABLE);
        assertThat(authenticator(200, "[\"amps-users\"]").authenticate("U000001", TOKEN)).isEqualTo(LogonOutcome.BACKEND_UNAVAILABLE);
        assertThat(authenticator(200, "").authenticate("U000001", TOKEN)).isEqualTo(LogonOutcome.BACKEND_UNAVAILABLE);
        assertThat(authenticator(200, null).authenticate("U000001", TOKEN)).isEqualTo(LogonOutcome.BACKEND_UNAVAILABLE);
    }

    @Test
    void ioFailureIsBackendUnavailableAndLoggedWithoutTheToken(CapturedOutput output) {
        FakeClient client = new FakeClient(200, "{}");
        client.ioFailure = new IOException("connection refused");
        var authenticator = new UserInfoAuthenticator(config(), client);

        assertThat(authenticator.authenticate("U000001", TOKEN)).isEqualTo(LogonOutcome.BACKEND_UNAVAILABLE);
        assertThat(output.getAll())
                .contains("ERROR")
                .contains("userinfo endpoint unreachable or timed out url=" + URL + " user=U000001")
                .contains("java.io.IOException: connection refused")
                .doesNotContain(TOKEN);
    }

    @Test
    void runtimeFailureIsBackendUnavailable() {
        FakeClient client = new FakeClient(200, "{}");
        client.runtimeFailure = new IllegalStateException("boom");

        assertThat(new UserInfoAuthenticator(config(), client).authenticate("U000001", TOKEN))
                .isEqualTo(LogonOutcome.BACKEND_UNAVAILABLE);
    }

    @Test
    void tokenWithControlCharactersNeverReachesTheEndpoint() {
        FakeClient client = new FakeClient(200, "{\"sub\":\"U000001\",\"csgroups\":[\"amps-users\"]}");
        var authenticator = new UserInfoAuthenticator(config(), client);

        assertThat(authenticator.authenticate("U000001", "tok\r\nen")).isEqualTo(LogonOutcome.INVALID_TOKEN);
        assertThat(authenticator.authenticate("U000001", "tok en")).isEqualTo(LogonOutcome.INVALID_TOKEN);
        assertThat(client.tokens).isEmpty();
    }

    @Test
    void constructorRejectsIncompleteConfiguration() {
        FakeClient client = new FakeClient(200, "{}");

        assertThatThrownBy(() -> new UserInfoAuthenticator(new AmpsProperties.UserInfo(" ", "sub", "groups",
                List.of("g"), Duration.ofSeconds(1), Duration.ofSeconds(1), true), client))
                .isInstanceOf(IllegalStateException.class).hasMessageContaining("amps.auth.userinfo.url");
        assertThatThrownBy(() -> new UserInfoAuthenticator(config(" ", "groups", "g"), client))
                .isInstanceOf(IllegalStateException.class).hasMessageContaining("principal-claim");
        assertThatThrownBy(() -> new UserInfoAuthenticator(config("sub", "", "g"), client))
                .isInstanceOf(IllegalStateException.class).hasMessageContaining("groups-claim");
    }
}
