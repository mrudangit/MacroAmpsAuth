package com.example.ampsauth;

import java.net.http.HttpResponse;

import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.test.context.SpringBootTest;

import static org.assertj.core.api.Assertions.assertThat;

@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT, properties = {
        "amps.auth.username-path-must-match=false",
        "amps.auth.inmemory.allow-plaintext=true",
        "amps.auth.inmemory.users[0].username=trader1",
        "amps.auth.inmemory.users[0].password={noop}secret-1"
})
class UsernamePathMatchDisabledIntegrationTest {

    @Value("${local.server.port}")
    private int port;

    @Test
    void mismatchedPathUsernameIsAcceptedWhenTheCheckIsDisabled() {
        TestHttp http = new TestHttp(port);

        HttpResponse<byte[]> response = http.get("/amps/v1/permissions/other",
                "Authorization", TestHttp.basic("trader1", "secret-1"));

        assertThat(response.statusCode()).isEqualTo(200);
        assertThat(TestHttp.body(response)).contains("\"logon\"");
    }

    @Test
    void credentialsAreStillChecked() {
        TestHttp http = new TestHttp(port);

        assertThat(http.get("/amps/v1/permissions/other", "Authorization", TestHttp.basic("trader1", "wrong")).statusCode())
                .isEqualTo(403);
    }
}
