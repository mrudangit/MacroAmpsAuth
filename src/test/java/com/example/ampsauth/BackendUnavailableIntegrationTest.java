package com.example.ampsauth;

import java.net.http.HttpResponse;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.context.bean.override.mockito.MockitoBean;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.mockito.Mockito.when;

/** The controller wired to a mocked {@link CredentialValidator}. */
@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT)
class BackendUnavailableIntegrationTest {

    private static final String PATH = "/amps/v1/permissions";

    @MockitoBean
    private CredentialValidator validator;

    @Value("${local.server.port}")
    private int port;

    private TestHttp http;

    @BeforeEach
    void setUp() {
        http = new TestHttp(port);
    }

    @Test
    void backendUnavailableIsServiceUnavailableWithEmptyBody() {
        when(validator.validate("trader1", "pw")).thenReturn(ValidationResult.BACKEND_UNAVAILABLE);

        HttpResponse<byte[]> response = http.get(PATH + "/trader1",
                "Authorization", TestHttp.basic("trader1", "pw"),
                "X-AMPS-Correlation-Id", "corr-503");

        assertThat(response.statusCode()).isEqualTo(503);
        assertThat(response.body()).isEmpty();
        assertThat(response.headers().firstValue("Cache-Control")).hasValue("no-store");
        assertThat(response.headers().firstValue("X-AMPS-Correlation-Id")).hasValue("corr-503");
    }

    @Test
    void backendExceptionIsServiceUnavailableWithEmptyBody() {
        when(validator.validate(anyString(), anyString())).thenThrow(new IllegalStateException("ldap exploded"));

        HttpResponse<byte[]> response = http.get(PATH + "/trader1", "Authorization", TestHttp.basic("trader1", "pw"));

        assertThat(response.statusCode()).isEqualTo(503);
        assertThat(response.body()).isEmpty();
    }

    @Test
    void validAndInvalidResultsMapToTheirStatuses() {
        when(validator.validate("trader1", "good")).thenReturn(ValidationResult.VALID);
        when(validator.validate("trader1", "bad")).thenReturn(ValidationResult.INVALID);

        assertThat(http.get(PATH + "/trader1", "Authorization", TestHttp.basic("trader1", "good")).statusCode()).isEqualTo(200);
        assertThat(http.get(PATH + "/trader1", "Authorization", TestHttp.basic("trader1", "bad")).statusCode()).isEqualTo(403);
        verify(validator).validate("trader1", "good");
        verify(validator).validate("trader1", "bad");
    }

    @Test
    void guardsShortCircuitBeforeTheBackendIsCalled() {
        assertThat(http.get(PATH + "/trader1").statusCode()).isEqualTo(401);
        assertThat(http.get(PATH + "/trader1", "Authorization", "Bearer x").statusCode()).isEqualTo(403);
        assertThat(http.get(PATH + "/trader1", "Authorization", "Basic %%%").statusCode()).isEqualTo(403);
        assertThat(http.get(PATH + "/trader1", "Authorization", TestHttp.basic("trader1", "")).statusCode()).isEqualTo(403);
        assertThat(http.get(PATH + "/trader1", "Authorization", TestHttp.basic("", "pw")).statusCode()).isEqualTo(403);
        assertThat(http.get(PATH + "/other", "Authorization", TestHttp.basic("trader1", "pw")).statusCode()).isEqualTo(403);

        verifyNoInteractions(validator);
    }
}
