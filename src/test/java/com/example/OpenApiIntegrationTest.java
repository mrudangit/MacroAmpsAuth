package com.example;

import java.net.http.HttpResponse;

import com.example.ampsauth.TestHttp;

import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.test.context.SpringBootTest;

import static org.assertj.core.api.Assertions.assertThat;

/** Swagger UI and the OpenAPI document exist only when the springdoc properties switch them on. */
class OpenApiIntegrationTest {

    @Nested
    @SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT)
    class DisabledByDefault {

        @Value("${local.server.port}")
        private int port;

        @Test
        void noSwaggerRoutesExist() {
            TestHttp http = new TestHttp(port);

            assertThat(http.get("/v3/api-docs").statusCode()).isEqualTo(404);
            assertThat(http.get("/swagger-ui.html").statusCode()).isEqualTo(404);
            assertThat(http.get("/swagger-ui/index.html").statusCode()).isEqualTo(404);
        }
    }

    @Nested
    @SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT, properties = {
            "springdoc.api-docs.enabled=true",
            "springdoc.swagger-ui.enabled=true"
    })
    class EnabledByProperties {

        @Value("${local.server.port}")
        private int port;

        @Test
        void openApiDocumentDescribesTheLogonEndpointAndTheTokenHeader() {
            TestHttp http = new TestHttp(port);

            HttpResponse<byte[]> docs = http.get("/v3/api-docs");
            assertThat(docs.statusCode()).isEqualTo(200);
            String json = TestHttp.body(docs);
            assertThat(json)
                    .contains("\"/amps/v1/permissions/{username}\"")
                    .doesNotContain("\"/amps/v1/permissions\"")
                    .contains("\"accessToken\"")
                    .contains("\"type\":\"apiKey\"")
                    .contains("\"in\":\"header\"")
                    .contains("\"name\":\"X-AMPS-Password\"")
                    .contains("\"401\"")
                    .contains("\"403\"")
                    .contains("\"503\"")
                    .doesNotContain("basicAuth")
                    .doesNotContain("/actuator");
            // The token header is offered through Authorize, not as a per-operation parameter.
            assertThat(json.split("\"X-AMPS-Password\"")).hasSize(2);
        }

        @Test
        void swaggerUiIsServed() {
            TestHttp http = new TestHttp(port);

            assertThat(http.get("/swagger-ui/index.html").statusCode()).isEqualTo(200);
            // /swagger-ui.html redirects to the UI; the test client does not follow redirects.
            assertThat(http.get("/swagger-ui.html").statusCode()).isIn(200, 302);
        }

        @Test
        void theApiItselfStillBehavesTheSame() {
            TestHttp http = new TestHttp(port);

            assertThat(http.get("/amps/v1/permissions/U000001").statusCode()).isEqualTo(401);
        }
    }
}
