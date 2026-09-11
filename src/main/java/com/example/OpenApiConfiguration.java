package com.example;

import com.example.ampsauth.AmpsAuthConfiguration;

import io.swagger.v3.oas.models.Components;
import io.swagger.v3.oas.models.OpenAPI;
import io.swagger.v3.oas.models.info.Info;
import io.swagger.v3.oas.models.media.Content;
import io.swagger.v3.oas.models.media.MediaType;
import io.swagger.v3.oas.models.media.ObjectSchema;
import io.swagger.v3.oas.models.responses.ApiResponse;
import io.swagger.v3.oas.models.responses.ApiResponses;
import io.swagger.v3.oas.models.security.SecurityRequirement;
import io.swagger.v3.oas.models.security.SecurityScheme;
import org.springdoc.core.customizers.OperationCustomizer;
import org.springframework.boot.autoconfigure.condition.ConditionalOnBooleanProperty;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

/**
 * OpenAPI description for Swagger UI, used for manual testing in development. Only active when
 * {@code springdoc.api-docs.enabled=true} (the {@code local} profile sets it); production keeps no
 * extra routes. Lives outside the feature package so that package has no springdoc dependency.
 */
@Configuration(proxyBeanMethods = false)
@ConditionalOnBooleanProperty("springdoc.api-docs.enabled")
public class OpenApiConfiguration {

    static final String BASIC_AUTH = "basicAuth";
    private static final String PERMISSIONS_CONTROLLER = AmpsAuthConfiguration.class.getPackageName() + ".PermissionsController";

    @Bean
    OpenAPI ampsAuthOpenApi() {
        return new OpenAPI()
                .info(new Info()
                        .title("AMPS Logon Authentication Service")
                        .version("v1")
                        .description("Authentication web service for the AMPS RESTful Authentication and "
                                + "Entitlement module. Click Authorize and enter the AMPS logon username and "
                                + "password (with the userinfo backend: the OAuth2 access token as the password)."))
                .components(new Components().addSecuritySchemes(BASIC_AUTH, new SecurityScheme()
                        .type(SecurityScheme.Type.HTTP)
                        .scheme("basic")
                        .description("HTTP Basic: the AMPS logon username and password")))
                .addSecurityItem(new SecurityRequirement().addList(BASIC_AUTH));
    }

    /**
     * Documents the logon endpoints: the Authorization header comes from the Authorize button rather
     * than a header field, and the responses follow the service contract.
     */
    @Bean
    OperationCustomizer ampsAuthOperationCustomizer() {
        return (operation, handlerMethod) -> {
            if (!PERMISSIONS_CONTROLLER.equals(handlerMethod.getBeanType().getName())) {
                return operation;
            }
            if (operation.getParameters() != null) {
                operation.getParameters().removeIf(p -> "Authorization".equalsIgnoreCase(p.getName()));
            }
            operation.setSummary("Authenticate an AMPS logon");
            operation.setDescription("Validates the Basic-auth credentials against the configured backend. "
                    + "The identity is always the Basic-auth username; the path variable, if present, is only "
                    + "cross-checked against it.");
            operation.setResponses(new ApiResponses()
                    .addApiResponse("200", new ApiResponse()
                            .description("Credentials valid: the permissions document")
                            .content(new Content().addMediaType("application/json", new MediaType()
                                    .schema(new ObjectSchema())
                                    .example("{\"logon\": true, \"replication-logon\": false}"))))
                    .addApiResponse("401", new ApiResponse()
                            .description("No Authorization header; WWW-Authenticate: Basic realm=\"amps\". Empty body."))
                    .addApiResponse("403", new ApiResponse()
                            .description("Rejected: wrong password or token, non-Basic scheme, malformed header, "
                                    + "empty username or password, or path username mismatch. Empty body."))
                    .addApiResponse("503", new ApiResponse()
                            .description("Credential backend unavailable (LDAP, UserInfo endpoint). Empty body.")));
            return operation;
        };
    }
}
