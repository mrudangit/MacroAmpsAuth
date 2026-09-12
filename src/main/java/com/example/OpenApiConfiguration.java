package com.example;

import com.example.ampsauth.AmpsAuthConfiguration;
import com.example.ampsauth.AmpsProperties;

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

    static final String ACCESS_TOKEN = "accessToken";
    private static final String PERMISSIONS_CONTROLLER = AmpsAuthConfiguration.class.getPackageName() + ".PermissionsController";

    @Bean
    OpenAPI ampsAuthOpenApi(AmpsProperties properties) {
        String header = properties.auth().passwordHeader();
        return new OpenAPI()
                .info(new Info()
                        .title("AMPS Logon Authentication Service")
                        .version("v1")
                        .description("Authentication web service for the AMPS RESTful Authentication and "
                                + "Entitlement module. Click Authorize and paste the OAuth2 access token "
                                + "(AMPS sends the logon password in the " + header + " header); then call the "
                                + "endpoint with the AMPS username in the path."))
                .components(new Components().addSecuritySchemes(ACCESS_TOKEN, new SecurityScheme()
                        .type(SecurityScheme.Type.APIKEY)
                        .in(SecurityScheme.In.HEADER)
                        .name(header)
                        .description("The OAuth2 access token that AMPS forwards as the logon password")))
                .addSecurityItem(new SecurityRequirement().addList(ACCESS_TOKEN));
    }

    /** Documents the logon endpoint: summary, description and the responses of the service contract. */
    @Bean
    OperationCustomizer ampsAuthOperationCustomizer(AmpsProperties properties) {
        String header = properties.auth().passwordHeader();
        return (operation, handlerMethod) -> {
            if (!PERMISSIONS_CONTROLLER.equals(handlerMethod.getBeanType().getName())) {
                return operation;
            }
            if (operation.getParameters() != null) {
                operation.getParameters().removeIf(p -> header.equalsIgnoreCase(p.getName()));
            }
            operation.setSummary("Authenticate an AMPS logon");
            operation.setDescription("Sends the access token from the " + header + " header to the UserInfo "
                    + "endpoint and requires its principal claim to equal the username in the path "
                    + "(and, if configured, membership of an enabled group).");
            operation.setResponses(new ApiResponses()
                    .addApiResponse("200", new ApiResponse()
                            .description("Logon accepted: the permissions document")
                            .content(new Content().addMediaType("application/json", new MediaType()
                                    .schema(new ObjectSchema())
                                    .example("{\"logon\": true, \"replication-logon\": false}"))))
                    .addApiResponse("401", new ApiResponse()
                            .description("No token in the " + header + " header; WWW-Authenticate: Basic realm=\"amps\" "
                                    + "makes the AMPS module retry with its credentials and headers. Empty body."))
                    .addApiResponse("403", new ApiResponse()
                            .description("Refused: token rejected by the identity provider, token of another user, "
                                    + "or user not in an enabled group. Empty body."))
                    .addApiResponse("503", new ApiResponse()
                            .description("UserInfo endpoint unreachable, timed out or unusable. Empty body.")));
            return operation;
        };
    }
}
