package com.example.ampsauth;

import jakarta.servlet.http.HttpServletRequest;

import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RequestHeader;
import org.springframework.web.bind.annotation.RestController;

/**
 * The AMPS-facing endpoint. AMPS calls {@code GET /amps/v1/permissions/{username}} with the logon
 * username substituted into the path ({@code {{USER_NAME}}}) and the logon password (an access
 * token) in the header named by {@code amps.auth.password-header}
 * ({@code <HTTPHeader>X-AMPS-Password: {{AMPS_PASSWORD}}</HTTPHeader>} on the AMPS side).
 * No logic beyond: read path and headers -> {@link LogonService} -> map the outcome to a status.
 * Error responses have empty bodies.
 * <p>
 * A request without the token header gets {@code 401} plus a Basic challenge rather than {@code 403}:
 * the AMPS module discovers the HTTP authentication scheme by first sending a credential-less
 * request and retrying after a {@code 401}, and the AMPS documentation does not say whether the
 * configured {@code HTTPHeader} values are already present on that first request. The challenge
 * makes the module retry with its credentials and headers either way; the Basic credentials
 * themselves are ignored, only the header counts.
 */
@RestController
class PermissionsController {

    public static final String PATH = "/amps/v1/permissions";
    public static final String CLIENT_NAME_HEADER = "X-AMPS-Client-Name";
    public static final String REMOTE_ADDRESS_HEADER = "X-AMPS-Remote-Address";
    public static final String CONNECTION_NAME_HEADER = "X-AMPS-Connection-Name";
    static final String BASIC_CHALLENGE = "Basic realm=\"amps\"";

    private final LogonService logonService;
    private final PermissionsDocument permissionsDocument;
    private final String passwordHeader;

    PermissionsController(LogonService logonService, PermissionsDocument permissionsDocument, AmpsProperties properties) {
        this.logonService = logonService;
        this.permissionsDocument = permissionsDocument;
        this.passwordHeader = properties.auth().passwordHeader();
    }

    @GetMapping(PATH + "/{username}")
    public ResponseEntity<byte[]> permissions(
            @PathVariable("username") String username,
            HttpServletRequest request,
            @RequestHeader(value = CLIENT_NAME_HEADER, required = false) String clientName,
            @RequestHeader(value = REMOTE_ADDRESS_HEADER, required = false) String remoteAddress,
            @RequestHeader(value = CONNECTION_NAME_HEADER, required = false) String connectionName) {
        LogonOutcome outcome = logonService.logon(username, request.getHeader(passwordHeader),
                new RequestMetadata(clientName, remoteAddress, connectionName));
        return switch (outcome) {
            case SUCCESS -> ResponseEntity.ok()
                    .contentType(MediaType.APPLICATION_JSON)
                    .body(permissionsDocument.bytes());
            case NO_TOKEN -> ResponseEntity.status(HttpStatus.UNAUTHORIZED)
                    .header(HttpHeaders.WWW_AUTHENTICATE, BASIC_CHALLENGE)
                    .build();
            case INVALID_TOKEN, PRINCIPAL_MISMATCH, NOT_ENTITLED ->
                    ResponseEntity.status(HttpStatus.FORBIDDEN).build();
            case BACKEND_UNAVAILABLE -> ResponseEntity.status(HttpStatus.SERVICE_UNAVAILABLE).build();
        };
    }
}
