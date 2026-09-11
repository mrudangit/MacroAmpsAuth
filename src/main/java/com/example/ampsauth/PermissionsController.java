package com.example.ampsauth;

import java.util.Optional;

import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RequestHeader;
import org.springframework.web.bind.annotation.RestController;

/**
 * The AMPS-facing endpoints. No logic beyond: read headers and path -> {@link LogonService} -> map
 * the outcome to status, body and headers. Error responses have empty bodies.
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

    public PermissionsController(LogonService logonService, PermissionsDocument permissionsDocument) {
        this.logonService = logonService;
        this.permissionsDocument = permissionsDocument;
    }

    /** ResourceURI with {@code {{USER_NAME}}}: the path variable is cross-checked against the Basic username. */
    @GetMapping(PATH + "/{username}")
    public ResponseEntity<byte[]> permissions(
            @PathVariable("username") String username,
            @RequestHeader(value = HttpHeaders.AUTHORIZATION, required = false) String authorization,
            @RequestHeader(value = CLIENT_NAME_HEADER, required = false) String clientName,
            @RequestHeader(value = REMOTE_ADDRESS_HEADER, required = false) String remoteAddress,
            @RequestHeader(value = CONNECTION_NAME_HEADER, required = false) String connectionName) {
        return respond(logonService.logon(Optional.of(username), authorization,
                new RequestMetadata(clientName, remoteAddress, connectionName)));
    }

    /** ResourceURI without {@code {{USER_NAME}}}: identity comes from the Basic username alone. */
    @GetMapping(PATH)
    public ResponseEntity<byte[]> permissions(
            @RequestHeader(value = HttpHeaders.AUTHORIZATION, required = false) String authorization,
            @RequestHeader(value = CLIENT_NAME_HEADER, required = false) String clientName,
            @RequestHeader(value = REMOTE_ADDRESS_HEADER, required = false) String remoteAddress,
            @RequestHeader(value = CONNECTION_NAME_HEADER, required = false) String connectionName) {
        return respond(logonService.logon(Optional.empty(), authorization,
                new RequestMetadata(clientName, remoteAddress, connectionName)));
    }

    private ResponseEntity<byte[]> respond(LogonOutcome outcome) {
        return switch (outcome) {
            case SUCCESS -> ResponseEntity.ok()
                    .contentType(MediaType.APPLICATION_JSON)
                    .body(permissionsDocument.bytes());
            case NO_CREDENTIALS -> ResponseEntity.status(HttpStatus.UNAUTHORIZED)
                    .header(HttpHeaders.WWW_AUTHENTICATE, BASIC_CHALLENGE)
                    .build();
            case MALFORMED, USERNAME_MISMATCH, INVALID -> ResponseEntity.status(HttpStatus.FORBIDDEN).build();
            case BACKEND_UNAVAILABLE -> ResponseEntity.status(HttpStatus.SERVICE_UNAVAILABLE).build();
        };
    }
}
