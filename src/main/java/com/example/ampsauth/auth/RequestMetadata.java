package com.example.ampsauth.auth;

/**
 * Optional {@code X-AMPS-*} request headers, used for logging only. Any value may be {@code null}.
 */
public record RequestMetadata(String clientName, String remoteAddress, String connectionName) {

    public static final RequestMetadata EMPTY = new RequestMetadata(null, null, null);
}
