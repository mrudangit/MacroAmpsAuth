package com.example.ampsauth;

/**
 * Thrown by {@link BasicAuthorizationParser} when an {@code Authorization} header is present but
 * unusable. The message is a short reason code and never contains any part of the header.
 */
class MalformedCredentialsException extends RuntimeException {

    public MalformedCredentialsException(String reason) {
        // No stack trace: this is a normal, frequent outcome, not a programming error.
        super(reason, null, false, false);
    }
}
