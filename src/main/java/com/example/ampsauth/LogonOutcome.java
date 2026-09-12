package com.example.ampsauth;

/**
 * Outcome of one logon attempt, in the order the checks are applied. The controller maps each value
 * to an HTTP status; the log line and the metrics carry the name.
 */
public enum LogonOutcome {
    /** Token accepted, principal matches, group check passed: 200 + permissions document. */
    SUCCESS,
    /**
     * The password header is missing or blank: 401 + {@code WWW-Authenticate: Basic}, the challenge
     * that makes the AMPS module retry with its credentials and headers. Nothing is sent to the
     * UserInfo endpoint.
     */
    NO_TOKEN,
    /** The UserInfo endpoint answered 401 or 403, or the token could never be valid: 403. */
    INVALID_TOKEN,
    /** The token is valid but belongs to a different user than the one in the path: 403. */
    PRINCIPAL_MISMATCH,
    /** The token is valid and the user matches, but is in none of the enabled groups: 403. */
    NOT_ENTITLED,
    /** UserInfo endpoint unreachable, timed out, or answered something unusable: 503. */
    BACKEND_UNAVAILABLE
}
