package com.example.ampsauth;

/**
 * Outcome of one logon attempt, in the order the guards are applied (see the response table in the
 * README / spec section 4.3). The controller maps each value to an HTTP status.
 */
public enum LogonOutcome {
    /** Credentials valid: 200 + permissions document. */
    SUCCESS,
    /** No {@code Authorization} header: 401 + {@code WWW-Authenticate: Basic}. */
    NO_CREDENTIALS,
    /** Header present but not usable (wrong scheme, bad base64, no colon, empty username/password): 403. */
    MALFORMED,
    /** Path username differs from the Basic-auth username: 403. */
    USERNAME_MISMATCH,
    /** Backend rejected the credentials: 403. */
    INVALID,
    /** Backend unreachable, timed out or threw: 503. */
    BACKEND_UNAVAILABLE
}
