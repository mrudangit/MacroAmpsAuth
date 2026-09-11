package com.example.ampsauth.auth;

/**
 * Pluggable credential backend. Exactly one implementation is active, selected by
 * {@code amps.auth.backend}.
 */
public interface CredentialValidator {

    /** Never called with an empty username or password. Must not retain the password. */
    ValidationResult validate(String username, String password);
}
