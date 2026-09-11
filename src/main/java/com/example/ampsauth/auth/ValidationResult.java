package com.example.ampsauth.auth;

/** Result of a credential check against the backend. */
public enum ValidationResult {
    VALID,
    INVALID,
    BACKEND_UNAVAILABLE
}
