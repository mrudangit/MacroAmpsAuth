package com.example.ampsauth;

/**
 * Parsed HTTP Basic credentials. {@link #toString()} masks the password so the record can never leak
 * it through logging or exception messages.
 */
record BasicCredentials(String username, String password) {

    @Override
    public String toString() {
        return "BasicCredentials[username=" + username + ", password=****]";
    }
}
