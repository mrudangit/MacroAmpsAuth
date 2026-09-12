package com.example.ampsauth;

import java.io.IOException;

/**
 * Isolates the HTTP call to the UserInfo endpoint so {@link UserInfoAuthenticator} can be tested
 * with a fake. The default implementation is {@link JdkUserInfoClient}.
 */
interface UserInfoClient {

    /**
     * {@code GET <userinfo url>} with {@code Authorization: Bearer <accessToken>}.
     *
     * @throws IOException          if the endpoint could not be reached or timed out
     * @throws InterruptedException if the calling thread was interrupted
     */
    UserInfoResponse fetch(String accessToken) throws IOException, InterruptedException;

    /** Status code and body of a UserInfo response. Never contains the token. */
    record UserInfoResponse(int statusCode, String body) {
    }
}
