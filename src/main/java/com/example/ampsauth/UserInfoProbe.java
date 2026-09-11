package com.example.ampsauth;

import java.io.IOException;

/** Reachability check used by the optional {@code userInfo} health indicator (no token involved). */
interface UserInfoProbe {

    /**
     * Sends an unauthenticated GET to the UserInfo endpoint and returns the HTTP status (usually 401).
     *
     * @throws IOException          if the endpoint could not be reached or timed out
     * @throws InterruptedException if the calling thread was interrupted
     */
    int probe() throws IOException, InterruptedException;
}
