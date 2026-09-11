package com.example.ampsauth.auth;

import javax.naming.NamingException;

/** Connectivity check used by the optional {@code ldap} health indicator (no credentials involved). */
public interface LdapProbe {

    /**
     * Opens and immediately closes a connection to the LDAP server.
     *
     * @throws javax.naming.CommunicationException if the server could not be reached
     * @throws NamingException                       if the server answered with an error
     */
    void probe() throws NamingException;
}
