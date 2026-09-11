package com.example.ampsauth.auth;

import javax.naming.NamingException;
import javax.naming.directory.DirContext;

/**
 * Isolates JNDI so {@link LdapCredentialValidator} can be tested with a fake. The default
 * implementation is {@link JndiDirContextFactory}.
 */
public interface DirContextFactory {

    /**
     * Performs a simple LDAP bind as {@code principal}. The caller must close the returned context.
     *
     * @throws javax.naming.AuthenticationException if the server rejected the credentials
     * @throws javax.naming.CommunicationException  if the server could not be reached
     * @throws NamingException                       for any other LDAP failure
     */
    DirContext bind(String principal, String password) throws NamingException;
}
