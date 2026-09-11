package com.example.ampsauth.auth;

import java.util.Hashtable;

import javax.naming.Context;
import javax.naming.NamingException;
import javax.naming.directory.DirContext;
import javax.naming.directory.InitialDirContext;

import com.example.ampsauth.config.AmpsProperties;

/**
 * Default {@link DirContextFactory}: a JDK JNDI simple bind with explicit connect and read timeouts
 * taken from {@code amps.auth.ldap.*}. TLS trust for {@code ldaps://} comes from the JVM truststore.
 */
public class JndiDirContextFactory implements DirContextFactory, LdapProbe {

    private static final String LDAP_CTX_FACTORY = "com.sun.jndi.ldap.LdapCtxFactory";
    private static final String CONNECT_TIMEOUT = "com.sun.jndi.ldap.connect.timeout";
    private static final String READ_TIMEOUT = "com.sun.jndi.ldap.read.timeout";

    private final String url;
    private final String connectTimeoutMillis;
    private final String readTimeoutMillis;

    public JndiDirContextFactory(AmpsProperties.Ldap config) {
        if (config.url() == null || config.url().isBlank()) {
            throw new IllegalStateException("amps.auth.ldap.url must be set when amps.auth.backend=ldap");
        }
        if (config.connectTimeout() == null || config.connectTimeout().isNegative() || config.connectTimeout().isZero()) {
            throw new IllegalStateException("amps.auth.ldap.connect-timeout must be positive");
        }
        if (config.readTimeout() == null || config.readTimeout().isNegative() || config.readTimeout().isZero()) {
            throw new IllegalStateException("amps.auth.ldap.read-timeout must be positive");
        }
        this.url = config.url().strip();
        this.connectTimeoutMillis = Long.toString(config.connectTimeout().toMillis());
        this.readTimeoutMillis = Long.toString(config.readTimeout().toMillis());
    }

    @Override
    public DirContext bind(String principal, String password) throws NamingException {
        if (principal == null || principal.isEmpty()) {
            throw new IllegalArgumentException("principal must not be empty");
        }
        if (password == null || password.isEmpty()) {
            // An empty password would be an anonymous bind, which many servers report as success.
            throw new IllegalArgumentException("password must not be empty");
        }
        Hashtable<String, Object> env = baseEnvironment();
        env.put(Context.SECURITY_AUTHENTICATION, "simple");
        env.put(Context.SECURITY_PRINCIPAL, principal);
        env.put(Context.SECURITY_CREDENTIALS, password);
        return new InitialDirContext(env);
    }

    /** Anonymous connect used by the health indicator; the server may refuse the anonymous bind. */
    @Override
    public void probe() throws NamingException {
        Hashtable<String, Object> env = baseEnvironment();
        env.put(Context.SECURITY_AUTHENTICATION, "none");
        new InitialDirContext(env).close();
    }

    public String url() {
        return url;
    }

    private Hashtable<String, Object> baseEnvironment() {
        Hashtable<String, Object> env = new Hashtable<>();
        env.put(Context.INITIAL_CONTEXT_FACTORY, LDAP_CTX_FACTORY);
        env.put(Context.PROVIDER_URL, url);
        env.put("java.naming.ldap.version", "3");
        env.put(CONNECT_TIMEOUT, connectTimeoutMillis);
        env.put(READ_TIMEOUT, readTimeoutMillis);
        return env;
    }
}
