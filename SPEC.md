# AMPS Logon Authentication Service — Build Specification

This document is a complete, self-contained specification for a Spring Boot service that acts as the
authentication web service for the AMPS (60East) **RESTful Authentication and Entitlement module**
(`libamps_http_entitlement.so`). Implement everything in this document. Where a choice is left open,
prefer the simplest option that satisfies the acceptance criteria in sections 4.3, 10 and 12.

Reference for the AMPS side of the contract:
https://crankuptheamps.com/docs/amps-user-guide/securing/http-auth-module

---

## 1. Background — what AMPS will do to this service

- When an AMPS client logs on with a username and password, the AMPS module sends
  `GET <ResourceURI>` to this service. The placeholder `{{USER_NAME}}` in the configured URI is
  replaced with the logon username.
- The logon **username and password are sent as HTTP authentication credentials** (the module
  supports Basic and Digest; this service implements **Basic only**).
- AMPS may add extra request headers configured on the AMPS side (client name, remote address,
  correlation id, connection name). See section 4.2.
- Response semantics expected by AMPS:
  - `200 OK` with a JSON *permissions document* → the logon is authenticated. The body must be
    valid JSON. `"logon": true` grants permission to log on.
  - `403 Forbidden` → the logon is rejected.
  - Any other failure (timeout, 5xx, unparseable body) → the logon is rejected.
- Timing: the AMPS module's default connect timeout is 2 s and request timeout is 5 s, and the call
  happens on an AMPS server thread. Target latency: **< 100 ms p99 excluding the credential backend,
  < 500 ms including it**. Every logon after an AMPS failover hits this service at the same time, so
  it must handle bursts.
- Caching: AMPS calls this service only at logon and caches the parsed document per user while that
  user has open connections. The service must therefore be **stateless and idempotent** — the same
  credentials always produce the same answer.

## 2. Scope

**In scope (this iteration)**

1. Validate the username/password from the `Authorization: Basic` header against a pluggable
   credential backend (in-memory users for dev/test, LDAP/Active Directory bind for production).
2. On success, return a fixed permissions document containing `"logon": true`.
3. On failure, return `403`.
4. Health endpoint, structured logging, basic metrics.
5. Unit + integration tests, README, AMPS configuration snippet.

**Out of scope (do not build now, but do not preclude)**

- Topic / admin entitlements (per-user `topic` and `admin` permission lists). The success document
  is served from a loadable template precisely so this can be added later.
- Digest authentication (cannot be implemented against an LDAP bind).
- Replication logon permissions, `user_name` overrides.
- Account lockout / rate limiting.
- Any database, sessions, JWT, OAuth.

## 3. Technology and constraints

- **Java 21** (LTS).
- **Spring Boot — current GA release.** Check https://spring.io/projects/spring-boot or
  start.spring.io for the current version; do not guess one from memory. Use the matching Spring
  Boot BOM for all dependency versions.
- **Maven**, single module, executable jar named `amps-auth-service`. `mvn verify` must pass.
- Dependencies (keep minimal):
  - `spring-boot-starter-web`
  - `spring-boot-starter-actuator`
  - `spring-boot-starter-validation`
  - `spring-security-crypto` **only** (for `PasswordEncoder` / bcrypt).
    **Do NOT add `spring-boot-starter-security`.** Its auto-configuration adds a login page, CSRF
    handling and 401-on-bad-credentials semantics that contradict the AMPS contract. Basic auth is
    parsed manually (section 7).
  - LDAP: use the JDK's JNDI (`javax.naming.directory.InitialDirContext`). No extra dependency.
  - Tests: `spring-boot-starter-test` (JUnit 5, Mockito, AssertJ, MockMvc).
- No Lombok. Use Java records for value types. Constructor injection only. No field injection.
- Package root: `com.example.ampsauth` (will be renamed later — keep the root in one place).
- Return **empty bodies** on 401/403/503. Never expose stack traces or error details in responses.

## 4. HTTP contract

### 4.1 Endpoints

| Method | Path | Purpose |
|---|---|---|
| `GET` | `/amps/v1/permissions/{username}` | Primary endpoint. `{username}` is what AMPS substituted for `{{USER_NAME}}`. |
| `GET` | `/amps/v1/permissions` | Same behaviour with no path variable (for a ResourceURI without `{{USER_NAME}}`). |
| `GET` | `/actuator/health`, `/actuator/health/liveness`, `/actuator/health/readiness` | Ops. |
| `GET` | `/actuator/metrics`, `/actuator/info` | Ops. |

Rules:

- The **identity is always the Basic-auth username**. The path variable is a cross-check only.
- If the path variable is present and differs from the Basic-auth username (compare
  case-insensitively, after URL decoding) → `403`. This check is controlled by
  `amps.auth.username-path-must-match` (default `true`).
- Do not configure the AMPS `ResourceURI` with a `.json` suffix; the endpoint has none.
- If usernames may contain `\` or `/` (e.g. `DOMAIN\user`), the AMPS side should use the
  no-path-variable form to avoid servlet container URL-decoding restrictions. Document this in the
  README.
- No other routes. Unknown paths → default Spring `404` with no body details.

### 4.2 Request headers

| Header | Where it comes from (AMPS `HTTPHeader` token) | Required | Handling |
|---|---|---|---|
| `Authorization: Basic <base64(username:password)>` | AMPS logon credentials | yes | Decode (standard base64, UTF-8), split at the **first** `:` — passwords may contain `:`. |
| `X-AMPS-Client-Name` | `{{AMPS_CLIENT_NAME}}` | no | Log only. |
| `X-AMPS-Remote-Address` | `{{AMPS_REMOTE_ADDRESS}}` | no | Log only. |
| `X-AMPS-Correlation-Id` | `{{AMPS_CORRELATION_ID}}` | no | Put in MDC as `ampsCorrelationId`; echo back as response header `X-AMPS-Correlation-Id`. |
| `X-AMPS-Connection-Name` | `{{AMPS_CONNECTION_NAME}}` | no | Log only. |

### 4.3 Responses (acceptance criteria)

| Situation | Status | Body | Response headers |
|---|---|---|---|
| No `Authorization` header | `401` | empty | `WWW-Authenticate: Basic realm="amps"` — the AMPS HTTP client may probe before sending credentials; the challenge tells it to use Basic. |
| `Authorization` present but scheme is not `Basic` (case-insensitive) | `403` | empty | |
| Base64 invalid, or decoded value has no `:` | `403` | empty | |
| Empty username or empty password | `403` | empty | Must short-circuit **before** any backend call (an empty password can succeed as an anonymous LDAP bind). |
| Path username ≠ Basic username (when check enabled) | `403` | empty | |
| Backend says credentials invalid | `403` | empty | |
| Backend unreachable / timed out / unexpected exception | `503` | empty | AMPS still fails the logon; `503` makes outages distinguishable from bad passwords in logs and metrics. |
| Credentials valid | `200` | permissions document (section 4.4) | `Content-Type: application/json`, `Cache-Control: no-store` |

All responses carry `X-AMPS-Correlation-Id` if the request had one.

The password must **never** appear in logs, responses, exception messages, or metrics tags.

### 4.4 Success document

Served verbatim from a template resource. Default: `classpath:amps/permissions-logon-only.json`:

```json
{
  "logon": true,
  "replication-logon": false
}
```

- Load once at startup. **Fail startup** if the resource is missing or is not valid JSON.
- Serve the exact bytes (pretty-printed or compact — both are fine for AMPS).
- Property `amps.permissions.template` may point to `file:/path/to/doc.json` so the document can be
  changed without a rebuild (restart required).
- README must state clearly: this document has **no `topic` list**, so AMPS must **not** reference this
  module in an `<Entitlement>` block yet — keep AMPS's default (allow-all) entitlement module. When
  the module is later used for entitlements too, `topic` / `admin` permission lists must be added to
  the document, otherwise authenticated users will be unable to publish or subscribe.

## 5. Credential backends

```java
package com.example.ampsauth.auth;

public interface CredentialValidator {
    /** Never called with an empty username or password. Must not retain the password. */
    ValidationResult validate(String username, String password);
}

public enum ValidationResult { VALID, INVALID, BACKEND_UNAVAILABLE }
```

Exactly one implementation is active, selected by `amps.auth.backend` (`inmemory` | `ldap`) using
`@ConditionalOnProperty`. Startup must fail with a clear message if the value is unknown.

### 5.1 `inmemory` (default — dev, test, and emergency break-glass)

- Users come from `amps.auth.inmemory.users[]` with `username` and `password`, where `password` is in
  Spring's delegating encoder format: `{bcrypt}$2a$10$...` or `{noop}plaintext`.
- Use `PasswordEncoderFactories.createDelegatingPasswordEncoder()` from `spring-security-crypto`.
- Username lookup is case-insensitive.
- For an unknown username, still run `matches()` against a pre-computed dummy bcrypt hash so that
  response time does not reveal whether the user exists.
- Startup validation: reject any `{noop}` password unless `amps.auth.inmemory.allow-plaintext=true`
  (intended for the `local` profile only). Reject duplicate usernames.
- Provide a hashing tool built into the jar:
  - `java -jar amps-auth-service.jar --hash-password` → prompts on the console
    (`System.console().readPassword()`), prints `{bcrypt}...`, exits 0 **without starting Tomcat**.
  - `--hash-password=<value>` is also accepted for scripting (README warns about shell history).
  - Implement by inspecting `args` in `main` before calling `SpringApplication.run`.

### 5.2 `ldap` (production — Active Directory or any LDAP v3)

- Authenticate by performing a **simple bind as the user** (no service account, no search).
- Properties (`amps.auth.ldap.*`): `url` (`ldaps://host:636` in production), `user-principal-pattern`
  (e.g. `{0}@corp.example.com` for AD UPN, or `uid={0},ou=people,dc=example,dc=com`),
  `connect-timeout` (default `1000ms`), `read-timeout` (default `2000ms`).
- Set `com.sun.jndi.ldap.connect.timeout` and `com.sun.jndi.ldap.read.timeout` on the JNDI
  environment from those properties.
- Mapping: bind succeeds → `VALID`; `javax.naming.AuthenticationException` → `INVALID`;
  `javax.naming.CommunicationException` or any other `NamingException`/runtime exception →
  `BACKEND_UNAVAILABLE` (log at ERROR with the exception, never the password).
- Always close the `DirContext` in `finally`.
- The empty-password guard in section 4.3 must also be enforced inside this class (defence in depth).
- For testability, isolate JNDI behind a small interface the tests can fake:

```java
interface DirContextFactory {
    javax.naming.directory.DirContext bind(String principal, String password)
        throws javax.naming.NamingException;
}
```

- TLS trust for `ldaps://` uses the JVM truststore; README documents `-Djavax.net.ssl.trustStore`.
- Note for README (future): search-then-bind with a service account can be added later if the
  principal pattern approach is insufficient.

## 6. Configuration

Bind with `@ConfigurationProperties(prefix = "amps")` using records, `@Validated`, and
`@ConfigurationPropertiesScan`/`@EnableConfigurationProperties`.

`src/main/resources/application.yml` (production-shaped defaults):

```yaml
server:
  port: 8080
  error:
    include-message: never
    include-stacktrace: never
    include-exception: false
  tomcat:
    threads:
      max: 200
    connection-timeout: 5s
  # Production: terminate TLS here (AMPS verifies the certificate via its CAKey option).
  # ssl:
  #   bundle: amps-auth          # define under spring.ssl.bundle.pem or .jks
  #   client-auth: none          # set to "need" to require the AMPS client certificate (mTLS)

amps:
  auth:
    backend: inmemory                    # inmemory | ldap
    username-path-must-match: true
    inmemory:
      allow-plaintext: false
      users: []                          # see application-local.yml
    ldap:
      url: ldaps://ldap.example.com:636
      user-principal-pattern: "{0}@corp.example.com"
      connect-timeout: 1000ms
      read-timeout: 2000ms
  permissions:
    template: classpath:amps/permissions-logon-only.json

management:
  endpoints:
    web:
      exposure:
        include: health,info,metrics
  endpoint:
    health:
      probes:
        enabled: true
      show-details: never

logging:
  pattern:
    console: "%d{yyyy-MM-dd'T'HH:mm:ss.SSSXXX} %-5level [%thread] corr=%X{ampsCorrelationId:-} %logger{36} - %msg%n"
```

`src/main/resources/application-local.yml` (developer profile, HTTP only):

```yaml
amps:
  auth:
    backend: inmemory
    inmemory:
      allow-plaintext: true
      users:
        - username: trader1
          password: "{noop}secret"
        - username: trader2
          password: "{bcrypt}$2a$10$REPLACE_WITH_HASH_FROM_TOOL"
logging:
  level:
    com.example.ampsauth: DEBUG
```

## 7. Code structure

```
src/main/java/com/example/ampsauth/
  AmpsAuthApplication.java              main(); handles --hash-password before SpringApplication.run
  config/AmpsProperties.java            records: Auth(backend, usernamePathMustMatch, InMemory, Ldap), Permissions(template)
  config/ValidatorConfiguration.java    @ConditionalOnProperty beans for the two validators
  web/PermissionsController.java        the two GET mappings; maps LogonOutcome -> ResponseEntity
  web/BasicCredentials.java             record(username, password) with toString() that hides the password
  web/BasicAuthorizationParser.java     parse(String header): Optional<BasicCredentials>; throws MalformedCredentialsException
  web/MalformedCredentialsException.java
  web/CorrelationIdFilter.java          OncePerRequestFilter: X-AMPS-Correlation-Id -> MDC + response header
  auth/CredentialValidator.java
  auth/ValidationResult.java
  auth/InMemoryCredentialValidator.java
  auth/LdapCredentialValidator.java
  auth/DirContextFactory.java           + JndiDirContextFactory (default impl)
  auth/LogonService.java                orchestration: guards -> validator -> LogonOutcome; metrics; the one INFO log line
  auth/LogonOutcome.java                enum SUCCESS, NO_CREDENTIALS, MALFORMED, USERNAME_MISMATCH, INVALID, BACKEND_UNAVAILABLE
  permissions/PermissionsDocument.java  loads and validates the template at startup; exposes byte[]
  tools/PasswordHashTool.java
src/main/resources/
  application.yml
  application-local.yml
  amps/permissions-logon-only.json
src/test/java/com/example/ampsauth/...  (section 10)
README.md
```

Responsibilities:

- `PermissionsController` does no logic beyond: read headers/path → call `LogonService` → map the
  outcome to the status/body/headers table in 4.3.
- `LogonService.logon(Optional<String> pathUsername, String authorizationHeader, RequestMetadata meta)`
  applies the guards in the order of table 4.3, calls the validator, records metrics, and writes the
  single INFO log line. `RequestMetadata` carries the `X-AMPS-*` values for logging.
- `BasicAuthorizationParser` rules: header null/blank → `Optional.empty()`; scheme compared
  case-insensitively; standard (not URL-safe) base64; UTF-8; split at first `:`; do **not** trim;
  empty username or empty password → `MalformedCredentialsException`.

## 8. Logging, metrics, health

- Exactly one INFO line per logon attempt, e.g.
  `logon user=trader1 outcome=SUCCESS client=MacroDesktop-jdoe remote=10.1.2.3 conn=json-tcp-17 ms=41`
  (`user` omitted or `-` when it could not be parsed). Correlation id comes from the MDC via the
  log pattern.
- ERROR with stack trace for `BACKEND_UNAVAILABLE`.
- Never log the `Authorization` header, the password, or full request headers. Make sure no request
  logging filter (`CommonsRequestLoggingFilter` etc.) is enabled.
- Micrometer: counter `amps.logon.attempts` tagged `outcome=<LogonOutcome>`; timer
  `amps.logon.duration` tagged `outcome`. Never tag with the username.
- Health: liveness and readiness groups enabled. Readiness must **not** depend on LDAP (a flapping
  LDAP would take the service out of the load balancer and block every logon, including in-memory
  break-glass users). An optional `ldap` health indicator may contribute to `/actuator/health` when
  the `ldap` backend is active, excluded from the readiness group.

## 9. Security requirements

- Production runs behind TLS (`server.ssl` via Spring SSL bundles); the AMPS side verifies the
  certificate with its `CAKey` option. Plain HTTP is acceptable only in the `local` profile.
- Optional mTLS: document `server.ssl.client-auth: need` and the matching AMPS `Certificate`/`Key`
  options; do not enable by default.
- Basic auth only; `Cache-Control: no-store` on every response.
- Passwords are never logged, stored, or included in metrics/traces; `BasicCredentials.toString()`
  masks the password.
- Empty username/password rejected before any backend call.
- Timing-uniform handling of unknown users in the in-memory backend (dummy hash).
- All backend calls have explicit timeouts (section 5.2).
- Startup fails fast on invalid configuration (unknown backend, plaintext without opt-in, bad template).

## 10. Tests (all must pass in `mvn verify`)

**Unit**

- `BasicAuthorizationParserTest`: valid header; password containing `:`; non-ASCII UTF-8 username
  and password; missing/blank header → empty; `Bearer` scheme → malformed; `basic` lower-case
  scheme accepted; invalid base64 → malformed; no colon → malformed; empty username → malformed;
  empty password → malformed; surrounding spaces are preserved, not trimmed.
- `InMemoryCredentialValidatorTest`: valid bcrypt; valid `{noop}` when allowed; wrong password →
  INVALID; unknown user → INVALID; case-insensitive username; startup rejects `{noop}` when not
  allowed; duplicate usernames rejected.
- `LdapCredentialValidatorTest` (fake `DirContextFactory`): bind ok → VALID and context closed;
  `AuthenticationException` → INVALID; `CommunicationException` → BACKEND_UNAVAILABLE; generic
  `NamingException` → BACKEND_UNAVAILABLE; principal pattern formatting (`{0}` substitution);
  empty password never reaches the factory.
- `PermissionsDocumentTest`: loads the default template; invalid JSON resource fails; missing
  resource fails; bytes served unchanged.
- `LogonServiceTest` (Mockito validator): outcome mapping for every row in table 4.3; metrics
  counter incremented with the right tag.

**Integration** (`@SpringBootTest(webEnvironment = RANDOM_PORT)` with `inmemory` backend and test
users, plus one test with a mocked `CredentialValidator` bean)

- `200`, JSON body equals the template, `Content-Type: application/json`,
  `Cache-Control: no-store`, correlation id echoed.
- `403` for wrong password; body is empty.
- `401` with `WWW-Authenticate: Basic realm="amps"` when no header.
- `403` for `Bearer` and for malformed base64.
- `403` for path/auth username mismatch; `200` when `amps.auth.username-path-must-match=false`.
- `200` on the no-path-variable endpoint.
- `503` when the validator returns `BACKEND_UNAVAILABLE`; body empty.
- A log-capture test asserting the password string never appears in log output for any of the above.

**Manual smoke test** (documented in README, using the `local` profile):

```bash
java -jar target/amps-auth-service.jar --spring.profiles.active=local

curl -i -u trader1:secret  http://localhost:8080/amps/v1/permissions/trader1   # 200 + JSON
curl -i -u trader1:wrong   http://localhost:8080/amps/v1/permissions/trader1   # 403
curl -i                    http://localhost:8080/amps/v1/permissions/trader1   # 401 + WWW-Authenticate
curl -i -u trader1:secret  http://localhost:8080/amps/v1/permissions/other     # 403 (mismatch)
curl -i -u trader1:secret  http://localhost:8080/amps/v1/permissions           # 200 + JSON
```

## 11. AMPS configuration (include in README)

Logon-only wiring: the module is used for `Authentication` only. Do **not** add an `<Entitlement>`
block for it yet (see section 4.4).

```xml
<Modules>
  <Module>
    <Name>web-auth</Name>
    <Library>libamps_http_entitlement.so</Library>
    <Options>
      <ResourceURI>https://amps-auth.example.com:8443/amps/v1/permissions/{{USER_NAME}}</ResourceURI>
      <HTTPHeader>X-AMPS-Client-Name: {{AMPS_CLIENT_NAME}}</HTTPHeader>
      <HTTPHeader>X-AMPS-Remote-Address: {{AMPS_REMOTE_ADDRESS}}</HTTPHeader>
      <HTTPHeader>X-AMPS-Correlation-Id: {{AMPS_CORRELATION_ID}}</HTTPHeader>
      <HTTPHeader>X-AMPS-Connection-Name: {{AMPS_CONNECTION_NAME}}</HTTPHeader>
      <ReuseConnections>enabled</ReuseConnections>
      <ConnectionTimeout>1000</ConnectionTimeout>
      <RequestTimeout>3000</RequestTimeout>
      <!-- production TLS: AMPS verifies the service certificate -->
      <CAKey>/etc/amps/security/ca.pem</CAKey>
      <!-- local testing over plain http: drop CAKey and use http:// in ResourceURI -->
    </Options>
  </Module>
</Modules>

<!-- Instance-wide authentication; can also be placed inside an individual <Transport>. -->
<Authentication>
  <Module>web-auth</Module>
</Authentication>
```

End-to-end check: log on with any AMPS client using `tcp://trader1:secret@amps-host:9007/amps/json`
(or the equivalent `Client.logon()` with a username/password). A wrong password must be refused by
AMPS, and the service log must show the corresponding `outcome=INVALID` line.

README troubleshooting section must explain: `403` in the service log = bad credentials;
`503` = credential backend down; no request reaching the service = AMPS connectivity/TLS problem
(check AMPS log for the module's error lines and the `ConnectionTimeout`/`RequestTimeout` values).

## 12. Deliverables and definition of done

- [ ] `mvn verify` passes with all tests in section 10.
- [ ] `java -jar target/amps-auth-service.jar --spring.profiles.active=local` starts and the curl
      matrix in section 10 produces exactly the listed status codes.
- [ ] `--hash-password` tool works and never starts the web server.
- [ ] No password appears in any log output (verified by test).
- [ ] `README.md` covers: purpose and AMPS contract summary; endpoints and response table;
      configuration reference for every `amps.*` property; hashing a password; running locally;
      enabling TLS (and optional mTLS); LDAP setup and truststore; AMPS configuration block;
      the entitlement caveat from section 4.4; troubleshooting.
- [ ] Package root defined in one place so it can be renamed easily.

## 13. Suggested implementation order

1. Scaffold the Maven project with the dependencies in section 3; confirm `mvn verify` runs (empty).
2. `AmpsProperties` + `PermissionsDocument` with startup validation, plus their tests.
3. `BasicAuthorizationParser` + tests.
4. `InMemoryCredentialValidator` + `PasswordHashTool` + tests.
5. `LogonService`, `CorrelationIdFilter`, `PermissionsController` + integration tests.
6. `LdapCredentialValidator` + `DirContextFactory` + tests.
7. Metrics, health groups, log pattern, log-capture test.
8. `application-local.yml`, README (including section 11 block), final `mvn verify`.
9. Review every row of table 4.3 and every checkbox in section 12 before finishing.

## 14. Do not

- Do not add `spring-boot-starter-security`, a database, sessions, JWT, or OAuth.
- Do not return `401` for wrong credentials — it must be `403`.
- Do not log or echo the password or the `Authorization` header.
- Do not trim or alter the password.
- Do not put the username in metric tags.
- Do not change the response contract or endpoint paths without updating the README and section 11.
- Do not skip or weaken tests to make the build pass.
