# AMPS Logon Authentication Service

A small, stateless Spring Boot service that answers logon requests from the AMPS (60East)
**RESTful Authentication and Entitlement module** (`libamps_http_entitlement.so`).

When an AMPS client logs on, AMPS calls this service over HTTP(S) with the client's credentials in an
`Authorization: Basic` header. The service validates them against a pluggable credential backend
(in-memory users for dev/test and break-glass, an LDAP/Active Directory bind, or an OAuth2/OIDC
UserInfo endpoint when the "password" is an access token from a PKCE flow) and answers `200` with a
JSON *permissions document* (`"logon": true`), `403` when the logon must be refused, or `503` when
the credential backend itself is unavailable.

Reference for the AMPS side of the contract:
<https://crankuptheamps.com/docs/amps-user-guide/securing/http-auth-module>

---

## Table of contents

- [1. How AMPS uses this service](#1-how-amps-uses-this-service)
- [2. Build and run](#2-build-and-run)
  - [2.1 Requirements](#21-requirements)
  - [2.2 Build](#22-build)
  - [2.3 Run locally and smoke-test](#23-run-locally-and-smoke-test)
- [3. HTTP API](#3-http-api)
  - [3.1 Endpoints](#31-endpoints)
  - [3.2 Request headers](#32-request-headers)
  - [3.3 Responses](#33-responses)
  - [3.4 Identity, the path variable and `DOMAIN\user`](#34-identity-the-path-variable-and-domainuser)
  - [3.5 The permissions document (and the entitlement caveat)](#35-the-permissions-document-and-the-entitlement-caveat)
- [4. Configuration reference](#4-configuration-reference)
  - [4.1 `amps.*` properties](#41-amps-properties)
  - [4.2 Server, management and logging settings](#42-server-management-and-logging-settings)
  - [4.3 The `local` profile](#43-the-local-profile)
- [5. Credential backends](#5-credential-backends)
  - [5.1 `inmemory`](#51-inmemory)
  - [5.2 Hashing a password](#52-hashing-a-password)
  - [5.3 `ldap`](#53-ldap)
  - [5.4 LDAP over TLS and the JVM truststore](#54-ldap-over-tls-and-the-jvm-truststore)
  - [5.5 `userinfo` (OAuth2/OIDC access token)](#55-userinfo-oauth2oidc-access-token)
- [6. TLS for this service (and optional mTLS)](#6-tls-for-this-service-and-optional-mtls)
- [7. Logging, metrics and health](#7-logging-metrics-and-health)
  - [7.1 Logging](#71-logging)
  - [7.2 Metrics](#72-metrics)
  - [7.3 Health](#73-health)
- [8. AMPS configuration](#8-amps-configuration)
- [9. Troubleshooting](#9-troubleshooting)
- [10. Security notes](#10-security-notes)
- [11. Project layout and renaming the package root](#11-project-layout-and-renaming-the-package-root)
  - [11.1 Embedding the feature in another application](#111-embedding-the-feature-in-another-application)
- [12. Out of scope (for now)](#12-out-of-scope-for-now)

---

## 1. How AMPS uses this service

- On every client logon, the AMPS module issues `GET <ResourceURI>`. The placeholder `{{USER_NAME}}`
  in the configured URI is replaced with the logon username.
- The logon username and password travel as **HTTP Basic** credentials. The AMPS module also supports
  Digest; **this service implements Basic only** (Digest cannot be implemented against an LDAP bind —
  the bind needs the clear password, which Digest never provides).
- AMPS may add extra request headers (client name, remote address, correlation id, connection name);
  see [3.2](#32-request-headers).
- Response semantics expected by AMPS:
  - `200 OK` with a valid JSON permissions document → the logon is authenticated; `"logon": true`
    grants permission to log on.
  - `403 Forbidden` → the logon is rejected.
  - Anything else (timeout, 5xx, unparseable body) → the logon is rejected.
- **Timing.** The AMPS module's default connect timeout is 2 s and its request timeout is 5 s, and the
  call happens on an AMPS server thread. Target latency is **< 100 ms p99 excluding the credential
  backend and < 500 ms including it**. After an AMPS failover every client logs on at the same time,
  so the service must absorb bursts (the embedded Tomcat is configured with 200 worker threads).
- **Caching and statelessness.** AMPS calls this service only at logon and caches the parsed document
  per user while that user has open connections. The service is therefore **stateless and
  idempotent**: the same credentials always produce the same answer, and it keeps no sessions.
  A consequence worth remembering: **a password change (or a user being disabled) only takes effect at
  the user's next logon** — existing AMPS connections are unaffected.

---

## 2. Build and run

### 2.1 Requirements

| | |
|---|---|
| Java | **21** (LTS). The build compiles with `--release 21`. |
| Spring Boot | **4.1.1** (current GA). All dependency versions come from the Spring Boot BOM. |
| Build tool | **Maven**, single module. |
| Artifact | `target/amps-auth-service.jar` (executable Spring Boot jar). |

Dependencies are deliberately minimal: `spring-boot-starter-webmvc` (Spring Boot 4's name for the
former `spring-boot-starter-web`), `spring-boot-starter-actuator`, `spring-boot-starter-validation`,
and `spring-security-crypto` for `PasswordEncoder`/bcrypt. LDAP uses the JDK's own JNDI
(`javax.naming.directory.InitialDirContext`) and the UserInfo backend the JDK HTTP client — no
extra dependency. The only addition is `springdoc-openapi-starter-webmvc-ui` for Swagger UI, which is
inert unless enabled ([2.3](#23-run-locally-and-smoke-test)) and used only by
`com.example.OpenApiConfiguration`, outside the copyable feature package.

> **`spring-boot-starter-security` is deliberately NOT a dependency.** Its auto-configuration adds a
> login page, CSRF handling and `401`-on-bad-credentials semantics, all of which contradict the AMPS
> contract (bad credentials must be `403`). Basic authentication is parsed by hand in
> `BasicAuthorizationParser`; only the bcrypt `PasswordEncoder` is borrowed from Spring Security.

### 2.2 Build

```bash
mvn verify          # compiles, runs every unit and integration test, packages the jar
```

The result is `target/amps-auth-service.jar`, runnable with `java -jar`.

### 2.3 Run locally and smoke-test

The `local` profile adds two in-memory users (plaintext allowed) and DEBUG logging
(see [4.3](#43-the-local-profile)). Like the shipped defaults it listens on plain HTTP on port 8080;
production must add the TLS bundle from [6](#6-tls-for-this-service-and-optional-mtls).

```bash
java -jar target/amps-auth-service.jar --spring.profiles.active=local
```

Then run the smoke-test matrix. The comments are the exact expected status codes:

```bash
curl -i -u trader1:secret  http://localhost:8080/amps/v1/permissions/trader1   # 200 + JSON
curl -i -u trader1:wrong   http://localhost:8080/amps/v1/permissions/trader1   # 403
curl -i                    http://localhost:8080/amps/v1/permissions/trader1   # 401 + WWW-Authenticate
curl -i -u trader1:secret  http://localhost:8080/amps/v1/permissions/other     # 403 (mismatch)
curl -i -u trader1:secret  http://localhost:8080/amps/v1/permissions           # 200 + JSON
```

Useful extras:

```bash
curl -s http://localhost:8080/actuator/health
curl -s http://localhost:8080/actuator/health/readiness
curl -s 'http://localhost:8080/actuator/metrics/amps.logon.attempts?tag=outcome:INVALID'
```

**Swagger UI.** With the `local` profile, Swagger UI is at <http://localhost:8080/swagger-ui.html>
(OpenAPI document at `/v3/api-docs`). Click **Authorize**, enter the username and password (or,
with the `userinfo` backend, the access token as the password), and try the two endpoints. It is
**off by default** so production has no extra routes; enable it in any other environment with

```bash
java -jar target/amps-auth-service.jar --springdoc.api-docs.enabled=true --springdoc.swagger-ui.enabled=true
```

---

## 3. HTTP API

### 3.1 Endpoints

| Method | Path | Purpose |
|---|---|---|
| `GET` | `/amps/v1/permissions/{username}` | Primary endpoint. `{username}` is whatever AMPS substituted for `{{USER_NAME}}`. |
| `GET` | `/amps/v1/permissions` | Same behaviour without a path variable, for a `ResourceURI` that does not contain `{{USER_NAME}}`. |
| `GET` | `/actuator/health`, `/actuator/health/liveness`, `/actuator/health/readiness` | Ops probes. |
| `GET` | `/actuator/info`, `/actuator/metrics` | Ops. |

There are no other routes: the actuator index page (`/actuator`) is disabled
(`management.endpoints.web.discovery.enabled: false`) and only `health`, `info` and `metrics` are
exposed. Swagger UI (`/swagger-ui.html`, `/swagger-ui/**`, `/v3/api-docs/**`) exists only when the
`springdoc.*` properties enable it, as the `local` profile does ([2.3](#23-run-locally-and-smoke-test)). Unknown paths get Spring's default `404` with no message, exception or stack trace in the
body (`server.error.include-*` are all off); an unsupported method gets the same style of `405`.

> **Do not put a `.json` suffix on the AMPS `ResourceURI`.** The endpoint has none;
> `/amps/v1/permissions/trader1.json` would be treated as the username `trader1.json` and fail the
> cross-check (or the backend lookup).

### 3.2 Request headers

| Header | AMPS `HTTPHeader` token | Required | Handling |
|---|---|---|---|
| `Authorization: Basic <base64(username:password)>` | AMPS logon credentials | yes | Standard (not URL-safe) base64, decoded as strict UTF-8, split at the **first** `:` — passwords may contain colons. Nothing is trimmed: leading/trailing spaces inside the username or password are preserved. The scheme name is compared case-insensitively (`basic` is accepted). With the `userinfo` backend the "password" is an OAuth2 access token ([5.5](#55-userinfo-oauth2oidc-access-token)); Tomcat's default 8 KB header limit fits tokens up to roughly 5 KB, raise `server.max-http-request-header-size` for larger ones. |
| `X-AMPS-Client-Name` | `{{AMPS_CLIENT_NAME}}` | no | Logged only. |
| `X-AMPS-Remote-Address` | `{{AMPS_REMOTE_ADDRESS}}` | no | Logged only. |
| `X-AMPS-Connection-Name` | `{{AMPS_CONNECTION_NAME}}` | no | Logged only. |
| `X-AMPS-Correlation-Id` | `{{AMPS_CORRELATION_ID}}` | no | Echoed back **verbatim** as the response header of the same name, and put into the SLF4J MDC under the key `ampsCorrelationId` (the console log pattern renders it as `corr=...`). The MDC copy is sanitised like the other logged values and bounded to 256 characters; a blank header is ignored. |

Every request-supplied value that reaches a log line (`user`, `client`, `remote`, `conn`, `corr`) is
sanitised first: control characters, all whitespace, Unicode line/paragraph separators, format
characters (bidi overrides, zero-width characters) and `=` are replaced with `_`, and the value is
truncated to 128 characters (256 for the correlation id) with a trailing `...`. A value can therefore
neither break a log line nor forge another `key=value` token such as `outcome=SUCCESS`. A missing or
empty value is logged as `-`.

### 3.3 Responses

| Situation | Status | Body | Response headers |
|---|---|---|---|
| No `Authorization` header (null or blank) | `401` | empty | `WWW-Authenticate: Basic realm="amps"` — the AMPS HTTP client may probe before sending credentials; the challenge tells it to use Basic. |
| `Authorization` present but the scheme is not `Basic` (case-insensitive) | `403` | empty | |
| Base64 invalid, not valid UTF-8, or the decoded value has no `:` | `403` | empty | |
| Empty username or empty password | `403` | empty | Short-circuited **before** any backend call — an empty password can otherwise succeed as an anonymous LDAP bind. |
| Path username ≠ Basic username (when the check is enabled) | `403` | empty | |
| Backend says the credentials are invalid | `403` | empty | |
| Backend unreachable, timed out, threw, or returned nothing | `503` | empty | AMPS still fails the logon; `503` makes outages distinguishable from bad passwords in logs and metrics. |
| Credentials valid | `200` | the permissions document ([3.5](#35-the-permissions-document-and-the-entitlement-caveat)) | `Content-Type: application/json` |

Additionally, on **every** response the service emits:

- `Cache-Control: no-store` (set by `CorrelationIdFilter` for all requests, including `404`s and
  actuator endpoints);
- `X-AMPS-Correlation-Id`, echoed whenever the request carried one.

**Error bodies are always empty.** No stack traces, exception names, reason codes or any other detail
is ever returned to the caller — the reason lives only in the service log
(see [9. Troubleshooting](#9-troubleshooting)).

### 3.4 Identity, the path variable and `DOMAIN\user`

- **The identity is always the Basic-auth username.** The path variable is a cross-check only; it is
  never used to look up a user.
- If the path variable is present and differs from the Basic-auth username (compared
  case-insensitively, after the servlet container's URL decoding) the request is refused with `403`
  and `outcome=USERNAME_MISMATCH`.
- The check is controlled by `amps.auth.username-path-must-match` (default `true`). Set it to `false`
  if the AMPS side legitimately substitutes a different form of the name than the one the client
  presents for the logon.
- **If usernames may contain `\` or `/`** — for example Active Directory `DOMAIN\user` — configure the
  AMPS `ResourceURI` **without** `{{USER_NAME}}` and use the no-path-variable endpoint
  (`.../amps/v1/permissions`). Servlet containers reject encoded slashes (`%2F`) and treat encoded
  backslashes inconsistently, so the path-variable form is unreliable for such names. The
  no-path-variable form has identical behaviour, minus the cross-check.
- Concretely, embedded Tomcat rejects a path containing `%2F` **at the connector**, before any filter
  or controller runs: the answer is a bare `400` (no `Cache-Control`/correlation headers, no
  `logon ...` log line). AMPS treats it like any other non-`200`, i.e. the logon is refused.

### 3.5 The permissions document (and the entitlement caveat)

On success the service returns the **verbatim bytes** of the template configured in
`amps.permissions.template`. The default is `classpath:amps/permissions-logon-only.json`:

```json
{
  "logon": true,
  "replication-logon": false
}
```

- The template is loaded and validated **once at startup**. Startup **fails** if the resource is
  missing, unreadable, not valid JSON (trailing content included), or not a JSON *object*.
- A **WARN** is logged if the document does not contain a `"logon"` field that is boolean `true`,
  because AMPS would then refuse every authenticated logon.
- The property may point at a file instead of the classpath, e.g.
  `amps.permissions.template=file:/etc/amps-auth/permissions.json`, so the document can be changed
  without a rebuild. **A restart is required** to pick up changes — the bytes are cached in memory.
- The bytes are served exactly as they are on disk; pretty-printed or compact are both fine for AMPS.

> ### ⚠ Entitlement caveat
>
> This document contains **no `topic` list and no `admin` list**. Therefore AMPS must **not** reference
> this module in an `<Entitlement>` block yet — keep AMPS's default (allow-all) entitlement module and
> wire this module under `<Authentication>` only, exactly as shown in
> [8. AMPS configuration](#8-amps-configuration).
>
> If the module is later used for entitlements as well, `topic` and `admin` permission lists **must**
> be added to the document first; otherwise authenticated users will be unable to publish or
> subscribe to anything.

---

## 4. Configuration reference

Configuration is bound from `amps.*` into validated records (`AmpsProperties`). Anything that cannot
bind, or that fails validation, **fails startup** with a message naming the property. Values can come
from `application.yml`, a profile file, environment variables (`AMPS_AUTH_BACKEND=ldap`), or the
command line (`--amps.auth.backend=ldap`).

### 4.1 `amps.*` properties

| Property | Type | Default | Meaning |
|---|---|---|---|
| `amps.auth.backend` | enum: `inmemory` \| `ldap` \| `userinfo` | `inmemory` | Selects the single active credential backend. Matched **case-insensitively** (`LDAP`, `Ldap`, `ldap` all work). **Any other value fails startup**: a typo such as `kerberos` is rejected while binding the property (`Failed to bind properties under 'amps.auth.backend'`), and a spelling that binds but selects nothing (for example `in-memory`) is rejected with `Unsupported amps.auth.backend value '<x>'; expected one of: inmemory, ldap, userinfo`. |
| `amps.auth.username-path-must-match` | boolean | `true` | When `true`, a `{username}` path variable that differs (case-insensitively) from the Basic-auth username produces `403` / `outcome=USERNAME_MISMATCH`. When `false`, the path variable is ignored entirely. Has no effect on the no-path-variable endpoint. |
| `amps.auth.inmemory.allow-plaintext` | boolean | `false` | When `false`, any `{noop}` password in the user list **fails startup**. Intended to be turned on in the `local` profile only. |
| `amps.auth.inmemory.users` | list | empty | The in-memory user list. Its entries are bound and bean-validated for every backend; the encoder/plaintext/duplicate checks below run only when `backend=inmemory`. **Define the whole list in one place** (one profile file or one property source): Spring binds an indexed list from the highest-priority source that contains it and never merges entries across sources, so adding `users[2]` on the command line replaces the list from the file (and, with a gap in the indexes, fails startup). |
| `amps.auth.inmemory.users[].username` | string | — | Must not be blank. Compared case-insensitively at both startup (duplicate detection) and lookup time. |
| `amps.auth.inmemory.users[].password` | string | — | Spring delegating-encoder format: `{bcrypt}$2a$10$...` or `{noop}plaintext`. See the startup rules below. |
| `amps.auth.ldap.url` | string | `ldaps://ldap.example.com:636` (from `application.yml`) | LDAP server URL. **Required** when `backend=ldap`; startup fails if it is blank. Use `ldaps://host:636` in production: a plain `ldap://` URL is accepted but logs a **WARN** at startup, because a simple bind sends the user's password in clear text. |
| `amps.auth.ldap.user-principal-pattern` | string | `{0}@corp.example.com` (from `application.yml`) | Bind principal template. `{0}` is replaced with the Basic-auth username **verbatim — no escaping is applied**. Typical values: `{0}@corp.example.com` (Active Directory UPN) or `uid={0},ou=people,dc=example,dc=com`. **Startup fails if the pattern does not contain `{0}`.** |
| `amps.auth.ldap.connect-timeout` | duration | `1000ms` | Maps to the JNDI property `com.sun.jndi.ldap.connect.timeout`. Must be positive. `connect-timeout + read-timeout` is the service's worst-case LDAP time per logon; keep that sum at or below the AMPS `RequestTimeout` (see [8](#8-amps-configuration)). |
| `amps.auth.ldap.read-timeout` | duration | `2000ms` | Maps to the JNDI property `com.sun.jndi.ldap.read.timeout`. Must be positive. |
| `amps.auth.ldap.health-indicator-enabled` | boolean | `true` | When the `ldap` backend is active, registers an `ldap` health component that does an **anonymous connect** to the server. It contributes to `/actuator/health` **only** — never to the readiness or liveness groups. A server that is reachable but refuses anonymous binds still counts as `UP`. Set to `false` if a load balancer probes `/actuator/health` (instead of `/actuator/health/readiness`), so that an LDAP outage cannot pull the service out of rotation. |
| `amps.auth.userinfo.url` | string | `https://login.example.com/oauth2/userinfo` (from `application.yml`) | The OIDC UserInfo endpoint called with `Authorization: Bearer <access token>`. **Required** when `backend=userinfo`; must be an absolute `http(s)://` URL; a plain `http://` URL logs a **WARN** at startup (tokens in clear text). Redirects are never followed. |
| `amps.auth.userinfo.principal-claim` | string | `preferred_username` | Claim whose value must equal the AMPS username (case-insensitive). Exact claim name first, then a dotted path into nested objects. Common alternatives: `upn`, `email`, `sub`. |
| `amps.auth.userinfo.groups-claim` | string | `groups` | Claim listing the user's groups: a JSON array of strings, or one string of space/comma-separated names. Exact name first (so namespaced names such as `https://example.com/groups` work), then a dotted path such as `realm_access.roles`. |
| `amps.auth.userinfo.enabled-groups` | list of strings | empty | Groups that grant logon; the user must be in **at least one** (compared case-insensitively, trimmed). **Must not be empty** when `backend=userinfo` — startup fails otherwise. |
| `amps.auth.userinfo.principal-must-match` | boolean | `true` | When `true`, a token whose principal claim differs from the AMPS username is refused (`403`, WARN in the log). Leave it on: otherwise any valid token of any user in an enabled group could log on under any name. |
| `amps.auth.userinfo.connect-timeout` | duration | `1000ms` | TCP/TLS connect timeout of the UserInfo call. Must be positive. |
| `amps.auth.userinfo.read-timeout` | duration | `2000ms` | Response timeout of the UserInfo call. Must be positive; `connect-timeout + read-timeout` is the worst case per logon (see [8](#8-amps-configuration)). |
| `amps.auth.userinfo.health-indicator-enabled` | boolean | `true` | When the `userinfo` backend is active, registers a `userInfo` health component that sends an **unauthenticated** GET to the endpoint; any HTTP answer (typically `401`) counts as `UP`, only a connection failure or timeout is `DOWN`. Contributes to `/actuator/health` only, never to readiness or liveness. |
| `amps.permissions.template` | string (Spring resource location) | `classpath:amps/permissions-logon-only.json` | Where the success document comes from. May be `file:/path/to/doc.json`. Loaded once at startup; startup fails if it is missing or is not a JSON object. |

The whole `amps.*` tree is bound and bean-validated at startup whatever the backend (for example a
blank `users[].username` or `users[].password` fails validation even with `backend=ldap`). The
backend-specific checks run only for the selected backend: the LDAP URL/pattern/timeout checks when
`amps.auth.backend=ldap`, the UserInfo URL/claim/group checks when `amps.auth.backend=userinfo`, the
in-memory password rules below when `amps.auth.backend=inmemory`.

**Startup validation of `amps.auth.inmemory.users[].password`** — each of these aborts startup with a
message naming the offending index (and the username, where it is known):

- a blank username or password;
- a value that does not start with an encoder id in braces (`{bcrypt}`, `{noop}`, …);
- `{noop}` while `amps.auth.inmemory.allow-plaintext` is `false`;
- a `{bcrypt}` value that is not a well-formed bcrypt hash (`$2$`, `$2a$`, `$2b$` or `$2y$`, a
  two-digit cost, then 53 hash characters - the same shape Spring's `BCryptPasswordEncoder` can
  verify);
- an unknown encoder id (anything the delegating encoder cannot map);
- a duplicate username (compared case-insensitively).

### 4.2 Server, management and logging settings

These live in `src/main/resources/application.yml` and are the production-shaped defaults:

```yaml
server:
  port: 8080
  error:
    include-message: never        # never leak exception detail in a response body
    include-stacktrace: never
    include-exception: false
  tomcat:
    threads:
      max: 200                    # absorb the logon burst after an AMPS failover
    connection-timeout: 5s
  # Production: terminate TLS here (AMPS verifies the certificate via its CAKey option).
  # ssl:
  #   bundle: amps-auth          # define under spring.ssl.bundle.pem or .jks
  #   client-auth: none          # set to "need" to require the AMPS client certificate (mTLS)

management:
  endpoints:
    web:
      exposure:
        include: health,info,metrics    # nothing else is exposed over HTTP
      discovery:
        enabled: false                  # no /actuator index page
  endpoint:
    health:
      probes:
        enabled: true                   # enables /actuator/health/liveness and /readiness
      show-details: never               # health details are never returned to a caller

springdoc:
  api-docs:
    enabled: false                  # Swagger UI / OpenAPI off in production
  swagger-ui:
    enabled: false
  paths-to-match: /amps/**

logging:
  pattern:
    console: "%d{yyyy-MM-dd'T'HH:mm:ss.SSSXXX} %-5level [%thread] corr=%X{ampsCorrelationId:-} %logger{36} - %msg%n"
```

Notes:

- `server.port` — change it (or set `SERVER_PORT`) to match the AMPS `ResourceURI`; `8443` is the
  usual choice once TLS is enabled.
- `management.endpoint.health.show-details: never` means `/actuator/health` returns only
  `{"status":"UP"}` — the `ldap` component's detail is visible in logs, not over HTTP.
- The log pattern is what renders the correlation id as `corr=<id>` (and `corr=` when absent).

### 4.3 The `local` profile

`src/main/resources/application-local.yml` is the developer profile: the in-memory backend with
plaintext passwords explicitly allowed, and DEBUG logging for the service's own package. It adds no
TLS configuration, so it runs on **plain HTTP** like the shipped defaults; the production TLS bundle
in [6](#6-tls-for-this-service-and-optional-mtls) is what changes that.

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
          # bcrypt hash of "secret2", generated with: java -jar target/amps-auth-service.jar --hash-password
          password: "{bcrypt}$2a$10$Bgfxhrf7l3ZhnfFA9rUXMuCWfLeGp8IKikNruUrlC7KrDoTW.eZH2"
# Swagger UI at http://localhost:8080/swagger-ui.html (OpenAPI document at /v3/api-docs).
springdoc:
  api-docs:
    enabled: true
  swagger-ui:
    enabled: true
logging:
  level:
    # The key below is the service's package root, filled in by Maven resource filtering
    # from the base.package property in pom.xml (the built file contains the real name).
    "@base.package@": DEBUG
```

So the local users are **`trader1` / `secret`** (plaintext, `{noop}`) and **`trader2` / `secret2`**
(bcrypt-hashed). The `logging.level` key is not hard-coded in the source file: Maven resource
filtering replaces `@base.package@` with the `base.package` property from `pom.xml`, so the built
`target/classes/application-local.yml` reads `"com.example.ampsauth": DEBUG`
(see [11](#11-project-layout-and-renaming-the-package-root)).

> Never enable this profile, `allow-plaintext`, or `{noop}` passwords outside a developer machine.

---

## 5. Credential backends

Exactly one `CredentialValidator` implementation is active, chosen by `amps.auth.backend`. The
interface is deliberately tiny:

```java
public interface CredentialValidator {
    /** Never called with an empty username or password. Must not retain the password. */
    ValidationResult validate(String username, String password);
}

public enum ValidationResult { VALID, INVALID, BACKEND_UNAVAILABLE }
```

If the validator throws, or returns nothing at all, the service treats the attempt as
`BACKEND_UNAVAILABLE` (`503`) and logs an ERROR (with the stack trace when an exception was involved;
a `null` return is logged as `credential backend returned null for user=...`) — never a `403`, so
that a code or infrastructure fault can never be mistaken for a wrong password.

### 5.1 `inmemory`

The default. Intended for development, tests, and emergency break-glass accounts in production
(a handful of bcrypt-hashed operators who can still log on when LDAP is down).

- Users come from `amps.auth.inmemory.users[]`; passwords are in Spring's delegating-encoder format
  and are verified with `PasswordEncoderFactories.createDelegatingPasswordEncoder()`.
- **Username lookup is case-insensitive** (`Trader1` matches the configured `trader1`).
- **Timing-uniform:** for an unknown username the validator still performs one bcrypt comparison
  against a pre-computed dummy hash, so response time does not reveal whether a user exists.
- All the startup validation listed in [4.1](#41-amps-properties) applies — a typo in a hash, a
  duplicated user or a forgotten `{noop}` stops the service at boot rather than at 03:00.

```yaml
amps:
  auth:
    backend: inmemory
    inmemory:
      allow-plaintext: false
      users:
        - username: breakglass-ops
          password: "{bcrypt}$2a$10$..."   # paste the complete value printed by --hash-password
```

### 5.2 Hashing a password

The jar doubles as the hashing tool. It runs **before** Spring starts, so the web server is never
started and no port is bound:

```bash
java -jar target/amps-auth-service.jar --hash-password
# Password to hash:            <- input is hidden when a terminal is attached
# {bcrypt}$2a$10$Bgfxhrf7l3ZhnfFA9rUXMuCWfLeGp8IKikNruUrlC7KrDoTW.eZH2    <- example output for "secret2"
```

- With a terminal attached, the prompt uses `Console.readPassword()` and the input is **not echoed**.
- With no terminal attached (a pipe, a CI job), the tool prints
  `Password to hash: (no terminal detected; input is not hidden)` to stderr and reads **one line from
  stdin**, unhidden.
- The hash is the **only** thing written to stdout, and the process exits with code **0**; the prompt
  goes to the terminal (or to stderr when there is none) and errors go to stderr, so
  `HASH=$(java -jar target/amps-auth-service.jar --hash-password)` captures just the hash.
- An empty password prints `error: no password given (empty passwords are not allowed)` and exits **1**.
- bcrypt hashes at most **72 bytes** (UTF-8). A longer password prints
  `error: bcrypt supports passwords of at most 72 bytes (UTF-8); choose a shorter one` and exits **1**.
  (At logon, bcrypt compares only the first 72 bytes of whatever the client sends.)
- For scripting, `--hash-password=<value>` skips the prompt:

  ```bash
  java -jar target/amps-auth-service.jar --hash-password='s3cr3t'
  ```

  > ⚠ The value lands in your **shell history** (and in the process list, visible to other users on
  > the machine). Prefer the interactive form; if you must script it, clear the history entry
  > afterwards.

Paste the printed `{bcrypt}...` value — including the `{bcrypt}` prefix — into
`amps.auth.inmemory.users[].password`.

### 5.3 `ldap`

Production backend for Active Directory or any LDAP v3 server.

- Authentication is a **simple bind as the user**: no service account, no directory search, no group
  lookups. The bind principal is `amps.auth.ldap.user-principal-pattern` with `{0}` replaced by the
  Basic-auth username, substituted **verbatim** (no LDAP escaping is applied — see the note below).
- Timeouts are always explicit: `connect-timeout` and `read-timeout` are pushed onto the JNDI
  environment as `com.sun.jndi.ldap.connect.timeout` and `com.sun.jndi.ldap.read.timeout`.
- The `DirContext` is **always closed** in a `finally` block, whatever the outcome.
- The **empty-password guard is enforced at three layers** — in the request path before the validator
  is called, again inside the validator, and once more inside the JNDI factory. An empty password
  would otherwise be sent as an **anonymous bind**, which most servers report as success.
- A plain `ldap://` URL is accepted but logs a **WARN** at startup: a simple bind carries the user's
  password in clear text, so use `ldaps://` anywhere but an isolated test environment.

Outcome mapping:

| LDAP result | `ValidationResult` | HTTP | Logging |
|---|---|---|---|
| Bind succeeds | `VALID` | `200` | the normal INFO logon line |
| `javax.naming.AuthenticationException` | `INVALID` | `403` | DEBUG only (`LDAP bind rejected principal=... reason=<server diagnostic>`, whitespace rendered as `_`; for Active Directory the diagnostic carries `data_52e` = wrong password, `775` = locked, `532` = expired, `533` = disabled, `773` = must change) |
| `javax.naming.CommunicationException` | `BACKEND_UNAVAILABLE` | `503` | **ERROR** with the exception |
| Any other `NamingException` | `BACKEND_UNAVAILABLE` | `503` | **ERROR** with the exception |
| Any runtime exception | `BACKEND_UNAVAILABLE` | `503` | **ERROR** with the exception |

The password is never included in any of these log lines.

```yaml
amps:
  auth:
    backend: ldap
    ldap:
      url: ldaps://dc01.corp.example.com:636
      user-principal-pattern: "{0}@corp.example.com"
      connect-timeout: 1000ms
      read-timeout: 2000ms
      health-indicator-enabled: true
```

Notes and future options:

- Because `{0}` is substituted verbatim, keep the pattern in a form where the username is a single
  component (a UPN, or the RDN value of a DN). If usernames can contain LDAP special characters
  (`,` `+` `"` `\` `<` `>` `;` `=`), a DN-style pattern is not safe — prefer the UPN form, or add
  search-then-bind (below).
- **Future option:** *search-then-bind* with a service account (search for the user's DN by
  `sAMAccountName`/`uid`, then bind as the DN found) can be added later if the principal-pattern
  approach turns out to be insufficient — for example with multiple OUs or non-deterministic DNs.
  It is not implemented today because it requires a service-account credential to manage.
- **Digest authentication is not supported** and will not be: an LDAP simple bind needs the clear
  password, which HTTP Digest never transmits. Configure AMPS for Basic.

### 5.4 LDAP over TLS and the JVM truststore

`ldaps://` connections are validated against the **JVM truststore**. If your LDAP server's
certificate is issued by a private CA, either import the CA into the JVM's default truststore or
point the JVM at your own:

```bash
# Import the LDAP CA into a dedicated PKCS12 truststore
keytool -importcert \
  -alias corp-ldap-ca \
  -file /etc/pki/corp-ldap-ca.pem \
  -keystore /etc/amps-auth/truststore.p12 \
  -storetype PKCS12 \
  -storepass "$TRUSTSTORE_PASSWORD" \
  -noprompt

# Run the service against it
java \
  -Djavax.net.ssl.trustStore=/etc/amps-auth/truststore.p12 \
  -Djavax.net.ssl.trustStorePassword="$TRUSTSTORE_PASSWORD" \
  -Djavax.net.ssl.trustStoreType=PKCS12 \
  -jar target/amps-auth-service.jar
```

A missing or wrong CA shows up as `503` / `outcome=BACKEND_UNAVAILABLE` with an ERROR line whose
cause chain mentions `SSLHandshakeException` / `PKIX path building failed`. Add
`-Djavax.net.debug=ssl:handshake` temporarily to diagnose it.

### 5.5 `userinfo` (OAuth2/OIDC access token)

For clients that obtain an **access token** from the identity provider first (an Authorization Code +
PKCE flow, typically) and then log on to AMPS with their username and **the token as the password**.
The service never sees a real password; it checks the token by calling the provider's
**UserInfo endpoint**:

1. `GET amps.auth.userinfo.url` with `Authorization: Bearer <token>` and `Accept: application/json`,
   using the configured connect/read timeouts, never following redirects.
2. The response must be `200` with a JSON object. The **principal claim** must equal the AMPS
   username (case-insensitive) — this is what binds the token to the name AMPS will use as the
   identity.
3. The **groups claim** must contain at least one of `amps.auth.userinfo.enabled-groups`
   (case-insensitive).

| UserInfo result | `ValidationResult` | HTTP | Logging |
|---|---|---|---|
| `200`, principal matches, an enabled group present | `VALID` | `200` | the normal INFO logon line |
| `200` but no enabled group (or no groups claim) | `INVALID` | `403` | DEBUG (`user=... is not in an enabled group (claim=... groups=[...])`) |
| `200` but the principal claim differs from the username | `INVALID` | `403` | **WARN** `userinfo principal does not match the logon username user=... principal=...` — a token presented under another user's name |
| `401` or `403` (invalid, expired or revoked token) | `INVALID` | `403` | DEBUG |
| Any other status (`404`, `429`, `5xx`, a redirect, ...) | `BACKEND_UNAVAILABLE` | `503` | **ERROR** `userinfo endpoint returned status=...` |
| Body not a JSON object | `BACKEND_UNAVAILABLE` | `503` | **ERROR** |
| Connection failure or timeout | `BACKEND_UNAVAILABLE` | `503` | **ERROR** with the exception |

The token is never logged, never echoed, and can only ever be sent to the configured URL. An empty
"password" is refused before any call ([3.3](#33-responses)); a token containing control characters
is refused as well (it could never be valid and must not reach an HTTP header).

```yaml
amps:
  auth:
    backend: userinfo
    userinfo:
      url: https://login.corp.example.com/oauth2/v1/userinfo
      principal-claim: preferred_username      # or upn / email / sub, whatever equals the AMPS username
      groups-claim: groups                     # or a dotted path such as realm_access.roles
      enabled-groups:
        - amps-users
        - amps-admins
      principal-must-match: true
      connect-timeout: 1000ms
      read-timeout: 2000ms
      health-indicator-enabled: true
```

Notes:

- **Which claims your provider returns** depends on its configuration: groups usually have to be
  added to the UserInfo response explicitly (a "groups" scope or claim mapping in Entra ID, Okta,
  Keycloak, Ping and similar). Check with `curl -H "Authorization: Bearer <token>" <url>` once and
  set `principal-claim` / `groups-claim` to what you see.
- Group names are compared case-insensitively after trimming, so `AMPS-Users` and `amps-users`
  are the same group.
- The provider's certificate is validated against the **JVM truststore**, exactly as for `ldaps://`
  ([5.4](#54-ldap-over-tls-and-the-jvm-truststore)).
- Access tokens are long: a 4 KB token fits Tomcat's default 8 KB request-header limit; raise
  `server.max-http-request-header-size` if your provider issues larger ones.
- The service stays stateless: every logon is one UserInfo call, and AMPS caches the result per
  user while the connection is open. A revoked token therefore only takes effect at the next logon,
  like a password change.
- **AMPS side:** nothing changes in the AMPS configuration ([8](#8-amps-configuration)); the client
  application simply passes the access token where it would pass the password, e.g.
  `tcp://jdoe:<access token>@amps-host:9007/amps/json` or `Client.logon()` with the token as the
  password.

---

## 6. TLS for this service (and optional mTLS)

In production this service terminates TLS itself, configured through **Spring SSL bundles**. AMPS
verifies the certificate with its `CAKey` option. Plain HTTP is acceptable **only** in the `local`
profile.

**PEM bundle** (certificate + private key files):

```yaml
server:
  port: 8443
  ssl:
    bundle: amps-auth

spring:
  ssl:
    bundle:
      pem:
        amps-auth:
          keystore:
            certificate: file:/etc/amps-auth/tls/server-fullchain.pem
            private-key: file:/etc/amps-auth/tls/server-key.pem
            private-key-password: ${AMPS_AUTH_KEY_PASSWORD:}
```

**JKS / PKCS12 bundle** (a keystore file):

```yaml
server:
  port: 8443
  ssl:
    bundle: amps-auth

spring:
  ssl:
    bundle:
      jks:
        amps-auth:
          keystore:
            location: file:/etc/amps-auth/tls/server.p12
            password: ${AMPS_AUTH_KEYSTORE_PASSWORD}
            type: PKCS12
```

Then point AMPS at `https://` and give it the CA that signed the service certificate:

```xml
<ResourceURI>https://amps-auth.example.com:8443/amps/v1/permissions/{{USER_NAME}}</ResourceURI>
<CAKey>/etc/amps/security/ca.pem</CAKey>
```

**Optional mutual TLS.** Not enabled by default. To require the AMPS client certificate, add a
truststore to the bundle and demand client authentication:

```yaml
server:
  ssl:
    bundle: amps-auth
    client-auth: need            # "none" (default) | "want" | "need"

spring:
  ssl:
    bundle:
      pem:
        amps-auth:
          keystore:
            certificate: file:/etc/amps-auth/tls/server-fullchain.pem
            private-key: file:/etc/amps-auth/tls/server-key.pem
          truststore:
            certificate: file:/etc/amps-auth/tls/amps-client-ca.pem
```

and give the AMPS module the matching client certificate and key:

```xml
<Certificate>/etc/amps/security/amps-client.pem</Certificate>
<Key>/etc/amps/security/amps-client-key.pem</Key>
```

Note that mTLS authenticates the *AMPS instance*, not the end user — the end user is still
authenticated by the Basic credentials.

---

## 7. Logging, metrics and health

### 7.1 Logging

**Exactly one INFO line per logon attempt**, whatever the outcome:

```
logon user=trader1 outcome=SUCCESS client=MacroDesktop-jdoe remote=10.1.2.3 conn=json-tcp-17 ms=41
```

With the configured console pattern, a full line looks like:

```
2026-09-10T19:52:11.417+01:00 INFO  [http-nio-8080-exec-3] corr=8f2c1a9e-3b41 c.example.ampsauth.auth.LogonService - logon user=trader1 outcome=SUCCESS client=MacroDesktop-jdoe remote=10.1.2.3 conn=json-tcp-17 ms=41
```

(`%logger{36}` abbreviates the logger name, hence `c.example...`.)

| Field | Meaning |
|---|---|
| `user` | The Basic-auth username, or `-` when it could not be parsed (no header, wrong scheme, bad base64, no colon). |
| `outcome` | One of `SUCCESS`, `NO_CREDENTIALS`, `MALFORMED`, `USERNAME_MISMATCH`, `INVALID`, `BACKEND_UNAVAILABLE`. |
| `client`, `remote`, `conn` | The `X-AMPS-Client-Name` / `X-AMPS-Remote-Address` / `X-AMPS-Connection-Name` headers, or `-`. |
| `ms` | Wall-clock milliseconds spent handling the attempt, including the backend call. |
| `corr=` (from the pattern) | The `X-AMPS-Correlation-Id`, via the MDC key `ampsCorrelationId`. |

All request-supplied values (`user`, `client`, `remote`, `conn`, and the `corr` id) are sanitised as
described in [3.2](#32-request-headers): control characters, whitespace, Unicode line separators,
format characters and `=` become `_`, and the value is truncated (128 characters, 256 for `corr`).
A crafted username such as `evil outcome=SUCCESS` is therefore logged as
`user=evil_outcome_SUCCESS outcome=INVALID ...` and cannot forge or break a log line.

Other log output:

- **ERROR** for every `BACKEND_UNAVAILABLE`, with the full stack trace whenever an exception was
  involved (LDAP unreachable, a `NamingException`, or an unexpected exception out of the validator);
  a validator that returns `null` is logged as an ERROR without a trace.
- **DEBUG** for a malformed `Authorization` header — a short reason code only
  (`unsupported-scheme`, `missing-token`, `invalid-base64`, `invalid-utf8`, `missing-colon`,
  `empty-username`, `empty-password`), never any part of the header.
- **INFO at startup** naming the active backend and where the permissions document was loaded from.

The `Authorization` header, the password and full request headers are **never** logged. No request
logging filter (`CommonsRequestLoggingFilter` or similar) is enabled, and none should be added.
`BasicCredentials.toString()` and `AmpsProperties.User.toString()` both mask the password, so even an
accidental `{}` of one of those objects cannot leak it.

### 7.2 Metrics

Two Micrometer meters, both **pre-registered at startup for every outcome** (so a counter exists and
reads `0` before the first request) and both tagged **only** with `outcome` — never with a username:

| Meter | Type | Tags |
|---|---|---|
| `amps.logon.attempts` | counter | `outcome` |
| `amps.logon.duration` | timer | `outcome` |

`outcome` values: `SUCCESS`, `NO_CREDENTIALS`, `MALFORMED`, `USERNAME_MISMATCH`, `INVALID`,
`BACKEND_UNAVAILABLE`.

```bash
# all outcomes
curl -s http://localhost:8080/actuator/metrics/amps.logon.attempts

# just the failed-password count
curl -s 'http://localhost:8080/actuator/metrics/amps.logon.attempts?tag=outcome:INVALID'

# latency of successful logons
curl -s 'http://localhost:8080/actuator/metrics/amps.logon.duration?tag=outcome:SUCCESS'
```

Worth alerting on: a sustained non-zero rate of `BACKEND_UNAVAILABLE` (the credential backend is
down) and a sudden spike in `INVALID` (a misconfigured client, or a password-guessing attempt — note
that this service does **no** lockout or rate limiting, see [12](#12-out-of-scope-for-now)).

### 7.3 Health

| Endpoint | Contents |
|---|---|
| `/actuator/health` | Overall status, including the optional `ldap` component (when the `ldap` backend is active and `amps.auth.ldap.health-indicator-enabled=true`) or the optional `userInfo` component (when the `userinfo` backend is active and `amps.auth.userinfo.health-indicator-enabled=true`). |
| `/actuator/health/liveness` | Liveness probe — the JVM/context is alive. Never depends on LDAP. |
| `/actuator/health/readiness` | Readiness probe — the application is ready to serve. **Never depends on LDAP.** |

`show-details` is `never`, so these endpoints return only a status (`{"status":"UP"}`) and never
expose the LDAP URL or an error class to a caller.

> **Why readiness must not depend on LDAP.** A flapping directory would otherwise take every instance
> of this service out of the load balancer at once. That would block *all* logons — including the
> in-memory break-glass accounts that exist precisely for the case where LDAP is broken — and turn a
> partial outage into a total one. A backend outage is surfaced as `503` per request, as
> `outcome=BACKEND_UNAVAILABLE` in the metrics, and as the `ldap` component in `/actuator/health`;
> that is enough for alerting without also removing the instance from service.

The `ldap` health component performs an **anonymous connect** (no credentials). A server that is
reachable but refuses anonymous binds still reports `UP` (with the note `anonymous bind refused`);
only an unreachable or erroring server reports `DOWN`. The `userInfo` component likewise sends an
**unauthenticated** GET and treats any HTTP answer (normally `401`) as `UP`. **If your load balancer
probes `/actuator/health` rather than `/actuator/health/readiness`, set the backend's
`health-indicator-enabled` property to `false`** — otherwise you reintroduce exactly the coupling the
readiness group avoids.

---

## 8. AMPS configuration

Logon-only wiring: the module is used for `Authentication` only. Do **not** add an `<Entitlement>`
block for it yet (see [3.5](#35-the-permissions-document-and-the-entitlement-caveat)).

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

Points to check when adapting it:

- The `ResourceURI` has **no `.json` suffix** and must match the scheme/host/port this service is
  actually listening on.
- Use the form **without** `{{USER_NAME}}` (`.../amps/v1/permissions`) if usernames can contain `\`
  or `/` — see [3.4](#34-identity-the-path-variable-and-domainuser).
- `ConnectionTimeout`/`RequestTimeout` are milliseconds. With the defaults above, this service's
  worst-case LDAP time per logon is about 3000 ms (`connect-timeout` 1000 ms + `read-timeout`
  2000 ms), the same as `RequestTimeout`: if you raise the LDAP timeouts, raise `RequestTimeout`
  with them, and keep it below the AMPS client's own logon timeout. The in-memory backend answers in
  well under 100 ms.
- **No `<Entitlement>` block may reference `web-auth`** with the current permissions document.

**End-to-end check.** Log on with any AMPS client, e.g.

```
tcp://trader1:secret@amps-host:9007/amps/json
```

(or the equivalent `Client.logon()` with a username and password). A wrong password must be refused
by AMPS, and this service's log must show the corresponding line with `outcome=INVALID`.

---

## 9. Troubleshooting

Start with this service's log — there is exactly one INFO line per attempt, and the `outcome` field
names the reason. Response bodies are always empty by design, so the log and the metrics are the only
diagnosis surface.

| Symptom | Meaning | What to do |
|---|---|---|
| `403` with `outcome=INVALID` | The backend rejected the credentials — a genuinely wrong username or password. | Verify the password. For LDAP, check the account is not locked/expired and that `user-principal-pattern` builds the right principal for this user: the DEBUG line `LDAP bind rejected principal=... reason=...` shows exactly what was tried and the server's diagnostic, with whitespace rendered as `_` (Active Directory: `data_52e` wrong password, `775` locked, `532` expired, `533` disabled, `773` must change). |
| `503` with `outcome=BACKEND_UNAVAILABLE` | The credential backend is down, unreachable or timed out — **not** a bad password. | Find the accompanying **ERROR** line and its stack trace. For LDAP, check `amps.auth.ldap.url` (host, port, `ldaps` vs `ldap`), network/firewall reachability, `connect-timeout`/`read-timeout`, and the **truststore** ([5.4](#54-ldap-over-tls-and-the-jvm-truststore)) — a `PKIX path building failed` cause means the LDAP CA is not trusted. For `userinfo`, `userinfo endpoint returned status=404` means a wrong `amps.auth.userinfo.url`, `status=429`/`5xx` a provider problem, and `unreachable or timed out` a network, TLS or timeout problem. `/actuator/health` flips to `DOWN` when the `ldap`/`userInfo` health component fails, but with `show-details: never` it shows no component detail — the URL and error class are in the service log (`WARN ... health check ...`). |
| `403` with `outcome=INVALID` and a WARN `userinfo principal does not match the logon username user=<a> principal=<b>` | A valid access token of user `<b>` was presented with AMPS username `<a>`. | Usually a client passing the wrong username (for example `sAMAccountName` while the claim holds a UPN): change the client or `amps.auth.userinfo.principal-claim`. If `<a>` and `<b>` are different people, treat it as a security event. |
| `403` with `outcome=INVALID` and a DEBUG `user=... is not in an enabled group` | The token is valid but the user is in none of `amps.auth.userinfo.enabled-groups`, or the groups claim is missing. | Check the group membership at the provider, that the provider actually puts groups into the UserInfo response, and that `amps.auth.userinfo.groups-claim` names that claim. |
| Nothing at all appears in this service's log when a client logs on | The request never reached the service: an AMPS connectivity or TLS problem. | Check the **AMPS log** for the module's error lines. Verify the `ResourceURI` scheme, host, port and path (no `.json` suffix), that `CAKey` is the CA that signed this service's certificate, and that `ConnectionTimeout`/`RequestTimeout` are not shorter than the round trip. Reproduce the exact URL with `curl -v` from the AMPS host. |
| `401` with `outcome=NO_CREDENTIALS` | AMPS (or a probe/health checker/load balancer) called the endpoint with **no** `Authorization` header. | Harmless on its own — the `WWW-Authenticate: Basic realm="amps"` challenge tells the AMPS HTTP client to retry with credentials, and a successful retry follows immediately. If it is *not* followed by a real attempt, something other than AMPS is probing the endpoint, or the AMPS module is not configured to send credentials. |
| `403` with `outcome=USERNAME_MISMATCH` | The name AMPS substituted into `ResourceURI` differs from the Basic-auth logon username. | Check what `{{USER_NAME}}` expands to (domain prefixes, UPN vs `sAMAccountName`, URL-decoding of `\`). Either align the two, switch to the no-path-variable `ResourceURI`, or set `amps.auth.username-path-must-match: false`. |
| `403` with `outcome=MALFORMED` | The `Authorization` header was present but unusable: a non-`Basic` scheme (for example Digest), invalid base64, non-UTF-8 bytes, no `:` in the decoded value, or an empty username/password. | Configure the AMPS module for **Basic**, not Digest ([5.3](#53-ldap)). The DEBUG log of `com.example.ampsauth` shows the exact reason code. |
| `404` from the service | Wrong path in the `ResourceURI`. | The only endpoints are `/amps/v1/permissions/{username}` and `/amps/v1/permissions` — no `.json` suffix, no trailing slash. |
| AMPS logon succeeds but the client cannot subscribe or publish | An `<Entitlement>` block references this module, but the permissions document has no `topic` list. | Remove the `<Entitlement>` reference and keep AMPS's default allow-all entitlement module — see [3.5](#35-the-permissions-document-and-the-entitlement-caveat). |

**Startup failures.** The service fails fast rather than starting in a broken state. The message
always names the property:

| Message | Cause | Fix |
|---|---|---|
| `Failed to bind properties under 'amps.auth.backend'` (unknown name such as `kerberos`) or `Unsupported amps.auth.backend value '<x>'; expected one of: inmemory, ldap, userinfo` (a spelling such as `in-memory` that binds but selects nothing) | Typo in the backend name. | Use `inmemory`, `ldap` or `userinfo` (any case). |
| `amps.auth.userinfo.url must be set when amps.auth.backend=userinfo` / `must be an absolute http:// or https:// URL` / `enabled-groups must list at least one group` / `principal-claim must not be blank` / `groups-claim must not be blank` / `connect-timeout must be positive` | Incomplete UserInfo configuration. | Fill in the property ([4.1](#41-amps-properties), [5.5](#55-userinfo-oauth2oidc-access-token)). |
| `...password for user '<u>' is plaintext ({noop}); hash it with --hash-password or set amps.auth.inmemory.allow-plaintext=true (local profile only)` | A `{noop}` password without the opt-in. | Hash it ([5.2](#52-hashing-a-password)), or set `allow-plaintext: true` in the `local` profile only. |
| `...password for user '<u>' is not a valid bcrypt hash` / `must start with an encoder id such as {bcrypt}` / `uses an unsupported encoder id {...}` | A truncated, hand-edited or prefix-less password value. | Regenerate it with `--hash-password` and paste the whole `{bcrypt}...` string. |
| `...: duplicate username '<u>' (usernames are compared case-insensitively)` | The same user twice (possibly differing only in case). | Remove the duplicate. |
| `Binding to target ... List<AmpsProperties$User> ... failed` / `The elements [amps.auth.inmemory.users[n]...] were left unbound` | The user list is split across property sources (for example two users in a profile file plus `--amps.auth.inmemory.users[2].*` on the command line): Spring takes an indexed list from one source only. | Define every user in the same file. Note that this Spring binding report prints the offending values, so a `{noop}` password supplied that way would appear in the startup output — another reason to keep users in one place. |
| `permissions template not found: <loc>` / `is not valid JSON` / `must be a JSON object` | `amps.permissions.template` points at a missing or broken document. | Fix the path or the JSON. |
| WARN `permissions template ... does not contain a true "logon" flag` | The document would make AMPS refuse every logon. | Add `"logon": true`. |
| `amps.auth.ldap.url must be set when amps.auth.backend=ldap` / `user-principal-pattern must contain {0}` / `connect-timeout must be positive` | Incomplete LDAP configuration. | Fill in the property ([4.1](#41-amps-properties)). |

---

## 10. Security notes

- **Basic only, `403` for bad credentials.** `401` is reserved for "no credentials at all"; returning
  `401` for a wrong password would contradict the AMPS contract.
- **The password never leaves the request path.** It is never logged, never echoed, never put in an
  exception message, never used as a metric tag, and never stored. `BasicCredentials.toString()` and
  `AmpsProperties.User.toString()` mask it.
- **Empty username or password is rejected before any backend call** (and again inside the LDAP
  validator and JNDI factory), because an empty password can succeed as an anonymous LDAP bind.
- **Timing-uniform unknown users** in the in-memory backend (dummy bcrypt comparison).
- **Explicit timeouts** on every backend call.
- **`Cache-Control: no-store` on every response**, so no intermediary caches a permissions document.
- **Empty error bodies**; `server.error.include-message/stacktrace/exception` are all off.
- **Log fields are sanitised** ([3.2](#32-request-headers)), so a hostile username or header cannot
  forge or break a log line; the correlation id is echoed as-is but sanitised before it reaches the
  log.
- **Fail-fast configuration**: unknown backend, plaintext without opt-in, a bad template, duplicate or
  malformed users — all stop startup.
- **No Spring Security auto-configuration**, so there is no login page, no CSRF filter and no session
  cookie to attack.
- Run the service behind TLS ([6](#6-tls-for-this-service-and-optional-mtls)) and restrict network
  access to the AMPS hosts; the endpoint is an oracle for "is this password correct", so it should not
  be reachable from a general-purpose network.

---

## 11. Project layout and renaming the package root

The whole feature is **one flat package folder**, `src/main/java/com/example/ampsauth`: no
sub-packages, and no imports between its own classes, so it can be copied into another project as a
unit (see [11.1](#111-embedding-the-feature-in-another-application)). The standalone runner sits one
level above it. (This supersedes the sub-package layout sketched in `SPEC.md` section 7.)

```
src/main/java/com/example/
  AmpsAuthApplication.java          standalone runner: main(); handles --hash-password before SpringApplication.run
  OpenApiConfiguration.java         Swagger UI / OpenAPI description (only when springdoc.api-docs.enabled=true)
src/main/java/com/example/ampsauth/ <- the feature package: copy this folder
  AmpsAuthConfiguration.java        the single integration point: enables AmpsProperties, scans this package,
                                    builds PermissionsDocument, selects the CredentialValidator by amps.auth.backend
  AmpsProperties.java               validated records for every amps.* property
  PermissionsController.java        the two GET mappings; maps LogonOutcome -> ResponseEntity
  BasicCredentials.java             record(username, password); toString() masks the password
  BasicAuthorizationParser.java     parse(header): Optional<BasicCredentials>
  MalformedCredentialsException.java
  CorrelationIdFilter.java          correlation id -> MDC + response header; Cache-Control: no-store
  CredentialValidator.java          the backend SPI (public: implement it to add a backend)
  ValidationResult.java             VALID | INVALID | BACKEND_UNAVAILABLE
  InMemoryCredentialValidator.java
  LdapCredentialValidator.java
  DirContextFactory.java            JNDI seam for tests
  JndiDirContextFactory.java        default impl; also implements LdapProbe
  LdapProbe.java                    connectivity check for the health indicator
  LdapHealthIndicator.java          the optional "ldap" health component
  UserInfoCredentialValidator.java  access token -> UserInfo endpoint -> principal + enabled-group check
  UserInfoClient.java               HTTP seam for tests (fetch with a bearer token)
  JdkUserInfoClient.java            default impl on the JDK HttpClient; also implements UserInfoProbe
  UserInfoProbe.java                reachability check for the health indicator
  UserInfoHealthIndicator.java      the optional "userInfo" health component
  LogonService.java                 guards -> validator -> outcome; metrics; the one INFO line
  LogonOutcome.java                 SUCCESS | NO_CREDENTIALS | MALFORMED | USERNAME_MISMATCH | INVALID | BACKEND_UNAVAILABLE
  RequestMetadata.java              the X-AMPS-* values, for logging only
  LogSanitizer.java                 log-field sanitiser (control/whitespace/separator/= -> _, truncation)
  PermissionsDocument.java          loads and validates the template; serves the bytes
  PasswordHashTool.java             --hash-password
src/main/resources/
  application.yml
  application-local.yml
  amps/permissions-logon-only.json
src/test/java/com/example/ampsauth/ <- the tests, one flat folder as well (copy it alongside)
```

Only `AmpsAuthConfiguration`, `AmpsProperties`, `CredentialValidator`, `ValidationResult`,
`LogonOutcome`, `LogonService`, `RequestMetadata` and `PasswordHashTool` are public; everything else
is package-private, so a host application sees a small, deliberate surface.

### 11.1 Embedding the feature in another application

1. In IntelliJ IDEA, copy the package `com.example.ampsauth` (the folder above) into the host
   project's source root, for example under the host's root package as
   `com.acme.trading.ampsauth`. The copy dialog rewrites the `package` declarations; because the
   classes never import each other, nothing else needs fixing. Copy
   `src/test/java/com/example/ampsauth` the same way if you want the tests (they need
   `spring-boot-starter-test` and find the host's `@SpringBootApplication` by themselves).
2. Add the dependencies from [2.1](#21-requirements) that the host does not already have: the web
   starter, actuator, validation and `spring-security-crypto` (**not**
   `spring-boot-starter-security`).
3. Copy `src/main/resources/amps/permissions-logon-only.json` into the host's resources, or point
   `amps.permissions.template` at a file. Startup fails without a template.
4. Add the `amps.*` settings from [4](#4-configuration-reference) to the host's `application.yml`,
   plus the `management.*` and `server.error.*` settings from
   [4.2](#42-server-management-and-logging-settings) if the host has no equivalents. The record
   defaults mean the feature starts with the `inmemory` backend and no users, so every logon is
   refused until it is configured.
5. If the package is **not** below the host's `@SpringBootApplication` package, add
   `@Import(AmpsAuthConfiguration.class)` to one of the host's configuration classes; that is the
   only class the host ever references. If it is below, the normal component scan finds it.
6. Optionally add the two `PasswordHashTool` lines from `AmpsAuthApplication.main` to the host's
   `main` so `--hash-password` works there too.
7. Keep the endpoint paths (`/amps/v1/permissions...`) out of any host security filter chain: this
   package does its own authentication, and the AMPS contract needs `403`, not `401`, for bad
   credentials. If the host uses Spring Security, permit these paths explicitly.

The package root `com.example.ampsauth` is defined in exactly **one** place for the build and the
configuration: the `base.package` property in `pom.xml`. Nothing in the Java sources or the YAML
files spells it out as a string — `AmpsAuthConfiguration` enables the properties and scans its own
package, `AmpsAuthApplication` scans from one level above, and `application-local.yml` gets it
through Maven resource filtering. (This README mentions the name only as documentation.)

**To rename it:** change `base.package` in `pom.xml`, then rename the package `com.example.ampsauth`
in the IDE (the refactoring moves both source folders and fixes every reference in one step).

---

## 12. Out of scope (for now)

Not built in this iteration, but deliberately not precluded either:

- **Topic / admin entitlements** (per-user `topic` and `admin` permission lists). The success document
  is served from a loadable template precisely so this can be added later — see the caveat in
  [3.5](#35-the-permissions-document-and-the-entitlement-caveat).
- **Digest authentication** — cannot be implemented against an LDAP bind.
- **Replication logon permissions** and `user_name` overrides (the default document ships
  `"replication-logon": false`).
- **Account lockout / rate limiting.** Repeated `outcome=INVALID` is visible in the metrics, but the
  service itself throttles nothing.
- **Any database, session store, local JWT validation or token issuance.** The service stays
  stateless; the `userinfo` backend only *calls* the identity provider with the token it was given.
- **Search-then-bind LDAP** with a service account — see [5.3](#53-ldap).
