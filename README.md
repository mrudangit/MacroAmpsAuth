# AMPS Logon Authentication Service

A small, stateless Spring Boot service that answers logon requests from the AMPS (60East)
**RESTful Authentication and Entitlement module** (`libamps_http_entitlement.so`).

The AMPS client logs on with its username and an **OAuth2/OIDC access token as the password**
(obtained beforehand, typically through an Authorization Code + PKCE flow). AMPS calls this service
with the username in the URL path and the token in a request header. The service sends the token to
the identity provider's **UserInfo endpoint**, checks that the user it describes is the user who is
logging on (and, optionally, is in an enabled group), and answers `200` with a JSON *permissions
document* (`"logon": true`), `403` when the logon must be refused, or `503` when the identity
provider is unavailable.

```
AMPS client ──logon(user, token)──▶ AMPS ──GET /amps/v1/permissions/{user}──▶ this service ──GET userinfo──▶ identity provider
                                              X-AMPS-Password: {token}                 Authorization: Bearer {token}
                                    ◀── 200 {"logon": true} / 403 / 503 ──                ◀── 200 {"sub": "...", "csgroups": [...]} ──
```

Reference for the AMPS side of the contract:
<https://crankuptheamps.com/docs/amps-user-guide/securing/http-auth-module> (AMPS 5.3.x User Guide).

---

## Table of contents

- [1. How AMPS uses this service](#1-how-amps-uses-this-service)
- [2. Build and run](#2-build-and-run)
- [3. HTTP API](#3-http-api)
- [4. Configuration reference](#4-configuration-reference)
- [5. The UserInfo check](#5-the-userinfo-check)
- [6. The permissions document (and the entitlement caveat)](#6-the-permissions-document-and-the-entitlement-caveat)
- [7. Logging, metrics and health](#7-logging-metrics-and-health)
- [8. TLS](#8-tls)
- [9. AMPS configuration](#9-amps-configuration)
- [10. Troubleshooting](#10-troubleshooting)
- [11. Security notes](#11-security-notes)
- [12. Project layout and embedding](#12-project-layout-and-embedding)
- [13. Out of scope](#13-out-of-scope)

---

## 1. How AMPS uses this service

- On every client logon the AMPS module issues `GET <ResourceURI>`, with `{{USER_NAME}}` in the
  configured URI replaced by the logon username.
- Extra request headers come from `HTTPHeader` options on the AMPS side. This service reads the logon
  password from the header built with the `{{AMPS_PASSWORD}}` token (`X-AMPS-Password` by default)
  and treats it as the access token. The module also carries the credentials as HTTP Basic
  authentication, which it sends after a `401` challenge. The AMPS doc does not say whether the
  `HTTPHeader` values are already present on the module's initial, credential-less request, so a
  request **without** the token header is answered with `401` and `WWW-Authenticate: Basic
  realm="amps"`: the module then retries with its credentials and headers either way. The Basic
  credentials themselves are ignored; only the header counts.
- Response semantics expected by AMPS: `200` with a valid JSON permissions document authenticates the
  logon (`"logon": true` grants permission to log on); `403` rejects it; anything else (timeout,
  `5xx`, unparseable body) also rejects it.
- **Timing.** The module's own defaults are a 2 s connect timeout and a 5 s request timeout, and the
  call happens on an AMPS server thread. After an AMPS failover every client logs on at once, so the
  service must absorb bursts (embedded Tomcat runs 200 worker threads). Each logon costs one
  UserInfo round trip; keep the AMPS `RequestTimeout` above the service's worst case
  (`connect-timeout + read-timeout`, 3 s by default) — see [9](#9-amps-configuration).
- **Caching and statelessness.** AMPS calls this service only at logon and caches the parsed document
  per user name while that user has any open connection (the cache skips re-parsing, not the HTTP
  call: every logon is one credential-checked GET). The service is stateless and idempotent: the
  same token always produces the same answer. A revoked token, or a user removed from the enabled
  group, therefore only takes effect at that user's **next logon**; existing connections are
  unaffected. To force a user off immediately, reset that user's entitlements on the AMPS side
  (`amps-action-do-reset-entitlement`), which closes their connections.

---

## 2. Build and run

| | |
|---|---|
| Java | **21** (LTS); the build compiles with `--release 21`. |
| Spring Boot | **4.1.1** (current GA). All dependency versions come from the Spring Boot BOM. |
| Build tool | **Maven**, single module. |
| Artifact | `target/amps-auth-service.jar` (executable Spring Boot jar). |

Dependencies: `spring-boot-starter-webmvc`, `spring-boot-starter-actuator`,
`spring-boot-starter-validation`, and `springdoc-openapi-starter-webmvc-ui` for the optional Swagger
UI. The UserInfo call uses the JDK's own `java.net.http.HttpClient`. There is deliberately **no**
`spring-boot-starter-security`: the AMPS contract needs `403` (not `401`) for refused logons and no
login page, CSRF or sessions.

```bash
mvn verify          # compiles, runs every unit and integration test, packages the jar
```

### Run locally

The `local` profile turns on Swagger UI and DEBUG logging and points the UserInfo URL at
`http://localhost:9999/userinfo`. Either point that property at a real identity provider or start the
bundled stub, which accepts any token except `bad` and answers with user `U000001` in group
`amps-users`:

```bash
python3 local/stub-userinfo.py &                                        # stand-in identity provider
java -jar target/amps-auth-service.jar --spring.profiles.active=local
```

Smoke-test matrix (the comments are the exact expected status codes):

```bash
curl -i -H 'X-AMPS-Password: eyJ.some.token' http://localhost:8080/amps/v1/permissions/U000001   # 200 + JSON
curl -i -H 'X-AMPS-Password: eyJ.some.token' http://localhost:8080/amps/v1/permissions/u000001   # 200 (case-insensitive)
curl -i -H 'X-AMPS-Password: eyJ.some.token' http://localhost:8080/amps/v1/permissions/other     # 403 (token belongs to U000001)
curl -i -H 'X-AMPS-Password: bad'            http://localhost:8080/amps/v1/permissions/U000001   # 403 (identity provider says 401)
curl -i                                      http://localhost:8080/amps/v1/permissions/U000001   # 401 + WWW-Authenticate (no token)
curl -s http://localhost:8080/actuator/health                                                   # {"status":"UP"}
```

Stop the stub and the first call answers `503` (identity provider unreachable).

**Swagger UI.** With the `local` profile it is at <http://localhost:8080/swagger-ui.html> (OpenAPI
document at `/v3/api-docs`). Click **Authorize**, paste the access token (it goes into the
`X-AMPS-Password` header), then try the endpoint with the username in the path. Swagger is **off by
default** so production has no extra routes; enable it elsewhere with
`--springdoc.api-docs.enabled=true --springdoc.swagger-ui.enabled=true`.

---

## 3. HTTP API

### Endpoints

| Method | Path | Purpose |
|---|---|---|
| `GET` | `/amps/v1/permissions/{username}` | The only logon endpoint. `{username}` is what AMPS substituted for `{{USER_NAME}}`. |
| `GET` | `/actuator/health`, `/actuator/health/liveness`, `/actuator/health/readiness` | Ops probes. |
| `GET` | `/actuator/info`, `/actuator/metrics` | Ops. |

Nothing else is routed: the actuator index page is disabled, only `health`, `info` and `metrics` are
exposed, and Swagger routes exist only when enabled. Unknown paths, a trailing slash, or a missing
path variable get Spring's default `404` with no message, exception or stack trace in the body; an
unsupported method gets the same style of `405`.

> Do not put a `.json` suffix on the AMPS `ResourceURI`: `/amps/v1/permissions/U000001.json` would be
> treated as the username `U000001.json`.

### Request headers

| Header | AMPS `HTTPHeader` token | Required | Handling |
|---|---|---|---|
| `X-AMPS-Password` (name from `amps.auth.password-header`) | `{{AMPS_PASSWORD}}` | yes | The access token, taken verbatim (nothing trimmed). Missing or blank → `401` with a Basic challenge. A value containing control characters → `403` without any UserInfo call. |
| `X-AMPS-Client-Name` | `{{AMPS_CLIENT_NAME}}` | no | Logged only. |
| `X-AMPS-Remote-Address` | `{{AMPS_REMOTE_ADDRESS}}` | no | Logged only. |
| `X-AMPS-Connection-Name` | `{{AMPS_CONNECTION_NAME}}` | no | Logged only. |
| `X-AMPS-Correlation-Id` | `{{AMPS_CORRELATION_ID}}` | no | Echoed back **verbatim** as the same response header and put into the log MDC as `corr=...` (sanitised, bounded to 256 characters). |
| `Authorization` | (sent by the module itself) | — | Ignored. |

Every request-supplied value that reaches a log line (`user`, `client`, `remote`, `conn`, `corr`) is
sanitised first: control characters, whitespace, Unicode separators, format characters and `=` become
`_`, and the value is truncated. A value can therefore neither break a log line nor forge another
`key=value` token. Access tokens are long: Tomcat's default 8 KB request-header limit fits tokens of
roughly 6 KB; raise `server.max-http-request-header-size` for larger ones.

### Responses

| Situation | Outcome (log / metric) | Status | Body |
|---|---|---|---|
| Token accepted, principal matches, group check passed | `SUCCESS` | `200` | the permissions document, `Content-Type: application/json` |
| Password header missing or blank | `NO_TOKEN` | `401` | empty; `WWW-Authenticate: Basic realm="amps"` |
| Identity provider answered `401` or `403`, or the token contains control characters | `INVALID_TOKEN` | `403` | empty |
| Token valid but its principal claim ≠ the path username | `PRINCIPAL_MISMATCH` | `403` | empty |
| Token valid, user matches, but in none of `enabled-groups` | `NOT_ENTITLED` | `403` | empty |
| Identity provider unreachable, timed out, other status, or non-JSON body | `BACKEND_UNAVAILABLE` | `503` | empty |

Every response carries `Cache-Control: no-store` and, when the request had one,
`X-AMPS-Correlation-Id`. **Error bodies are always empty**; the reason lives only in the service
log. `401` is returned only for a missing token, as the challenge that makes the AMPS module retry with
its credentials and headers; a refused logon is always `403`.

---

## 4. Configuration reference

Configuration is bound from `amps.*` into validated records (`AmpsProperties`). Anything that cannot
bind or fails validation **fails startup** with a message naming the property. Values can come from
`application.yml`, a profile file, environment variables (`AMPS_AUTH_USERINFO_URL=...`) or the command
line (`--amps.auth.userinfo.url=...`).

| Property | Type | Default | Meaning |
|---|---|---|---|
| `amps.auth.password-header` | string | `X-AMPS-Password` | Request header that carries the AMPS logon password (the access token). Must match the `HTTPHeader` name in the AMPS configuration. |
| `amps.auth.userinfo.url` | string | `https://login.example.com/oauth2/userinfo` (from `application.yml`) | The UserInfo endpoint, called with `Authorization: Bearer <token>`. **Required**; must be an absolute `http(s)://` URL. A plain `http://` URL logs a **WARN** at startup (tokens in clear text). Redirects are never followed. |
| `amps.auth.userinfo.principal-claim` | string | `sub` | Claim whose value must equal the username in the request path (case-insensitive). Exact claim name first, then a dotted path into nested objects. Alternatives seen in practice: `cssamaccountname`, `preferred_username`, `upn`, `email`. |
| `amps.auth.userinfo.groups-claim` | string | `csgroups` (from `application.yml`; record default `groups`) | Claim listing the user's groups: a JSON array of strings, or one string of space/comma-separated names. Exact name first (so namespaced names such as `https://example.com/groups` work), then a dotted path such as `realm_access.roles`. |
| `amps.auth.userinfo.enabled-groups` | list of strings | empty | Groups that grant logon; the user must be in **at least one** (compared case-insensitively, trimmed). **Empty means no group check**: every user with a valid token whose principal matches may log on, and a WARN says so at startup. |
| `amps.auth.userinfo.connect-timeout` | duration | `1000ms` | TCP/TLS connect timeout of the UserInfo call. Must be positive. |
| `amps.auth.userinfo.read-timeout` | duration | `2000ms` | Response timeout of the UserInfo call. Must be positive. `connect-timeout + read-timeout` is the worst case per logon; keep it below the AMPS `RequestTimeout`. |
| `amps.auth.userinfo.health-indicator-enabled` | boolean | `true` | Registers a `userInfo` health component that sends an **unauthenticated** GET to the endpoint; any HTTP answer (typically `401`) is `UP`, only a connection failure or timeout is `DOWN`. Contributes to `/actuator/health` only, never to readiness or liveness. |
| `amps.permissions.template` | string (Spring resource location) | `classpath:amps/permissions-logon-only.json` | Where the success document comes from. May be `file:/path/to/doc.json`. Loaded once at startup; startup fails if it is missing or not a JSON object. |

### Server, management and logging settings (`application.yml`)

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
        enabled: true                   # /actuator/health/liveness and /readiness
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

### The `local` profile (`application-local.yml`)

Swagger UI on, DEBUG for the service package, UserInfo URL `http://localhost:9999/userinfo`,
`enabled-groups: [amps-users]`. Plain HTTP. Never use it in production. The `logging.level` key is
written as `@base.package@` in the source file and filled in by Maven resource filtering from the
`base.package` property in `pom.xml`.

---

## 5. The UserInfo check

For each logon the service:

1. Takes the token from the password header. Missing or blank → `NO_TOKEN`. Control characters →
   `INVALID_TOKEN` (such a value could never be a real token and must not reach an HTTP header).
2. Sends `GET amps.auth.userinfo.url` with `Authorization: Bearer <token>` and
   `Accept: application/json`, with the configured timeouts, never following redirects.
3. Requires a `200` with a JSON object. `401`/`403` → `INVALID_TOKEN`; any other status, a redirect, a
   non-JSON body or a non-object → `BACKEND_UNAVAILABLE` (logged at ERROR).
4. Requires the **principal claim** to equal the path username, case-insensitively. This is what binds
   the token to the name AMPS will use as the identity: without it, any valid token of any user could
   log on under any name. A mismatch is logged at **WARN** with both names.
5. If `enabled-groups` is non-empty, requires the **groups claim** to contain at least one of them
   (case-insensitive, trimmed). Otherwise `NOT_ENTITLED`.

The default configuration matches a UserInfo response of this shape (the corporate ID in `sub`, the
group list in `csgroups`; other fields are ignored):

```json
{
  "sub": "U000001",
  "csmail": "jane.doe@example.com",
  "cssamaccountname": "U000001",
  "csgroups": ["DTCA_TEAM_A", "AMPS_PROD_USERS"]
}
```

With `enabled-groups: [AMPS_PROD_USERS]`, user `U000001` presenting a valid token for that record may
log on as `U000001` (or `u000001`), and nobody else may log on with that token.

The token is never logged, never echoed, and is only ever sent to the configured URL. The provider's
certificate is validated against the **JVM truststore** (see [8](#8-tls)). Which claims the provider
returns depends on its configuration; check once with
`curl -H "Authorization: Bearer <token>" <url>` and set `principal-claim`/`groups-claim` accordingly.

---

## 6. The permissions document (and the entitlement caveat)

On success the service returns the **verbatim bytes** of `amps.permissions.template`. The default,
`classpath:amps/permissions-logon-only.json`:

```json
{
  "logon": true,
  "replication-logon": false
}
```

- Loaded and validated **once at startup**; startup fails if the resource is missing, unreadable, not
  valid JSON (trailing content included), or not a JSON object. A **WARN** is logged if it does not
  contain `"logon": true` (the AMPS doc requires `logon` to be boolean when present and defines no
  default when absent, so always set it explicitly).
- Point the property at a file (`file:/etc/amps-auth/permissions.json`) to change the document without
  a rebuild; a **restart** is required. The bytes are served exactly as on disk.
- `"replication-logon": false` means AMPS **refuses any replication connection** whose logon is
  authenticated by this module. If the instance accepts inbound replication, authenticate that
  transport with a different module.

> ### ⚠ Entitlement caveat
>
> This document contains **no `topic` list and no `admin` list**. Per the AMPS doc a user without a
> `topic` list cannot publish or subscribe to anything, so AMPS must **not** reference this module in
> an `<Entitlement>` block yet — keep AMPS's default (allow-all) entitlement module and wire this
> module under `<Authentication>` only, exactly as in [9](#9-amps-configuration). If the module is
> later used for entitlements as well, `topic` and `admin` permission lists must be added to the
> document first, in the doc's shape (`{"topic": "orders", "read": true, "write": false}`).

---

## 7. Logging, metrics and health

**Exactly one INFO line per logon attempt:**

```
logon user=U000001 outcome=SUCCESS client=MacroDesktop-jdoe remote=10.1.2.3 conn=json-tcp-17 ms=41
```

`user` is the path username, `outcome` one of the six values in [3](#3-http-api), `client`/`remote`/
`conn` the `X-AMPS-*` headers (or `-`), `ms` the wall-clock time including the UserInfo call. The
correlation id is rendered as `corr=` by the console pattern. Other output: **ERROR** with the
exception for every `BACKEND_UNAVAILABLE`; **WARN** for a principal mismatch (`userinfo principal
does not match the logon username user=<a> principal=<b>`); **DEBUG** for a rejected token or a
missing group; **INFO** at startup naming the UserInfo URL, the claims and the enabled groups. The
token, the password header and full request headers are **never** logged, and no request-logging
filter is enabled. AMPS may probe the endpoint without the header before sending it, so one AMPS
logon can appear as a `NO_TOKEN` line followed by the real outcome; do not alert on `NO_TOKEN` alone.

**Metrics** (Micrometer, pre-registered at startup, tagged **only** with `outcome`, never a username):

| Meter | Type |
|---|---|
| `amps.logon.attempts` | counter |
| `amps.logon.duration` | timer |

```bash
curl -s 'http://localhost:8080/actuator/metrics/amps.logon.attempts?tag=outcome:INVALID_TOKEN'
```

Worth alerting on: a sustained non-zero rate of `BACKEND_UNAVAILABLE` (identity provider down) and a
spike in `PRINCIPAL_MISMATCH` (tokens presented under other users' names).

**Health.** `/actuator/health` includes the optional `userInfo` component; `liveness` and
`readiness` never depend on the identity provider, so a flapping provider cannot pull every instance
out of the load balancer at once (an outage is visible per request as `503` and in the metrics). If
your load balancer probes `/actuator/health` rather than `/readiness`, set
`amps.auth.userinfo.health-indicator-enabled: false`. `show-details` is `never`, so health endpoints
return only `{"status":"UP"}`.

---

## 8. TLS

**This service.** In production terminate TLS here with a Spring SSL bundle; AMPS verifies the
certificate through its `CAKey` option. Plain HTTP is acceptable only in the `local` profile.

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
```

(A JKS/PKCS12 keystore works the same way under `spring.ssl.bundle.jks`.) For optional **mTLS** add
`server.ssl.client-auth: need` and a `truststore` with the AMPS client CA to the bundle, and give the
AMPS module `<Certificate>` and `<Key>`; this authenticates the AMPS instance, not the end user.

**The identity provider.** The UserInfo URL's certificate is validated against the JVM truststore.
For a private CA, import it or point the JVM at your own store:

```bash
java -Djavax.net.ssl.trustStore=/etc/amps-auth/truststore.p12 \
     -Djavax.net.ssl.trustStorePassword="$TRUSTSTORE_PASSWORD" -Djavax.net.ssl.trustStoreType=PKCS12 \
     -jar target/amps-auth-service.jar
```

A missing CA shows up as `503` / `BACKEND_UNAVAILABLE` with `PKIX path building failed` in the ERROR
line.

**AMPS → this service.** With an `https://` ResourceURI the AMPS doc requires `CAKey` unless
`AllowUnverifiedPeer` is `true`, and refuses self-signed certificates unless `AllowSelfSigned` is
`true` (both default to `false`). For a self-signed test certificate use the doc's test-only options:

```xml
<AllowUnverifiedPeer>true</AllowUnverifiedPeer>   <!-- TEST ONLY -->
<AllowSelfSigned>true</AllowSelfSigned>           <!-- TEST ONLY -->
```

---

## 9. AMPS configuration

Logon-only wiring: the module is used for `Authentication` only. Do **not** add an `<Entitlement>`
block for it (see [6](#6-the-permissions-document-and-the-entitlement-caveat)).

```xml
<Modules>
  <Module>
    <Name>web-auth</Name>
    <Library>libamps_http_entitlement.so</Library>
    <Options>
      <ResourceURI>https://amps-auth.example.com:8443/amps/v1/permissions/{{USER_NAME}}</ResourceURI>
      <!-- the logon password (the access token) travels in this header -->
      <HTTPHeader>X-AMPS-Password: {{AMPS_PASSWORD}}</HTTPHeader>
      <HTTPHeader>X-AMPS-Client-Name: {{AMPS_CLIENT_NAME}}</HTTPHeader>
      <HTTPHeader>X-AMPS-Remote-Address: {{AMPS_REMOTE_ADDRESS}}</HTTPHeader>
      <HTTPHeader>X-AMPS-Correlation-Id: {{AMPS_CORRELATION_ID}}</HTTPHeader>
      <HTTPHeader>X-AMPS-Connection-Name: {{AMPS_CONNECTION_NAME}}</HTTPHeader>
      <ReuseConnections>enabled</ReuseConnections>
      <ConnectionTimeout>1000</ConnectionTimeout>
      <RequestTimeout>4000</RequestTimeout>
      <!-- production TLS: AMPS verifies the service certificate -->
      <CAKey>/etc/amps/security/ca.pem</CAKey>
      <!-- local testing over plain http: switch ResourceURI to http:// AND remove CAKey -->
    </Options>
  </Module>
</Modules>

<!-- Instance-wide authentication; can also be placed inside an individual <Transport>. -->
<Authentication>
  <Module>web-auth</Module>
</Authentication>
```

Points to check when adapting it:

- The `HTTPHeader` name must equal `amps.auth.password-header`. The value is the logon password
  verbatim, so the client must pass the access token as its password (for example
  `tcp://U000001:<access token>@amps-host:9007/amps/json`, or `Client.logon()` with the token).
- The `ResourceURI` has **no `.json` suffix** and needs `{{USER_NAME}}`: the username in the path is
  the identity the token is checked against. Use it only for names made of letters, digits and
  `.-_@`; the AMPS doc does not say whether other characters are percent-encoded.
- **Timeouts** are milliseconds. This service's worst case per logon is `connect-timeout +
  read-timeout` (3000 ms by default); `RequestTimeout` must stay **above** that, and at or below the
  module default of 5000 ms (the doc warns of stuck-thread warnings beyond it). Leave `RetryCount` at
  its default `0`: the doc retries "for any reason", which would repeat rejected tokens too.
- `ReuseConnections` is only honoured inside `<Modules><Module><Options>`; AMPS ignores it in an
  `<Authentication>` block. It is optional: this service closes idle connections after
  `server.tomcat.connection-timeout` (5 s).
- Options set in `<Modules>` are inherited defaults; an `<Options>` block inside `<Authentication>`
  (instance-wide or per `<Transport>`) overrides them. If several transports use different
  `ResourceURI` values, set the same `CredentialStore` on each so AMPS keeps one cache per user.
- Leave `ServerAcceptsEmptyAuthId` at its default `false`: this service needs the username in the
  path and never returns `user_name`, so token-only logons without a username cannot work.
- Do **not** load the module with `<EntitlementOnly/>`: in that mode AMPS sends no credentials at
  all, this service answers `401` to every request, and every entitlement check fails.
- Every AMPS client logs on through this service, including Galvanometer's SQL tab; such users must
  paste an access token as the password.

**End-to-end check.** Log on with any AMPS client using the token as the password. A rejected token
must be refused by AMPS, and this service's log must show the corresponding `outcome=INVALID_TOKEN`
line.

---

## 10. Troubleshooting

Start with this service's log: there is exactly one INFO line per attempt and the `outcome` names the
reason. Response bodies are always empty by design.

| Symptom | Meaning | What to do |
|---|---|---|
| `401` with `outcome=NO_TOKEN` | The request had no (or a blank) password header. | The `WWW-Authenticate` challenge makes the AMPS module retry with its credentials and headers, so a single `NO_TOKEN` followed by a real attempt is normal. A steady stream of `NO_TOKEN` lines with no real attempt means the `HTTPHeader` name does not equal `amps.auth.password-header`, or the module is in `EntitlementOnly` mode. |
| `403` with `outcome=INVALID_TOKEN` | The identity provider answered `401`/`403`: expired, revoked or malformed token, or a token for another provider. | Obtain a fresh token; check it against the UserInfo URL with `curl -H "Authorization: Bearer <token>" <url>`. |
| `403` with `outcome=PRINCIPAL_MISMATCH` and a WARN `principal does not match ... user=<a> principal=<b>` | A valid token of user `<b>` was presented with AMPS username `<a>`. | Usually the client passing a different form of the name than the claim holds (for example an e-mail while `sub` is the ID): change the client or `amps.auth.userinfo.principal-claim`. If `<a>` and `<b>` are different people, treat it as a security event. |
| `403` with `outcome=NOT_ENTITLED` | Token valid, user matches, but not in any enabled group (or the groups claim is missing). | Check the group membership at the provider, that the provider puts groups into the UserInfo response, and that `groups-claim` names that claim (DEBUG logs the groups seen). |
| `503` with `outcome=BACKEND_UNAVAILABLE` | The identity provider is down, unreachable, slow, or answered something unusable — **not** a bad token. | Read the ERROR line: `status=404` means a wrong `amps.auth.userinfo.url`, `status=429`/`5xx` a provider problem, `unreachable or timed out` a network, TLS or timeout problem (`PKIX path building failed` = untrusted provider CA, see [8](#8-tls)). |
| Nothing in this service's log when a client logs on | The request never reached the service: an AMPS connectivity or TLS problem. | Check the **AMPS log** for the module's error lines. Verify the `ResourceURI` scheme, host, port and path, that `CAKey` is the CA that signed this service's certificate (or the `AllowSelfSigned`/`AllowUnverifiedPeer` test options), and the `ConnectionTimeout`/`RequestTimeout` values. Reproduce with `curl -v` from the AMPS host. |
| AMPS refuses the logon but the service logged `SUCCESS` with `ms=` close to `RequestTimeout` | The answer arrived after the module closed the connection. | Raise `RequestTimeout` or lower the UserInfo timeouts. |
| AMPS logon succeeds but the client cannot subscribe or publish | An `<Entitlement>` block references this module, but the document has no `topic` list. | Remove the reference; see [6](#6-the-permissions-document-and-the-entitlement-caveat). |

**Startup failures** always name the property: a missing `amps.auth.userinfo.url`
(`must not be blank`), a URL that is not `http(s)://`, a blank `password-header` or claim name, a
non-positive timeout, or a permissions template that is missing / not valid JSON / not an object.

---

## 11. Security notes

- **The token never leaves the request path** except to the configured UserInfo URL: never logged,
  echoed, put in an exception message or a metric tag; redirects are never followed.
- **The token is bound to the username** by the principal-claim check; disabling it would let any
  valid token log on as anyone, so there is no switch for it.
- **Empty `enabled-groups` means no group check**, announced by a WARN at startup.
- **Explicit timeouts** on the UserInfo call; **`Cache-Control: no-store`** and empty error bodies on
  every response; `server.error.include-*` all off.
- **Log fields are sanitised**, so a hostile username or header cannot forge or break a log line.
- **Fail-fast configuration** and **no Spring Security auto-configuration** (no login page, CSRF or
  session cookie).
- Run behind TLS and restrict network access to the AMPS hosts: the endpoint is an oracle for "is
  this token valid for this user".

---

## 12. Project layout and embedding

The whole feature is one flat package folder, `src/main/java/com/example/ampsauth`, with no
sub-packages, so it can be copied into another project as a unit. The standalone runner and the
Swagger configuration sit one level above it.

```
src/main/java/com/example/
  AmpsAuthApplication.java          standalone runner
  OpenApiConfiguration.java         Swagger UI / OpenAPI description (only when springdoc.api-docs.enabled=true)
src/main/java/com/example/ampsauth/ <- the feature package: copy this folder
  AmpsAuthConfiguration.java        the single integration point: properties, scan, document, client, authenticator
  AmpsProperties.java               validated records for every amps.* property
  PermissionsController.java        GET /amps/v1/permissions/{username}: path + header -> LogonService -> status
  LogonService.java                 guards -> authenticator -> LogonOutcome; metrics; the one INFO line
  LogonOutcome.java                 SUCCESS | NO_TOKEN | INVALID_TOKEN | PRINCIPAL_MISMATCH | NOT_ENTITLED | BACKEND_UNAVAILABLE
  UserInfoAuthenticator.java        token -> UserInfo endpoint -> principal + group check
  UserInfoClient.java               HTTP seam for tests (fetch with a bearer token)
  JdkUserInfoClient.java            default impl on the JDK HttpClient; also implements UserInfoProbe
  UserInfoProbe.java                reachability check for the health indicator
  UserInfoHealthIndicator.java      the optional "userInfo" health component
  CorrelationIdFilter.java          correlation id -> MDC + response header; Cache-Control: no-store
  RequestMetadata.java              the X-AMPS-* values, for logging only
  LogSanitizer.java                 log-field sanitiser
  PermissionsDocument.java          loads and validates the template; serves the bytes
src/main/resources/
  application.yml, application-local.yml, amps/permissions-logon-only.json
src/test/java/com/example/ampsauth/ <- the tests (StubUserInfoServer is the fake identity provider)
local/stub-userinfo.py              stand-in UserInfo endpoint for local runs
```

To embed the feature in another Spring Boot application: copy the package folder (the classes never
import each other by package name, so an IDE "copy package" just works), add the three starters, copy
the permissions template, add the `amps.*` settings, and if the package is not below the host's
`@SpringBootApplication` package add `@Import(AmpsAuthConfiguration.class)`. Keep
`/amps/v1/permissions/**` out of any host security filter chain. The package root is defined once, as
`base.package` in `pom.xml`; rename it there and in the IDE.

---

## 13. Out of scope

- **Topic / admin entitlements** — the document is a loadable template so they can be added later.
- **Password-based backends** (in-memory users, LDAP bind): the logon password is always an access
  token in this design.
- **HTTP Basic or Digest handling**: the module's `Authorization` header is ignored; the `401`
  challenge exists only to make the module retry with its headers.
- **Token-only logons without a username** (`ServerAcceptsEmptyAuthId`, `user_name` in the document).
- **Local JWT validation or token issuance**, sessions, databases: the service only calls the
  identity provider with the token it was given.
- **Replication logons**, the Admin transport, `EntitlementOnly` mode, account lockout and rate
  limiting.
