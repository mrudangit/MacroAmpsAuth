# AMPS Logon Authentication Service — Specification

Revised 2026-09-11. This supersedes the original build specification: the service no longer parses
HTTP Basic credentials or validates passwords itself. The AMPS logon password is an **OAuth2/OIDC
access token**, AMPS forwards it in a request header, and the service checks it against the identity
provider's **UserInfo endpoint**. README.md is the operator documentation; this file is the contract.

Reference for the AMPS side: https://crankuptheamps.com/docs/amps-user-guide/securing/http-auth-module

---

## 1. What AMPS does

- On logon the AMPS module (`libamps_http_entitlement.so`) sends `GET <ResourceURI>` with
  `{{USER_NAME}}` replaced by the logon username, plus one header per configured `HTTPHeader`. The
  `{{AMPS_PASSWORD}}` token expands to the logon password.
- `200` with a JSON permissions document containing `"logon": true` authenticates the logon. `403`
  rejects it. Any other failure also rejects it.
- The module also carries the credentials as HTTP Basic/Digest, sent after a `401` challenge. The doc
  does not say whether `HTTPHeader` values are on the module's initial credential-less request, so a
  request without the token header is answered `401` + `WWW-Authenticate: Basic realm="amps"`, which
  makes the module retry with credentials and headers. The `Authorization` header is ignored.
- Module defaults: connect timeout 2000 ms, request timeout 5000 ms, no retries. The call runs on an
  AMPS server thread; logons burst after a failover. AMPS caches the parsed document per user name
  while the user has open connections and only calls the service at logon.

## 2. Scope

In scope: one endpoint; token check against a configurable UserInfo URL with principal and optional
group checks; fixed permissions document from a template; health, metrics, one log line per attempt;
tests; README with the AMPS configuration block; optional Swagger UI for manual testing.

Out of scope (do not build, do not preclude): topic/admin entitlements; password backends (in-memory,
LDAP); Basic/Digest handling; token-only logons without a username (`ServerAcceptsEmptyAuthId`,
`user_name` in the document); local JWT validation; replication logons; `EntitlementOnly` mode;
lockout or rate limiting; any database or session.

## 3. Technology

Java 21, Spring Boot current GA (BOM-managed versions), Maven single module, executable jar
`amps-auth-service.jar`, `mvn verify` must pass. Dependencies: `spring-boot-starter-webmvc`,
`spring-boot-starter-actuator`, `spring-boot-starter-validation`, `springdoc-openapi-starter-webmvc-ui`
(inert unless enabled), `spring-boot-starter-test`. The UserInfo call uses the JDK `HttpClient`.
**No `spring-boot-starter-security`.** No Lombok; records for values; constructor injection. Package
root `com.example.ampsauth`, one flat package, defined once (`base.package` in `pom.xml`). Empty
bodies on `403`/`503`; never expose stack traces.

## 4. HTTP contract

| Method | Path | Purpose |
|---|---|---|
| `GET` | `/amps/v1/permissions/{username}` | The logon endpoint. `{username}` is what AMPS substituted for `{{USER_NAME}}`. |
| `GET` | `/actuator/health`, `/actuator/health/liveness`, `/actuator/health/readiness`, `/actuator/info`, `/actuator/metrics` | Ops. |

No other routes (no no-path-variable form, no trailing slash); unknown paths → default `404` without
details; other methods → `405`.

Request headers:

| Header | AMPS token | Handling |
|---|---|---|
| `X-AMPS-Password` (configurable: `amps.auth.password-header`) | `{{AMPS_PASSWORD}}` | The access token, verbatim. Required. |
| `X-AMPS-Client-Name`, `X-AMPS-Remote-Address`, `X-AMPS-Connection-Name` | `{{AMPS_CLIENT_NAME}}`, `{{AMPS_REMOTE_ADDRESS}}`, `{{AMPS_CONNECTION_NAME}}` | Log only. |
| `X-AMPS-Correlation-Id` | `{{AMPS_CORRELATION_ID}}` | MDC key `ampsCorrelationId`; echoed back as the same response header. |
| `Authorization` | — | Ignored. |

Responses (acceptance criteria), in the order the checks are applied:

| Situation | Outcome | Status | Body |
|---|---|---|---|
| Password header missing or blank | `NO_TOKEN` | `401` | empty; `WWW-Authenticate: Basic realm="amps"`; no UserInfo call |
| Token contains control characters | `INVALID_TOKEN` | `403` | empty; no UserInfo call |
| UserInfo endpoint answers `401` or `403` | `INVALID_TOKEN` | `403` | empty |
| UserInfo endpoint unreachable, timed out, threw, other status, redirect, non-JSON or non-object body | `BACKEND_UNAVAILABLE` | `503` | empty |
| Principal claim missing or ≠ path username (case-insensitive) | `PRINCIPAL_MISMATCH` | `403` | empty; WARN with both names |
| `enabled-groups` non-empty and the groups claim contains none of them | `NOT_ENTITLED` | `403` | empty |
| Otherwise | `SUCCESS` | `200` | the permissions document, `Content-Type: application/json` |

Every response: `Cache-Control: no-store`, and `X-AMPS-Correlation-Id` when the request had one.
`401` is returned only for a missing token; a refused logon is always `403`. The token must never
appear in logs, responses, exception messages or metric tags.

Success document: served verbatim from `amps.permissions.template` (default
`classpath:amps/permissions-logon-only.json`, `{"logon": true, "replication-logon": false}`), loaded
once at startup; startup fails if missing or not a JSON object; WARN if `logon` is not `true`. The
README must carry the entitlement caveat (no `topic` list → no `<Entitlement>` reference) and the
consequence of `replication-logon: false`.

## 5. The UserInfo check

`GET amps.auth.userinfo.url` with `Authorization: Bearer <token>` and `Accept: application/json`,
connect/read timeouts from configuration, redirects never followed, TLS trust from the JVM
truststore. The principal claim (`amps.auth.userinfo.principal-claim`, default `sub`) is compared to
the path username case-insensitively; numeric claims are compared as strings. The groups claim
(`amps.auth.userinfo.groups-claim`) may be a JSON array of strings or one space/comma-separated
string; names are compared case-insensitively after trimming. Claims are looked up by exact name
first, then as a dotted path. Isolate the HTTP call behind a small interface (`UserInfoClient`) so the
check can be tested with a fake; test the JDK client itself against a local `HttpServer`.

## 6. Configuration

`@ConfigurationProperties(prefix = "amps")` records, `@Validated`:

```yaml
amps:
  auth:
    password-header: X-AMPS-Password
    userinfo:
      url: https://login.example.com/oauth2/userinfo   # required
      principal-claim: sub
      groups-claim: csgroups
      enabled-groups: []          # empty = no group check (WARN at startup)
      connect-timeout: 1000ms
      read-timeout: 2000ms
      health-indicator-enabled: true
  permissions:
    template: classpath:amps/permissions-logon-only.json
```

Startup fails on: blank URL, non-`http(s)` URL, blank header or claim names, non-positive timeouts,
bad template. `server.error.include-*` off; Tomcat 200 threads; actuator exposes `health,info,metrics`
with probes enabled and `show-details: never`; springdoc off by default; console log pattern renders
`corr=%X{ampsCorrelationId:-}`. The `local` profile enables Swagger and DEBUG and points the UserInfo
URL at `http://localhost:9999/userinfo` (a stub script lives in `local/`).

## 7. Code structure

```
src/main/java/com/example/AmpsAuthApplication.java      main()
src/main/java/com/example/OpenApiConfiguration.java     Swagger (apiKey-in-header security scheme), only when enabled
src/main/java/com/example/ampsauth/
  AmpsAuthConfiguration     @EnableConfigurationProperties + @ComponentScan; beans for document, client, authenticator, health
  AmpsProperties            records Auth(passwordHeader, UserInfo), Permissions(template)
  PermissionsController     the GET mapping; reads path + headers; maps LogonOutcome -> status
  LogonService              guards -> authenticator -> outcome; metrics; the one INFO line
  LogonOutcome              SUCCESS | NO_TOKEN | INVALID_TOKEN | PRINCIPAL_MISMATCH | NOT_ENTITLED | BACKEND_UNAVAILABLE
  UserInfoAuthenticator     the check in section 5
  UserInfoClient / JdkUserInfoClient / UserInfoProbe / UserInfoHealthIndicator
  CorrelationIdFilter, RequestMetadata, LogSanitizer, PermissionsDocument
```

## 8. Logging, metrics, health

One INFO line per attempt: `logon user=<path username> outcome=<outcome> client=… remote=… conn=… ms=…`,
all request-supplied values sanitised (control/whitespace/separator/`=` → `_`, truncated). ERROR with
the exception for `BACKEND_UNAVAILABLE`; WARN for `PRINCIPAL_MISMATCH`. Micrometer counter
`amps.logon.attempts` and timer `amps.logon.duration`, tagged `outcome` only, pre-registered for every
outcome. Liveness and readiness never depend on the identity provider; an optional `userInfo` health
component (unauthenticated GET, any HTTP answer = UP) contributes to `/actuator/health` only.

## 9. Tests (all must pass in `mvn verify`)

Unit: `UserInfoAuthenticatorTest` (fake client: every row of the table in section 4, claim lookup
variants, group formats, empty enabled-groups, token never logged, constructor validation);
`JdkUserInfoClientTest` (real client vs local server: bearer header, probe, timeouts, refused
connection, redirects not followed, URL validation); `LogonServiceTest` (guards, outcome→meter
mapping, one INFO line, exception → `BACKEND_UNAVAILABLE`); `PermissionsDocumentTest`;
`CorrelationIdFilterTest`; `LogSanitizerTest`; `UserInfoHealthIndicatorTest`;
`AmpsAuthConfigurationTest` (wiring, defaults, overrides, startup failures).

Integration (`@SpringBootTest` on a random port against a stub UserInfo `HttpServer` keyed by token):
`PermissionsEndpointIntegrationTest` (200 with the exact document and headers; the 401 challenge; every 403 and 503 row;
the `Authorization` header is ignored; only the path-variable route exists; actuator routes; metrics
tagged by outcome only; a custom header name), `TokenNeverLoggedIntegrationTest` (DEBUG on: no token
in the output, one INFO line per outcome, forged log tokens neutralised), `OpenApiIntegrationTest`
(Swagger absent by default; when enabled the document declares the header as an apiKey scheme).

Manual smoke test with the `local` profile and `local/stub-userinfo.py`: see README section 2.

## 10. AMPS configuration (README section 9)

```xml
<Module>
  <Name>web-auth</Name>
  <Library>libamps_http_entitlement.so</Library>
  <Options>
    <ResourceURI>https://amps-auth.example.com:8443/amps/v1/permissions/{{USER_NAME}}</ResourceURI>
    <HTTPHeader>X-AMPS-Password: {{AMPS_PASSWORD}}</HTTPHeader>
    <HTTPHeader>X-AMPS-Client-Name: {{AMPS_CLIENT_NAME}}</HTTPHeader>
    <HTTPHeader>X-AMPS-Remote-Address: {{AMPS_REMOTE_ADDRESS}}</HTTPHeader>
    <HTTPHeader>X-AMPS-Correlation-Id: {{AMPS_CORRELATION_ID}}</HTTPHeader>
    <HTTPHeader>X-AMPS-Connection-Name: {{AMPS_CONNECTION_NAME}}</HTTPHeader>
    <ReuseConnections>enabled</ReuseConnections>
    <ConnectionTimeout>1000</ConnectionTimeout>
    <RequestTimeout>4000</RequestTimeout>
    <CAKey>/etc/amps/security/ca.pem</CAKey>
  </Options>
</Module>
<Authentication><Module>web-auth</Module></Authentication>
```

`RequestTimeout` must exceed `connect-timeout + read-timeout`. No `<Entitlement>` reference, no
`<EntitlementOnly/>`, `RetryCount` 0, `ServerAcceptsEmptyAuthId` false.

## 11. Definition of done

- [ ] `mvn verify` passes with the tests in section 9.
- [ ] With the `local` profile and the stub, the smoke-test matrix in README section 2 produces exactly
      the listed status codes.
- [ ] No token appears in any log output (verified by test).
- [ ] README covers: the flow, endpoints and response table, every `amps.*` property, the UserInfo
      check and the expected JSON shape, running locally, TLS, the AMPS configuration block with the
      points to check, the entitlement caveat, troubleshooting.

## 12. Do not

- Do not add `spring-boot-starter-security`, a database, sessions, or local JWT validation.
- Do not return `401` for a refused logon — it must be `403`.
- Do not log or echo the token or the password header.
- Do not trim or alter the token; do not put the username in metric tags.
- Do not make the principal-claim check optional.
- Do not change the response contract or endpoint path without updating README sections 3 and 9.
- Do not skip or weaken tests to make the build pass.
