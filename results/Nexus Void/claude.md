# Security Audit Report — Nexus_Void (ASP.NET Core 7.0)

---

## [CRITICAL] — Pre-Authentication Remote Code Execution via JWT Auth Bypass + SQL Injection into Wishlist Data + Insecure Deserialization (TypeNameHandling.All)

**OWASP Category:** A03:2021 – Injection / A08:2021 – Software and Data Integrity Failures **CWE ID:** CWE-502 (Deserialization of Untrusted Data) + CWE-89 (SQL Injection) + CWE-287 (Improper Authentication)

**Location (Step 1 — Auth Bypass):** [Nexus_Void/Middleware/JWTMiddleware.cs](/Middleware/JWTMiddleware.cs) lines 17–46

**Vulnerable Code (Step 1):**

```csharp
if (string.IsNullOrEmpty(jwtToken))
{
    context.Response.Redirect("/");
    // NO return — execution falls through
}
...
if (validateToken.Equals("false"))
{
    context.Response.Redirect("/");
    // NO return — execution falls through
}
...
if(string.IsNullOrEmpty(username))
{
    context.Response.Redirect("/");
    // NO return — execution falls through
}

context.Items["username"] = username;
context.Items["ID"] = ID;

await _next(context);   // ALWAYS reached regardless of all three guard conditions
```

**Location (Step 2 — Unsigned Claim Injection):** [Nexus_Void/Helpers/JWTHelper.cs](/Helpers/JWTHelper.cs) lines 70–83

**Vulnerable Code (Step 2):**

```csharp
public string getClaims(string token, string claimType)
{
    var tokenHandler = new JwtSecurityTokenHandler();
    try
    {
        var securityToken = tokenHandler.ReadToken(token) as JwtSecurityToken; // NO signature validation
        var stringClaimValue = securityToken.Claims.First(Claim => Claim.Type == claimType).Value;
        return stringClaimValue;
    }
    ...
}
```

**Location (Step 3 — SQL Injection via Forged JWT Claim):** [Nexus_Void/Controllers/HomeController.cs](/Controllers/HomeController.cs) lines 93–103

**Vulnerable Code (Step 3):**

```csharp
string username = HttpContext.Items["username"].ToString();
...
string sqlQueryAddWishlist = $"INSERT INTO Wishlist(ID, username, data) VALUES({ID},'{username}', '{serializedData}')";
_db.Database.ExecuteSqlRaw(sqlQueryAddWishlist);
```

**Location (Step 4 — Insecure Deserialization):** [Nexus_Void/Helpers/SerializeHelper.cs](/Helpers/SerializeHelper.cs) lines 19–31

**Vulnerable Code (Step 4):**

```csharp
public static List<ProductModel> Deserialize(string str)
{
    string decodedData = EncodeHelper.Decode(str);  // Base64 decode only
    var deserialized = JsonConvert.DeserializeObject(decodedData, new JsonSerializerSettings
    {
        TypeNameHandling = TypeNameHandling.All  // Instantiates ANY .NET type named in $type
    });
    ...
}
```

**Source of Input:** Attacker-crafted HTTP cookie `Token` (unsigned JWT); attacker-controlled POST body `name` + `sellerName`.

**Sink:** `JsonConvert.DeserializeObject()` with `TypeNameHandling.All` consuming a Base64 payload that was written into `Wishlist.data` via SQL injection derived from a forged JWT claim.

**Data Flow Explanation:**

The attack is four-stage, each stage directly evidenced in source:

**Stage 1 — Authentication bypass:** `JWTMiddleware.InvokeAsync()` calls `context.Response.Redirect("/")` at three guard points (missing token, invalid signature, missing username) but never calls `return`. Execution always reaches `await _next(context)`, which forwards the request to the controller. The redirect response header is set on the response object but headers are not flushed until the controller writes its body.

**Stage 2 — Unsigned claim injection:** After `ValidateToken()` rejects the forged JWT (returns `"false"`), `getClaims()` is called with the same token using `tokenHandler.ReadToken(token)`. `ReadToken` is the non-validating reader — it parses the Base64-encoded JWT payload without cryptographic signature verification. The attacker's claim values are extracted verbatim and stored in `context.Items["username"]` and `context.Items["ID"]`.

**Stage 3 — SQL injection via forged `username` claim:** In `HomeController.Wishlist()` POST path (line 93–103), when no wishlist row exists for the user, the code executes the INSERT branch. The string `username` (sourced directly from `context.Items["username"]`, which is the forged claim) is interpolated unescaped into the raw SQL string. An attacker-controlled `username` value of `x', 'ATTACKER_PAYLOAD')--` produces:

```sql
INSERT INTO Wishlist(ID, username, data) VALUES(1,'x', 'ATTACKER_PAYLOAD')--', '...')
```

The `--` comments out the remainder. SQLite executes a valid three-column INSERT with `data = 'ATTACKER_PAYLOAD'` — an attacker-controlled Base64 string stored verbatim in `Wishlist.data`.

**Stage 4 — Deserialization to RCE:** On subsequent `GET /home/wishlist` (same forged JWT, same bypass), the row is fetched and `SerializeHelper.Deserialize()` is called. `EncodeHelper.Decode()` Base64-decodes the attacker's payload, then `JsonConvert.DeserializeObject()` with `TypeNameHandling.All` processes it. With `TypeNameHandling.All`, Newtonsoft.Json reads the `$type` field and instantiates the named .NET type via reflection. The attacker controls the entire JSON structure including `$type`, enabling .NET gadget chain execution.

**Supporting evidence — `EnableUnsafeBinaryFormatterSerialization`:** [Nexus_Void/Nexus_Void.csproj](/Nexus_Void.csproj) line 7:

```xml
<EnableUnsafeBinaryFormatterSerialization>true</EnableUnsafeBinaryFormatterSerialization>
```

This explicitly enables unsafe binary deserialization, widening the available gadget surface beyond what is available by default in .NET 7.

**Supporting evidence — execution context:** [config/supervisord.conf](/config/supervisord.conf) lines 1–2:

```ini
[supervisord]
user=root
```

The dotnet process runs as root. Code execution via gadget chain executes with root privileges.

**Supporting evidence — flag path:** [Dockerfile](/Dockerfile) line 33:

```dockerfile
COPY flag.txt /flag.txt
```

The file `/flag.txt` is explicitly placed at a known path, reachable by any shell command executing as root.

**Impact:** Unauthenticated, pre-authentication remote code execution as root. Full container compromise. Readable: `/flag.txt` (explicitly placed at this path per Dockerfile:33). No credentials, no prior knowledge of valid user accounts required.

**Exploitation Scenario:**

1. Craft a JWT payload: `{"username":"x', 'ATTACKER_B64')--","ID":"1","iss":"NexusVoid","exp":9999999999}`. Sign with any key (signature is irrelevant — it will fail validation but execution continues).
2. Send `GET /home/` with forged `Token` cookie to enumerate a valid product `name`+`sellerName` (the middleware bypass allows unauthenticated product listing).
3. Send `POST /home/wishlist` with forged cookie, `name=<valid_product>&sellerName=<valid_seller>`. The forged `username` claim is injected into the Wishlist INSERT SQL, writing the attacker's Base64 payload as `data` for ID=1.
4. Send `GET /home/wishlist` with forged cookie. Server deserializes attacker's JSON with `TypeNameHandling.All`. Gadget chain triggers command execution as root.

**Confidence Level:** HIGH — every link in the chain is directly evidenced by the provided source code. No external assumptions required.

---

## [CRITICAL] — SQL Injection Authentication Bypass (Login)

**OWASP Category:** A03:2021 – Injection **CWE ID:** CWE-89 (Improper Neutralization of Special Elements used in an SQL Command)

**Location:** [Nexus_Void/Controllers/LoginController.cs](/Controllers/LoginController.cs) line 33

**Vulnerable Code:**

```csharp
string sqlQuery = $"SELECT * FROM Users WHERE username='{userModel.username}' AND password='{userModel.password}'";
var result = _db.Users.FromSqlRaw(sqlQuery).FirstOrDefault();
if (result != null)
{
    // JWT issued
}
```

**Source of Input:** HTTP POST form fields `username` and `password` from the login form.

**Sink:** `_db.Users.FromSqlRaw(sqlQuery)` — raw SQL executed against SQLite.

**Data Flow Explanation:** `userModel.username` and `userModel.password` are bound directly from HTTP POST body parameters by the ASP.NET Core model binder. Both values are interpolated verbatim into the SQL string with no sanitization, parameterization, or escaping. The result object is checked for null to grant a JWT.

Payload `username = x' OR '1'='1'--` produces:

```sql
SELECT * FROM Users WHERE username='x' OR '1'='1'--' AND password='...'
```

The `OR '1'='1'` predicate is always true; `--` comments out the password check. `FirstOrDefault()` returns the first row in the Users table, and a JWT is issued for that account.

**Impact:** Full authentication bypass. Attacker receives a valid, server-signed JWT for any existing account with no knowledge of credentials. Grants access to all authenticated endpoints.

**Exploitation Scenario:** Submit `POST /` with `username=x' OR '1'='1'--` and any password value.

**Confidence Level:** HIGH

---

## [CRITICAL] — SQL Injection via Registration Endpoint (INSERT)

**OWASP Category:** A03:2021 – Injection **CWE ID:** CWE-89

**Location:** [Nexus_Void/Controllers/LoginController.cs](/Controllers/LoginController.cs) lines 69–75

**Vulnerable Code:**

```csharp
string checkUserSqlQuery = $"SELECT * FROM Users WHERE username='{userModel.username}'";
var result = _db.Users.FromSqlRaw(checkUserSqlQuery).FirstOrDefault();

if (result == null)
{
    string sqlQuery = $"INSERT INTO Users(username, password) VALUES('{userModel.username}','{userModel.password}')";
    _db.Database.ExecuteSqlRaw(sqlQuery);
}
```

**Source of Input:** HTTP POST form fields `username` and `password` from the registration form.

**Sink:** `_db.Users.FromSqlRaw()` (line 70) and `_db.Database.ExecuteSqlRaw()` (line 75).

**Data Flow Explanation:** Both the existence check SELECT and the INSERT are raw string-interpolated SQL. The `checkUserSqlQuery` at line 69 uses `username` to check for existing users; this query is injectable to force a false-no-user result, allowing the INSERT to proceed. The INSERT at line 74 concatenates both `username` and `password` directly. This allows injection into the Users table data values.

**Impact:** Injection into the registration flow. Can force registration of arbitrary usernames. Injection in the INSERT allows writing arbitrary values as username/password, enabling second-order SQL manipulation. Plaintext passwords confirm data is stored as-is.

**Exploitation Scenario:** `username = x' AND '1'='2` (forces check to return null), then registration proceeds. The INSERT also accepts injection via `password` field.

**Confidence Level:** HIGH

---

## [CRITICAL] — SQL Injection in Authenticated Wishlist and Settings Endpoints (Multiple DML Sinks)

**OWASP Category:** A03:2021 – Injection **CWE ID:** CWE-89

**Location:** [Nexus_Void/Controllers/HomeController.cs](/Controllers/HomeController.cs) lines 63, 66, 86, 101, 128, 144,

API Error: Claude's response exceeded the 32000 output token maximum. To configure this behavior, set the CLAUDE_CODE_MAX_OUTPUT_TOKENS environment variable.

Continuing the security audit report from the cut-off point.

---

## [CRITICAL] — SQL Injection in Authenticated Wishlist and Settings Endpoints (Multiple DML Sinks)

**OWASP Category:** A03:2021 – Injection **CWE ID:** CWE-89

**Location:** [Nexus_Void/Controllers/HomeController.cs](/Controllers/HomeController.cs) lines 63, 66, 86, 101, 128, 144, 155

**Vulnerable Code:**

```csharp
// HomeController.cs:63 — Wishlist GET (ID from JWT, no quotes)
string sqlQueryGetWishlist = $"SELECT * from Wishlist WHERE ID='{ID}'";

// HomeController.cs:66 — Wishlist POST (user-supplied form fields)
string sqlQueryProduct = $"SELECT * from Products WHERE name='{name}' AND sellerName='{sellerName}'";

// HomeController.cs:86 — Wishlist UPDATE
string sqlQueryAddWishlist = $"UPDATE Wishlist SET data='{serializedData}' WHERE ID={ID}";

// HomeController.cs:101 — Wishlist INSERT (username from JWT claim, already detailed in Chain finding)
string sqlQueryAddWishlist = $"INSERT INTO Wishlist(ID, username, data) VALUES({ID},'{username}', '{serializedData}')";

// HomeController.cs:128 — Setting POST (user.username from HTTP POST body)
string sqlQuery = $"UPDATE Users SET username='{user.username}' WHERE ID={ID}";

// HomeController.cs:144 — WishlistRemove GET
string sqlQueryGetWishlist = $"SELECT * from Wishlist WHERE ID='{ID}'";

// HomeController.cs:155 — WishlistRemove UPDATE
string sqlQueryAddWishlist = $"UPDATE Wishlist SET data='{serializedData}' WHERE ID='{ID}'";
```

**Source of Input:**

- Lines 66: HTTP POST body fields `name` and `sellerName` — fully attacker-controlled.
- Line 128: HTTP POST body field `user.username` — attacker-controlled.
- Lines 63, 86, 101, 144, 155: `ID` and `username` from `HttpContext.Items`, which are sourced from JWT claims. Via the auth bypass (Finding #1), these can be attacker-controlled without a valid signature.

**Sink:** All calls to `_db.Products.FromSqlRaw()`, `_db.Wishlist.FromSqlRaw()`, and `_db.Database.ExecuteSqlRaw()` — all executing raw SQL with no parameterization.

**Data Flow Explanation:**

At line 66, `name` and `sellerName` come directly from the HTTP POST form body bound by ASP.NET Core model binding. Both are interpolated into a SELECT query against the Products table. A UNION SELECT injection on `name` can return an attacker-fabricated `ProductModel` row:

```
name = anything' UNION SELECT 1,'injected_name','img','bid','end','seller','back' --
```

This fake product row passes the `if(!string.IsNullOrEmpty(product.name))` guard at line 69, gets added to the wishlist list, and is serialized by `SerializeHelper.Serialize()`. The serialized Base64 value is then written to `Wishlist.data` via the UPDATE at line 86. Note: the serialized Base64 string contains only characters `[A-Za-z0-9+/=]` and cannot itself inject SQL; however the product field values influence the deserialized object graph.

At line 128, `user.username` from HTTP POST is interpolated into a DML UPDATE. An attacker-controlled username with a single quote breaks the statement. However because `ExecuteSqlRaw` is called AFTER `GenerateJwtToken` but BEFORE `Response.Cookies.Append`, a malformed SQL that throws an exception prevents the new JWT from being issued. This limits the direct impact of Setting SQLi to a DoS on the profile update rather than a full data exfiltration pivot. The UNION SELECT path at line 66 remains the more reliable DML-adjacent injection.

**Impact:** UNION SELECT injection on `name`/`sellerName` (line 66) allows data exfiltration from any table accessible to the SQLite connection (schema enumeration, Users table read, password exfiltration). The UPDATE at line 128 is injectable but the exception path prevents reliable exploitation for further pivoting without the auth bypass chain.

**Exploitation Scenario:** Authenticated user (or using the auth bypass) sends `POST /home/wishlist` with `name=x' UNION SELECT 1,(SELECT password FROM Users WHERE username='admin'),1,1,1,1,1 --&sellerName=x`. The product check at line 69 passes (product.name = admin's password). The exfiltrated value is stored in the wishlist and can be read back via `GET /home/wishlist`.

**Confidence Level:** HIGH

---

## [HIGH] — JWT Middleware Authentication Bypass via Non-Blocking Redirect

**OWASP Category:** A07:2021 – Identification and Authentication Failures **CWE ID:** CWE-287 (Improper Authentication)

**Location:** [Nexus_Void/Middleware/JWTMiddleware.cs](/Middleware/JWTMiddleware.cs) lines 17–46

**Vulnerable Code:**

```csharp
public async Task InvokeAsync(HttpContext context)
{
    string jwtToken = context.Request.Cookies["Token"];

    if (string.IsNullOrEmpty(jwtToken))
    {
        context.Response.Redirect("/");
        // Missing: return — execution continues
    }

    JWTHelper _jwtHelper = new JWTHelper(_configuration);
    string validateToken = _jwtHelper.ValidateToken(jwtToken);

    if (validateToken.Equals("false"))
    {
        context.Response.Redirect("/");
        // Missing: return — execution continues
    }

    string username = _jwtHelper.getClaims(jwtToken, "username");
    string ID = _jwtHelper.getClaims(jwtToken, "ID");

    if(string.IsNullOrEmpty(username))
    {
        context.Response.Redirect("/");
        // Missing: return — execution continues
    }

    context.Items["username"] = username;
    context.Items["ID"] = ID;

    await _next(context);  // Reached unconditionally
}
```

**Source of Input:** HTTP cookie `Token` (or its absence).

**Sink:** `await _next(context)` — forwards the request to `HomeController` action methods that access `context.Items["username"]` and `context.Items["ID"]`.

**Data Flow Explanation:** ASP.NET Core's `HttpResponse.Redirect()` sets `Response.StatusCode = 302` and adds the `Location` header but does NOT flush headers or stop pipeline execution. Without a `return` statement, all three guard conditions fall through. The middleware always calls `await _next(context)`. When no JWT is present, `ValidateToken(null)` throws an exception caught internally returning `"false"`, and `getClaims(null, ...)` throws and returns `""`. The result: `context.Items["username"] = ""` and `context.Items["ID"] = ""`. The controller executes. HTTP clients not following redirects automatically (e.g., `curl` without `-L`, Python `requests` without `allow_redirects=True`) receive the response body of the protected controller action, bypassing authentication entirely.

This finding is the enabling primitive for the pre-auth RCE chain described in Finding #1: an unsigned JWT's claims are extracted by `getClaims()` (which calls `ReadToken()` without signature verification) and placed into `context.Items` before the controller runs.

**Impact:** Unauthenticated access to all routes under `/home/` and `/Home/` for non-browser HTTP clients. Used as the enabling layer for the full pre-auth RCE chain. Also exposes product data, wishlist data, and user profile to unauthenticated callers.

**Exploitation Scenario:** `curl http://target/home/` with no `Token` cookie returns the product index page. The 302 redirect header is present in the response but the controller's HTML body is also included and readable.

**Confidence Level:** HIGH

---

## [HIGH] — Plaintext Password Storage and Comparison

**OWASP Category:** A02:2021 – Cryptographic Failures **CWE ID:** CWE-256 (Plaintext Storage of a Password)

**Location:** [Nexus_Void/Controllers/LoginController.cs](/Controllers/LoginController.cs) lines 33 and 74

**Vulnerable Code:**

```csharp
// Login — password compared as plaintext
string sqlQuery = $"SELECT * FROM Users WHERE username='{userModel.username}' AND password='{userModel.password}'";

// Registration — password stored as plaintext
string sqlQuery = $"INSERT INTO Users(username, password) VALUES('{userModel.username}','{userModel.password}')";
```

**Source of Input:** HTTP POST body fields `username` and `password`.

**Sink:** SQLite Users table. The `password` column (defined in [Nexus_Void/Models/UserModel.cs](/Models/UserModel.cs)) stores the raw string. No hashing function is called at any point in the registration or login flow.

**Data Flow Explanation:** `userModel.password` is model-bound from the HTTP POST body and written directly into the INSERT SQL without any transformation. At login, the stored password is compared as a plain string in the WHERE clause. No hashing, no salting, no key derivation function is applied anywhere in the codebase. Any attacker who reads the Users table (possible via the SQL injection vulnerabilities above) obtains cleartext credentials immediately.

**Impact:** Complete credential compromise upon any SQL injection that reads the Users table. Credentials may be reused against other services. The UNION SELECT injection demonstrated in Finding #4 can directly exfiltrate cleartext passwords.

**Exploitation Scenario:** Via the UNION SELECT on `name`/`sellerName` at `HomeController.cs:66`: `name=x' UNION SELECT 1,(SELECT password FROM Users LIMIT 1),1,1,1,1,1 --&sellerName=x` — the raw password is returned as the product name in the wishlist view.

**Confidence Level:** HIGH

---

## [HIGH] — Unauthenticated Shell Command Execution Infrastructure with World-Writable Script Paths

**OWASP Category:** A05:2021 – Security Misconfiguration **CWE ID:** CWE-78 (OS Command Injection) / CWE-732 (Incorrect Permission Assignment for Critical Resource)

**Location:** [Nexus_Void/Controllers/HomeController.cs](/Controllers/HomeController.cs) lines 170–202; [Nexus_Void/Helpers/StatusCheckHelper.cs](/Helpers/StatusCheckHelper.cs) lines 20–35; [Dockerfile](/Dockerfile) lines 29–31

**Vulnerable Code:**

```csharp
// HomeController.cs:193-199 — Unauthenticated /status endpoint executes scripts from /tmp
statusCheckHelper.command = "bash /tmp/cpu.sh";
string cpuUsage = statusCheckHelper.output;

statusCheckHelper.command = "bash /tmp/mem.sh";
string memoryUsage = statusCheckHelper.output;

statusCheckHelper.command = "bash /tmp/disk.sh";
string diskUsage = statusCheckHelper.output;
```

```csharp
// StatusCheckHelper.cs:22-35 — command executed via bash -c
var processStartInfo = new ProcessStartInfo()
{
    FileName = $"/bin/bash",
    WorkingDirectory = "/tmp",
    Arguments = $"-c \"{_command}\"",
    RedirectStandardOutput = true,
    RedirectStandardError = true,
    UseShellExecute = false
};
p.StartInfo = processStartInfo;
p.Start();
output = p.StandardOutput.ReadToEnd();
```

```dockerfile
# Dockerfile:29-31 — scripts written to world-writable /tmp
RUN echo "top -bn1 | grep 'Cpu(s)' | awk '{print \$2 + \$4}' | tr -d '\\n'" > /tmp/cpu.sh
RUN echo "free -m | awk 'NR==2{printf \"%sMB\", \$3}'" > /tmp/mem.sh
RUN echo "df -h | awk '\$NF==\"/\"{printf \"%d/%dGB (%s)\", \$3, \$2, \$5}'" > /tmp/disk.sh
```

**Source of Input:** The `command` values are hardcoded in the controller and are not directly user-controlled. The **input vector** is the filesystem: `/tmp/cpu.sh`, `/tmp/mem.sh`, `/tmp/disk.sh` are located in a world-writable directory.

**Sink:** `Process.Start()` with `FileName = "/bin/bash"` and `Arguments = $"-c \"{_command}\""` at `StatusCheckHelper.cs:33`.

**Data Flow Explanation:** The `/status` and `/uptime` routes are defined with `[Route("/status")]` and `[Route("/uptime")]` attributes (HomeController.cs:170, 187). These routes are not under `/home/` or `/Home/`, so the JWT middleware at [Program.cs](/Program.cs) line 32 (`context.Request.Path.StartsWithSegments("/home")`) does NOT protect them. They are fully unauthenticated.

The `StatusCheckHelper` pattern — where setting the `command` property executes it immediately via `Process.Start()` — establishes a shell execution primitive. The commands executed are `bash /tmp/cpu.sh`, `bash /tmp/mem.sh`, `bash /tmp/disk.sh`. These script files reside in `/tmp/`, which is world-writable by convention on Linux. If an attacker achieves any file-write primitive (e.g., via the deserialization RCE chain in Finding #1), they can overwrite `/tmp/cpu.sh` with arbitrary shell commands. Subsequently, any unauthenticated HTTP request to `GET /status` triggers execution of those commands and returns stdout to the attacker.

This forms a **persistence and exfiltration mechanism**: after initial compromise, overwriting `/tmp/cpu.sh` allows repeated unauthenticated command execution via a publicly accessible endpoint.

**Impact:** Post-RCE persistence vector. After initial code execution via the deserialization chain, an attacker can install a persistent command execution backdoor requiring only unauthenticated GET requests to `/status`. Additionally, system information (uptime, CPU load, memory, disk) is disclosed to unauthenticated callers.

**Exploitation Scenario (two-stage):** (1) Via deserialization RCE: write `cat /flag.txt` to `/tmp/cpu.sh`. (2) `GET /status` returns flag content in the `CPU Usage:` field, unauthenticated.

**Confidence Level:** HIGH (hardcoded commands are not directly injectable; the risk is the architecture combined with world-writable script paths and unauthenticated endpoint access)

---

## [MEDIUM] — Missing CSRF Protection on All State-Mutating Endpoints

**OWASP Category:** A01:2021 – Broken Access Control **CWE ID:** CWE-352 (Cross-Site Request Forgery)

**Location:** [Nexus_Void/Controllers/HomeController.cs](/Controllers/HomeController.cs) lines 58, 120, 139; [Nexus_Void/Controllers/LoginController.cs](/Controllers/LoginController.cs) line 59; [Nexus_Void/Program.cs](/Program.cs) lines 9–13

**Vulnerable Code:**

```csharp
// Program.cs — no anti-forgery services registered
builder.Services.AddControllersWithViews();
// No: builder.Services.AddAntiforgery()
// No [ValidateAntiForgeryToken] on any POST action

// HomeController.cs — POST actions with no CSRF protection
[HttpPost]
public IActionResult Wishlist(string name, string sellerName) { ... }

[HttpPost]
public IActionResult Setting(UserModel user) { ... }

[HttpPost]
public IActionResult WishlistRemove(string name, string sellerName) { ... }
```

**Source of Input:** Cross-origin HTTP POST requests initiated by an attacker-controlled page visited by an authenticated user.

**Sink:** All three HomeController POST endpoints and `LoginController.Create` POST endpoint. Each mutates application state (adds/removes wishlist items, updates username) using cookie-based JWT authentication.

**Data Flow Explanation:** The application uses cookie-based authentication (`Response.Cookies.Append("Token", jwtToken)` at LoginController.cs:43). Browsers automatically attach cookies to same-origin and cross-origin requests by default (absent `SameSite=Strict`). No anti-forgery token is generated or validated anywhere in the application. `Program.cs` never calls `AddAntiforgery()` or `ValidateAntiForgeryToken`. An attacker who lures an authenticated user to a malicious page can issue cross-origin POST requests that the server treats as legitimate.

The cookie set at `Response.Cookies.Append("Token", jwtToken)` does not specify `SameSite` or `HttpOnly` attributes (no options passed), defaulting to browser-dependent behavior.

**Impact:** An authenticated user visiting a malicious page can have their wishlist modified or their username changed without their knowledge. Username change resets their JWT identity. Combined with the SQL injection at line 128, CSRF-triggered username change could be chained.

**Confidence Level:** MEDIUM (requires attacker to lure an authenticated user to a malicious page; impact is limited to wishlist/profile manipulation for the victim's own account)

---

## [MEDIUM] — Second-Order SQL Injection via Product Data in Wishlist Serialization

**OWASP Category:** A03:2021 – Injection **CWE ID:** CWE-89

**Location:** [Nexus_Void/Controllers/HomeController.cs](/Controllers/HomeController.cs) lines 66–88

**Vulnerable Code:**

```csharp
// User controls name and sellerName via POST
string sqlQueryProduct = $"SELECT * from Products WHERE name='{name}' AND sellerName='{sellerName}'";
var product = _db.Products.FromSqlRaw(sqlQueryProduct).FirstOrDefault();

if(!string.IsNullOrEmpty(product.name))
{
    ...
    products.Add(product);  // fake product from UNION SELECT added
    string serializedData = SerializeHelper.Serialize(products);

    string sqlQueryAddWishlist = $"UPDATE Wishlist SET data='{serializedData}' WHERE ID={ID}";
    _db.Database.ExecuteSqlRaw(sqlQueryAddWishlist);  // Serialized data written
}
```

**Source of Input:** HTTP POST body fields `name` and `sellerName`.

**Sink:** `_db.Products.FromSqlRaw()` at line 67 — injection in SELECT. Secondarily, the resulting `ProductModel` data flows into serialization and then into the UPDATE at line 86 (though Base64 encoding of serialized data prevents SQL injection in the UPDATE sink itself).

**Data Flow Explanation:** `name` and `sellerName` are injected into a raw SQL SELECT. A UNION SELECT injection returns an attacker-fabricated `ProductModel` with arbitrary field values. This fake product is added to `products` (line 82), serialized by `SerializeHelper.Serialize()` (line 84), and the result stored in `Wishlist.data` (line 88). The data flow is: HTTP POST body → SQL injection → attacker-controlled product row → wishlist serialized data. This is second-order because the injected data is processed through serialization before storage, and the SQL injection in the storage UPDATE (line 86) is not directly reachable due to Base64 encoding.

**Impact:** Data exfiltration from any table reachable by the SQLite connection (schema, Users, Products, Wishlist tables). The injected fake product's field values are stored and reflected back on wishlist view.

**Confidence Level:** HIGH

---

## [LOW] — Container Process Executes as Root

**OWASP Category:** A05:2021 – Security Misconfiguration **CWE ID:** CWE-250 (Execution with Unnecessary Privileges)

**Location:** [config/supervisord.conf](/config/supervisord.conf) line 2

**Vulnerable Code:**

```ini
[supervisord]
user=root
```

**Source of Input:** Container startup configuration.

**Sink:** All processes managed by supervisord, including the dotnet application process (`dotnet Nexus_Void.dll`).

**Data Flow Explanation:** The supervisord daemon starts with `user=root`. The managed `[program:dotnet]` program inherits this user context. Any code execution achieved within the dotnet process (e.g., via the deserialization RCE chain in Finding #1) runs as root inside the container. No non-root user or privilege drop is configured anywhere in the Dockerfile or supervisord configuration.

**Impact:** Any achieved RCE (from Finding #1) operates with root privileges, providing unrestricted access to the container filesystem, including `/flag.txt` (Dockerfile:33: `COPY flag.txt /flag.txt`).

**Confidence Level:** HIGH (directly observable from supervisord.conf:2)

---

## [LOW] — JWT Audience Validation Disabled

**OWASP Category:** A02:2021 – Cryptographic Failures **CWE ID:** CWE-347 (Improper Verification of Cryptographic Signature)

**Location:** [Nexus_Void/Helpers/JWTHelper.cs](/Helpers/JWTHelper.cs) line 55

**Vulnerable Code:**

```csharp
tokenHandler.ValidateToken(token, new TokenValidationParameters
{
    ValidateIssuerSigningKey = true,
    ValidateIssuer = true,
    ValidateAudience = false,   // Audience check disabled
    ValidIssuer = Issuer,
    IssuerSigningKey = securityKey
}, out SecurityToken validatedToken);
```

**Source of Input:** JWT cookie `Token`.

**Sink:** Token validation logic; if audience validation were enabled, it would reject tokens not intended for this application.

**Data Flow Explanation:** `ValidateAudience = false` means any JWT issued by `NexusVoid` issuer, regardless of intended audience, is accepted. If another service in the same ecosystem uses the same JWT secret and issuer but for a different audience, tokens from that service would be accepted by this application.

**Impact:** Low in isolation (requires another service with the same secret). Documents an incomplete security control that reduces defense in depth.

**Confidence Level:** MEDIUM (exploitability depends on external environment not visible in source)

---

## [LOW] — AllowedHosts Wildcard Configuration

**OWASP Category:** A05:2021 – Security Misconfiguration **CWE ID:** CWE-16 (Configuration)

**Location:** [Nexus_Void/appsettings.json](/appsettings.json) line 11

**Vulnerable Code:**

```json
"AllowedHosts": "*"
```

**Data Flow Explanation:** ASP.NET Core's host filtering middleware uses `AllowedHosts` to restrict which `Host` header values are accepted. A wildcard accepts any `Host` header value, potentially enabling Host Header Injection attacks if any component of the application constructs URLs using `HttpContext.Request.Host` (not observed in the provided code, but the permissive configuration removes a defense-in-depth control).

**Impact:** Low in isolation. Removes host header filtering protection.

**Confidence Level:** LOW

---

## [LOW] — Sensitive System Information Disclosure via Unauthenticated Endpoints

**OWASP Category:** A05:2021 – Security Misconfiguration **CWE ID:** CWE-200 (Exposure of Sensitive Information to an Unauthorized Actor)

**Location:** [Nexus_Void/Controllers/HomeController.cs](/Controllers/HomeController.cs) lines 170–202

**Vulnerable Code:**

```csharp
[Route("/uptime")]
[HttpGet]
public IActionResult Uptime()
{
    StatusCheckHelper statusCheckHelper = new StatusCheckHelper();
    statusCheckHelper.command = "uptime";
    return Content(statusCheckHelper.output);
}

[Route("/status")]
[HttpGet]
public IActionResult Status()
{
    ...
    return Content($"CPU Usage: {cpuUsage}\nMemory Usage: {memoryUsage}\nDisk Space: {diskUsage}");
}
```

**Data Flow Explanation:** Both `/uptime` and `/status` routes are not under `/home/` or `/Home/`, so `JWTMiddleware` is not applied (Program.cs:32). These endpoints are fully unauthenticated. They expose system runtime metrics (CPU load, memory used, disk usage, uptime) to any caller, aiding attacker reconnaissance.

**Impact:** Unauthenticated disclosure of system resource metrics. Informs attacker about system state, which may assist in timing attacks or resource enumeration.

**Confidence Level:** HIGH

---

# Executive Summary

```
Total Critical:  4
Total High:      3
Total Medium:    2
Total Low:       4
```

**Primary Risk Theme:** The application is built on a systematic failure to separate untrusted input from code-level execution paths. Every user-facing parameter flows directly into raw SQL string interpolation. The serialization layer uses `TypeNameHandling.All` — the most dangerous Newtonsoft.Json setting. The authentication middleware fails open due to missing `return` statements. These three design decisions converge into a single pre-authentication RCE chain requiring no credentials and no prior knowledge of the application state.

**Most Dangerous Exploitable Path:**

> **Pre-Auth RCE Chain (no credentials required):**
> 
> 1. Craft an unsigned JWT with `username = "x', '<MALICIOUS_BASE64>')--"` and `ID = "1"`.
> 2. `GET /home/` with forged cookie — JWT middleware validates (fails), calls Redirect (no `return`), `getClaims()` reads claims via `ReadToken()` (no signature check), controller executes, product list returned.
> 3. `POST /home/wishlist` with forged cookie + a valid product name+seller — middleware bypass repeats; forged `username` claim injected into the Wishlist INSERT SQL; attacker-controlled Base64 written as `Wishlist.data` for ID=1.
> 4. `GET /home/wishlist` with forged cookie — wishlist row fetched; `SerializeHelper.Deserialize()` Base64-decodes and passes to `JsonConvert.DeserializeObject()` with `TypeNameHandling.All`; gadget chain executes as root.
> 
> **Evidence anchors:** JWTMiddleware.cs:17–46 (bypass), JWTHelper.cs:71 (`ReadToken` no-sig), HomeController.cs:101 (username SQL injection), SerializeHelper.cs:23–25 (TypeNameHandling.All), Nexus_Void.csproj:7 (EnableUnsafeBinaryFormatterSerialization), supervisord.conf:2 (root), Dockerfile:33 (`/flag.txt`).

**Likelihood of RCE:** **HIGH**. The chain is fully derivable from provided source with no external environment assumptions (aside from the Newtonsoft.Json runtime having reachable gadget types, which is implicit from `TypeNameHandling.All` usage combined with `EnableUnsafeBinaryFormatterSerialization=true`). Every link in the chain is directly observable in provided files.

**Overall Security Posture:** **Critical — Exploitable Pre-Authentication RCE with root privilege.** The application has no safe input handling, no cryptographic integrity on the deserialization path, a non-functional authentication middleware, and runs as root. There is no defense-in-depth at any layer. All four CRITICAL findings are independently exploitable; their convergence into a single unauthenticated RCE chain elevates the overall risk to maximum.

Which sources of information did you use?

Exclusively the source code files provided in the repository at the path you opened. Specifically:

|File|Used For|
|---|---|
|[Nexus_Void/Controllers/LoginController.cs](/Controllers/LoginController.cs)|SQL injection in login/registration flows, plaintext password handling|
|[Nexus_Void/Controllers/HomeController.cs](/Controllers/HomeController.cs)|SQL injection in wishlist/setting endpoints, shell command execution, unauthenticated routes|
|[Nexus_Void/Middleware/JWTMiddleware.cs](/Middleware/JWTMiddleware.cs)|Non-blocking redirect authentication bypass|
|[Nexus_Void/Helpers/JWTHelper.cs](/Helpers/JWTHelper.cs)|`ReadToken()` without signature validation, audience validation disabled|
|[Nexus_Void/Helpers/SerializeHelper.cs](/Helpers/SerializeHelper.cs)|`TypeNameHandling.All` deserialization configuration|
|[Nexus_Void/Helpers/EncodeHelper.cs](/Helpers/EncodeHelper.cs)|Base64-only encoding (no integrity protection)|
|[Nexus_Void/Helpers/StatusCheckHelper.cs](/Helpers/StatusCheckHelper.cs)|Shell execution via `Process` + `/bin/bash -c`|
|[Nexus_Void/Program.cs](/Program.cs)|Middleware registration scope (JWT only on `/home` paths)|
|[Nexus_Void/Nexus_Void.csproj](/Nexus_Void.csproj)|`EnableUnsafeBinaryFormatterSerialization=true`, dependency versions|
|[Nexus_Void/appsettings.json](/appsettings.json)|`AllowedHosts: "*"`, JWT config|
|[Dockerfile](/Dockerfile)|Script placement in `/tmp/`, `COPY flag.txt /flag.txt`, base image|
|[config/supervisord.conf](/config/supervisord.conf)|`user=root` process execution context|

No internet searches, no CVE databases, no external writeups, no prior knowledge of specific library CVEs were referenced. All conclusions were derived solely from control flow and data flow observable in those files.