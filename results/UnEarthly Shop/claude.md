## [CRITICAL] - Unauthenticated MongoDB Aggregation Pipeline Injection

**OWASP Category:** A03:2021 – Injection **CWE ID:** CWE-943 (Improper Neutralization of Special Elements in Data Query Logic) **Location:** `challenge/frontend/controllers/ShopController.php:16-26`, `challenge/frontend/models/ProductModel.php:10-12`, `challenge/frontend/Database.php:30-35`

**Vulnerable Code:**

```php
// ShopController.php:16-26
$json = file_get_contents('php://input');
$query = json_decode($json, true);
if (!$query) { $router->jsonify(['message' => 'Insufficient parameters!'], 400); }
$products = $this->product->getProducts($query);

// ProductModel.php:10-12
public function getProducts($query) {
    return $this->database->query('products', $query);
}

// Database.php:30-35
public function query($collection, $query) {
    $collection = $this->db->$collection;
    $cursor = $collection->aggregate($query);
    ...
}
```

**Source of Input:** HTTP request body (`php://input`) on the unauthenticated `POST /api/products` endpoint.

**Sink:** `$collection->aggregate($query)` — MongoDB PHP driver aggregation method called with the raw, parsed, user-supplied array.

**Data Flow Explanation:**

1. Attacker sends HTTP POST to `/api/products` with arbitrary JSON body.
2. `json_decode($json, true)` converts body to a PHP array with no validation.
3. The only guard is `if (!$query)` — any non-empty array passes.
4. The array flows through `getProducts()` → `Database::query()` → `$collection->aggregate($query)` verbatim.
5. MongoDB `aggregate()` accepts an arbitrary pipeline array; the attacker controls the entire pipeline.

**Impact:** Complete unauthenticated read access to all MongoDB collections in the `unearthly_shop` database. An attacker can execute any aggregation pipeline stage including `$lookup` (cross-collection join), `$unionWith`, `$graphLookup`, `$out`, and `$merge`. This allows: exfiltration of the `users` collection (including plaintext passwords and serialized `access` field), and — critically — writing attacker-controlled data into any collection via `$merge` or `$out`.

**Exploitation Scenario — Stage 1, Credential Exfiltration:**

```json
POST /api/products
[{"$lookup": {"from": "users", "as": "u", "pipeline": []}}, {"$project": {"users": "$u"}}]
```

Response includes all user documents with `username`, `password` (plaintext), and `access` (PHP serialized string).

**Exploitation Scenario — Stage 2, Collection Write (Malicious Payload Injection):**

```json
POST /api/products
[
  {"$match": {"_id": 1}},
  {"$addFields": {"access": "<ATTACKER_CONTROLLED_PHP_SERIALIZED_PAYLOAD>"}},
  {"$project": {"_id": 1, "access": 1}},
  {"$merge": {"into": "users", "on": "_id", "whenMatched": "merge", "whenNotMatched": "discard"}}
]
```

MongoDB 4.2+ `$merge` with `whenMatched: "merge"` merges fields into the matching `users` document by `_id`. Product `_id: 1` maps to admin user `_id: 1`. The `access` field of the admin user is overwritten with the attacker's payload.

**Confidence Level:** HIGH — Complete, evidence-only data flow. No external assumptions required. The aggregation passthrough is direct and unambiguous in the source.

---

## [CRITICAL] - PHP Object Injection via `unserialize()` on Attacker-Controllable Session Data

**OWASP Category:** A08:2021 – Software and Data Integrity Failures **CWE ID:** CWE-502 (Deserialization of Untrusted Data) **Location:** `challenge/backend/models/UserModel.php:9`

**Vulnerable Code:**

```php
// UserModel.php:4-10
public function __construct()
{
    parent::__construct();
    $this->username = $_SESSION['username'] ?? '';
    $this->email    = $_SESSION['email'] ?? '';
    $this->access   = unserialize($_SESSION['access'] ?? '');
}
```

**Source of Input:** `$_SESSION['access']`, which is populated directly from the `access` field in the MongoDB `users` collection at login time:

```php
// AuthController.php:29-30
$_SESSION['username'] = $login->username;
$_SESSION['access']   = $login->access;
```

**Sink:** `unserialize($_SESSION['access'] ?? '')` — PHP native deserialization.

**Data Flow Explanation:**

1. At login, `$_SESSION['access']` is set to the raw value of the `access` field retrieved from the `users` MongoDB collection.
2. On every subsequent privileged HTTP request, `UserModel::__construct()` is invoked, which unconditionally calls `unserialize()` on the session value.
3. If an attacker can write an arbitrary string to the `access` field of any user document in MongoDB, and then authenticate as that user, `unserialize()` will process attacker-controlled data.
4. The MongoDB `access` field is writable via two confirmed paths: (a) `POST /admin/api/users/update` (requires prior authentication — see Finding below on Mass Assignment), and (b) the MongoDB Aggregation Injection via `$merge` (unauthenticated — see preceding finding).

**Impact:** Full PHP Object Injection. Any class loaded at deserialization time whose magic methods (`__destruct`, `__wakeup`, `__toString`, `__call`, etc.) perform dangerous operations constitutes a usable gadget. The `mongodb/mongodb` vendor library and PHP core classes are present in the autoload scope. Successful exploitation achieves Remote Code Execution as the `www` system user.

**Exploitation Scenario — Complete Unauthenticated RCE Chain (chained with Finding #1):**

1. **Step 1:** `POST /api/products` with `$lookup` pipeline → extract admin credentials (plaintext password) and current `access` value.
2. **Step 2:** `POST /api/products` with `$addFields` + `$merge` pipeline → write malicious PHP serialized object string into the admin user's `access` field in MongoDB.
3. **Step 3:** `POST /admin/api/auth/login` with extracted credentials → session is populated: `$_SESSION['access']` = attacker's serialized payload.
4. **Step 4:** Any request to a privileged route (e.g., `GET /admin/dashboard`) → `UserModel::__construct()` → `unserialize(attacker_payload)` → object instantiated → magic method fires → code execution.
5. **Step 5:** Execute `/readflag` SUID binary (explicitly placed at that path in `Dockerfile:28`: `RUN gcc -o /readflag /readflag.c && chmod 4755 /readflag`).

**Confidence Level:** HIGH — The deserialization call is unconditional and occurs on every request to a privileged controller. The write path to `$_SESSION['access']` via MongoDB is directly observable. The SUID binary path `/readflag` is explicitly declared in the Dockerfile.

---

## [CRITICAL] - Mass Assignment Enabling Privilege Escalation and Deserialization Payload Injection (Authenticated Path)

**OWASP Category:** A04:2021 – Insecure Design / A03:2021 – Injection **CWE ID:** CWE-915 (Improperly Controlled Modification of Dynamically-Determined Object Attributes) **Location:** `challenge/backend/controllers/UserController.php:41-54`, `challenge/backend/models/UserModel.php:71-73`, `challenge/backend/Database.php:62-76`

**Vulnerable Code:**

```php
// UserController.php:41-54
public function update($router) {
    $json = file_get_contents('php://input');
    $data = json_decode($json, true);
    if (!$data['_id'] || !$data['username'] || !$data['password']) {
        $router->jsonify(['message' => 'Insufficient parameters!'], 400);
    }
    if ($this->user->updateUser($data)) { ...

// UserModel.php:71-73
public function updateUser($data) {
    return $this->database->update('users', $data['_id'], $data);
}

// Database.php:66-71
$updateResult = $collection->updateOne(
    [ '_id' => intval($index) ],
    [ '$set' => $data ]
);
```

**Source of Input:** HTTP request body parsed via `json_decode()` at `UserController.php:42`.

**Sink:** `$collection->updateOne(['_id' => intval($index)], ['$set' => $data])` — the entire attacker-supplied `$data` array, including any additional fields beyond `_id`, `username`, `password`, is passed directly to MongoDB `$set`.

**Data Flow Explanation:** The `update()` action only validates the presence of `_id`, `username`, and `password`. It does not whitelist or filter allowed update fields. The full `$data` array (all attacker-supplied JSON keys) is forwarded to the database `$set` operator unchanged. An authenticated attacker can inject arbitrary additional fields — specifically the `access` field — with a malicious PHP serialized payload, directly into any user document.

**Impact:** Any authenticated admin-level user can inject a PHP serialized object into any user's `access` field, achieving PHP Object Injection on the next login of the targeted user. Combined with self-targeting, an attacker with any admin access can escalate to RCE.

**Confidence Level:** HIGH — The mass assignment path is unambiguous. `$data` flows from HTTP input through to `$set` without field filtering.

---

## [HIGH] - Plaintext Password Storage and Comparison

**OWASP Category:** A02:2021 – Cryptographic Failures **CWE ID:** CWE-256 (Plaintext Storage of a Password) / CWE-916 (Use of Password Hash With Insufficient Computational Effort — absence of any hashing) **Location:** `challenge/backend/models/UserModel.php:12-25`, `config/schema/users.json:4`

**Vulnerable Code:**

```php
// UserModel.php:14-22
$login = $this->database->query('users', [
    [
        '$match' => [
            'username' => strval($username),
            'password' => strval($password)
        ]
    ]
]);
```

```json
// users.json:1-7
{
    "_id": 1,
    "username": "admin",
    "password": "[REDACTED]",
    "access": "a:4:{s:9:\"Dashboard\";b:1;...}"
}
```

**Source of Input:** Passwords are stored as raw strings in MongoDB; comparison is done in plaintext via direct `$match`.

**Sink:** MongoDB `$match` comparison against stored plaintext string.

**Data Flow Explanation:** The `entrypoint.sh` generates a random password and stores it in plaintext in MongoDB. `UserModel::login()` compares the supplied password directly as a string value without any hashing step. Any read access to the `users` collection (e.g., via the aggregation injection) immediately yields usable credentials — no hash cracking required.

**Impact:** Credential extraction via the NoSQL injection finding immediately yields working plaintext credentials, removing any defense-in-depth that password hashing would have provided. The two-step attack (inject → exfiltrate plaintext password → login) is fully realizable.

**Confidence Level:** HIGH — Observable from both `UserModel.php` (no hash function call) and `users.json` (schema shows plaintext field).

---

## [HIGH] - Nginx Alias Path Traversal (Off-by-Slash Misconfiguration)

**OWASP Category:** A05:2021 – Security Misconfiguration **CWE ID:** CWE-22 (Improper Limitation of a Pathname to a Restricted Directory) **Location:** `config/nginx.conf:33-44`

**Vulnerable Code:**

```nginx
location /admin {
    alias /www/backend/;
    index index.php;
    try_files $uri $uri/ @admin;
    location ~ \.php$ {
        try_files $uri =404;
        fastcgi_pass unix:/run/php-fpm.sock;
        fastcgi_index index.php;
        fastcgi_param SCRIPT_FILENAME $request_filename;
        include fastcgi_params;
    }
}
```

**Source of Input:** HTTP `REQUEST_URI`.

**Sink:** Nginx `alias` directive resolves `$request_filename`, which is passed as `SCRIPT_FILENAME` to PHP-FPM.

**Data Flow Explanation:** The `location /admin` block does not have a trailing slash, but the `alias` directive resolves to `/www/backend/`. The canonical Nginx alias traversal applies: a request for `/admin../` causes Nginx to resolve the path as `/www/backend/../` = `/www/`. An attacker can request `/admin../frontend/index.php` which Nginx maps to `SCRIPT_FILENAME = /www/frontend/index.php`, causing PHP-FPM to execute frontend PHP files under the admin FastCGI configuration (which uses `$request_filename` for `SCRIPT_FILENAME`). This allows access to filesystem paths outside `/www/backend/`.

**Impact:** An attacker can access arbitrary files under `/www/` by traversing up from `/www/backend/` using the alias off-by-slash, potentially reaching any web-rooted PHP file with different execution context or leaking source code.

**Confidence Level:** MEDIUM-HIGH — The pattern is directly observable in the nginx configuration. Exploitability depends on whether Nginx normalizes `..` segments before alias resolution, which is configuration and version-dependent. The off-by-slash condition is definitively present.

---

## [MEDIUM] - Reflected/Stored Cross-Site Scripting (XSS) via Unescaped Session Data in Views

**OWASP Category:** A03:2021 – Injection **CWE ID:** CWE-79 (Improper Neutralization of Input During Web Page Generation) **Location:** `challenge/backend/views/dashboard.php:44`

**Vulnerable Code:**

```php
// dashboard.php:44
<h5>Welcome back <?php echo $username; ?></h5>
```

**Source of Input:** `$username` is extracted from `$data` array inside `Router::view()` via `extract($data)`. The `$data['username']` originates from `$this->username` in `Controller.php:21`, which is set from `$this->user->username`, which is `$_SESSION['username']` (set at login from the MongoDB `users.username` field).

**Sink:** `echo $username` — direct HTML output without `htmlspecialchars()`.

**Data Flow Explanation:** If an attacker can control the `username` value in the `users` collection (via the mass assignment vulnerability in `UserController::update()`), the value is stored in MongoDB, retrieved at login, stored in the session, and rendered unescaped into HTML. An authenticated attacker can set a username containing HTML/JavaScript and achieve stored XSS.

**Impact:** Stored XSS in the admin panel. Can be used for session hijacking of other admin users, admin-to-admin attacks, or UI defacement.

**Confidence Level:** HIGH — The echo-without-escaping is directly observable. The path from MongoDB → session → view is clear.

---

## [MEDIUM] - Missing Input Validation on Order Placement (Stored Data Injection Surface)

**OWASP Category:** A03:2021 – Injection **CWE ID:** CWE-20 (Improper Input Validation) **Location:** `challenge/frontend/controllers/ShopController.php:29-42`, `challenge/frontend/models/OrderModel.php:9-18`

**Vulnerable Code:**

```php
// ShopController.php:34-39
if (!$data['name'] || !$data['email'] || !$data['bid'] || !$data['item_id']) {
    $router->jsonify(['message' => 'Insufficient parameters!'], 400);
}
$this->order->placeOrder($data['name'], $data['email'], $data['bid'], $data['item_id']);

// OrderModel.php:9-18
public function placeOrder($name, $email, $bid, $item_id) {
    return $this->database->insert('orders', [
        'name'    => $name,
        'email'   => $email,
        'bid'     => $bid,
        'item_id' => $item_id
    ]);
}
```

**Source of Input:** HTTP request body to unauthenticated `POST /api/order`.

**Sink:** `$collection->insertOne($data)` — MongoDB insert.

**Data Flow Explanation:** Fields `name`, `email`, `bid`, and `item_id` are inserted into MongoDB without type validation, length limits, or content sanitization. These values are subsequently rendered in the admin `orders.php` view (populated via AJAX from `/admin/api/orders/list`). Malicious JavaScript embedded in `name` or `email` fields by an unauthenticated attacker will be stored and could be rendered in the admin panel.

**Impact:** Unauthenticated stored XSS in the admin orders view. This is a meaningful escalation vector: an unauthenticated external attacker can achieve JavaScript execution in an authenticated admin session.

**Confidence Level:** MEDIUM — The data flow is clear. The actual XSS trigger depends on how the admin `orders.js` renders the data (JavaScript file not provided). If values are inserted into the DOM without escaping, stored XSS is confirmed.

---

## [LOW] - Supervisord Running as Root

**OWASP Category:** A05:2021 – Security Misconfiguration **CWE ID:** CWE-250 (Execution with Unnecessary Privileges) **Location:** `config/supervisord.conf:2`

**Vulnerable Code:**

```ini
[supervisord]
user=root
```

**Source of Input:** Static configuration.

**Sink:** Process management context running with UID 0.

**Data Flow Explanation:** Supervisord is explicitly configured to run as the root user. While Nginx and PHP-FPM workers spawn as `www`, the supervisord process itself maintains root privileges. If a process under supervision is compromised and has a mechanism to interact with the supervisord control socket or the supervisord process itself, privilege escalation to root could be possible.

**Impact:** The attack surface for privilege escalation is increased. Combined with any code execution vulnerability achieved as `www`, a supervisord interaction path (if present) could enable root access. The SUID `/readflag` binary already provides a controlled root-read path without needing root shell, however.

**Confidence Level:** MEDIUM — The misconfiguration is directly observable. Exploitation requires an additional pivot beyond the supervisord configuration itself.

---

## [LOW] - Missing Security Headers

**OWASP Category:** A05:2021 – Security Misconfiguration **CWE ID:** CWE-693 (Protection Mechanism Failure) **Location:** `config/nginx.conf`

**Vulnerable Code:** The nginx configuration does not define any of: `X-Frame-Options`, `X-Content-Type-Options`, `Content-Security-Policy`, `Strict-Transport-Security`, `X-XSS-Protection`, or `Referrer-Policy` headers.

`server_tokens off;` is present (suppresses version disclosure), which is positive, but insufficient.

**Impact:** Absence of CSP amplifies XSS impact. Absence of X-Frame-Options enables clickjacking against the admin panel. Absence of X-Content-Type-Options enables MIME-sniffing attacks.

**Confidence Level:** HIGH — Directly observable absence in configuration.

---

## [LOW] - No Rate Limiting or Brute-Force Protection on Authentication Endpoint

**OWASP Category:** A07:2021 – Identification and Authentication Failures **CWE ID:** CWE-307 (Improper Restriction of Excessive Authentication Attempts) **Location:** `config/nginx.conf`, `challenge/backend/controllers/AuthController.php:14-33`

**Vulnerable Code:** Neither the nginx configuration (no `limit_req_zone`) nor the `AuthController::login()` method implements any rate limiting, lockout mechanism, or CAPTCHA.

**Data Flow Explanation:** The `POST /admin/api/auth/login` endpoint accepts unlimited sequential authentication attempts. Credentials are compared with no delay or lockout.

**Impact:** Permits unlimited credential brute-forcing against the admin login endpoint. This is a lower-severity finding in isolation given the randomly-generated password, but becomes relevant if combined with partial information leakage.

**Confidence Level:** HIGH — Observable absence of any throttling mechanism.

---

# Executive Summary

**Total Critical:** 3 **Total High:** 2 **Total Medium:** 2 **Total Low:** 3

---

**Primary Risk Theme:** The dominant risk theme is the complete absence of input validation between the public-facing API and the MongoDB aggregation layer, combined with the use of `unserialize()` on database-derived session data. These two independently dangerous patterns form a deterministic, unauthenticated RCE chain.

**Most Dangerous Exploitable Path:**

> `POST /api/products` (unauthenticated) → Arbitrary MongoDB aggregation pipeline → `$lookup` users collection → Extract plaintext admin password → Second `$merge`-based pipeline → Write attacker-controlled PHP serialized object string into admin user's `access` field in MongoDB → `POST /admin/api/auth/login` with stolen credentials → `GET /admin/dashboard` → `UserModel::__construct()` → `unserialize($_SESSION['access'])` → PHP Object Injection gadget chain → Remote Code Execution as `www` → Execute `/readflag` SUID binary

This entire chain requires zero prior authentication and zero exploitation of memory corruption. It is composed entirely of application-logic and deserialization flaws directly observable in the provided source code.

**Likelihood of RCE:** **HIGH**. The path is fully traceable in the source code with no speculative steps except the specific gadget chain required for `unserialize()` exploitation (which depends on the vendor library contents, not provided in full). The deserialization call itself is unconditional, attacker-reachable, and categorically dangerous regardless of the specific gadget enumeration.

**Overall Security Posture:** **Critical — Immediately Exploitable.** The application presents an unauthenticated arbitrary aggregation injection endpoint that directly enables credential theft and database write, feeding into an unconditional `unserialize()` call on session data. There is no defense-in-depth at any layer between public HTTP input and the final dangerous sink. Passwords are stored in plaintext, removing the last friction point from the attack chain.