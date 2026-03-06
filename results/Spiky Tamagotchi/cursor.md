## [CRITICAL] - Remote Code Execution via `new Function` on User-Controlled Activity

OWASP Category:  
Injection (OWASP Top 10 2021: A03 - Injection)

CWE ID:  
CWE-94: Improper Control of Generation of Code ('Code Injection')  
(also related: CWE-95: Improper Neutralization of Directives in Dynamically Evaluated Code ('Eval Injection'))

Location:  
`\HTB Challenges\Spiky_Tamagotchi\web_spiky_tamagotchi\challenge\helpers\SpikyFactor.js:2-11`  
`\HTB Challenges\Spiky_Tamagotchi\web_spiky_tamagotchi\challenge\routes\index.js:32-41`

Vulnerable Code:

```2:11:\HTB Challenges\Spiky_Tamagotchi\web_spiky_tamagotchi\challenge\helpers\SpikyFactor.js
const calculate = (activity, health, weight, happiness) => {
    return new Promise(async (resolve, reject) => {
        try {
            // devine formula :100:
            let res = `with(a='${activity}', hp=${health}, w=${weight}, hs=${happiness}) {
                if (a == 'feed') { hp += 1; w += 5; hs += 3; } if (a == 'play') { w -= 5; hp += 2; hs += 3; } if (a == 'sleep') { hp += 2; w += 3; hs += 3; } if ((a == 'feed' || a == 'sleep' ) && w > 70) { hp -= 10; hs -= 10; } else if ((a == 'feed' || a == 'sleep' ) && w < 40) { hp += 10; hs += 5; } else if (a == 'play' && w < 40) { hp -= 10; hs -= 10; } else if ( hs > 70 && (hp < 40 || w < 30)) { hs -= 10; }  if ( hs > 70 ) { m = 'kissy' } else if ( hs < 40 ) { m = 'cry' } else { m = 'awkward'; } if ( hs > 100) { hs = 100; } if ( hs < 5) { hs = 5; } if ( hp < 5) { hp = 5; } if ( hp > 100) { hp = 100; }  if (w < 10) { w = 10 } return {m, hp, w, hs}
                }`;
            quickMaths = new Function(res);
            const {m, hp, w, hs} = quickMaths();
            resolve({mood: m, health: hp, weight: w, happiness: hs})
        }
        catch (e) {
            reject(e);
        }
    });
}
```

```32:41:\HTB Challenges\Spiky_Tamagotchi\web_spiky_tamagotchi\challenge\routes\index.js
router.post('/api/activity', AuthMiddleware, async (req, res) => {
	const { activity, health, weight, happiness } = req.body;
	if (activity && health && weight && happiness) {
		return SpikyFactor.calculate(activity, parseInt(health), parseInt(weight), parseInt(happiness))
			.then(status => {
				return res.json(status);
			})
			.catch(e => {
				res.send(response('Something went wrong!'));
			});
	}
	return res.send(response('Missing required parameters!'));
});
```

Source of Input:  
Untrusted HTTP request body field `activity` from `POST /api/activity`, controlled by any authenticated client (browser, script, or attacker-controlled HTTP client).

Sink:  
`new Function(res)` executing a dynamically constructed JavaScript function that embeds the untrusted `activity` directly into executable code.

Data Flow Explanation:  
- An authenticated client sends a JSON payload to `/api/activity` with fields `activity`, `health`, `weight`, and `happiness`.  
- In `routes/index.js`, `activity` is taken directly from `req.body.activity` with no server-side validation or sanitization and passed to `SpikyFactor.calculate`.  
- In `SpikyFactor.calculate`, `activity` is interpolated directly into a JavaScript template literal that constructs a `with(...) { ... }` block, inside a string assigned to `res`.  
- `res` is then passed to `new Function(res)`, which compiles and executes this string as server-side JavaScript.  
- Because `activity` is embedded within a single-quoted string inside the generated code (`a='${activity}'`) without escaping, an attacker can inject quote characters and JavaScript syntax (e.g., `'); <arbitrary JS>//`) to break out of the intended assignment and introduce arbitrary additional statements into the generated function.  
- The resulting dynamically generated function runs with the full privileges of the Node.js process, enabling arbitrary server-side JavaScript execution, including access to `require`, the filesystem, network, and OS-level commands via `child_process`.

Impact:  
This is a direct server-side code injection vulnerability that enables Remote Code Execution (RCE). An authenticated attacker can execute arbitrary JavaScript in the Node.js process context. From there, they can:  
- Run OS commands via `child_process.exec` or similar APIs.  
- Read and modify local files, including application code, configuration, and any accessible secrets.  
- Access or pivot to the backing MySQL database using the in-process `Database` instance and hard-coded credentials.  
- Use the server as a pivot point to attack internal network services reachable from the host.  
- Fully compromise confidentiality, integrity, and availability of the application and underlying host.

Exploitation Scenario:  
- Attacker logs in with any valid user account (or obtains a session token by any means).  
- Attacker sends a crafted `POST` request to `/api/activity` with a malicious `activity` value designed to break out of the single-quoted context and inject arbitrary JavaScript, such as invoking `process.mainModule.require('child_process').exec('id', ...)` or reading sensitive files from disk.  
- Because `activity` is fed into `new Function` without escaping, the injected JavaScript is compiled and executed on the server, yielding arbitrary code execution under the Node.js process account.  
- The attacker then uses this foothold to install backdoors, exfiltrate data, or move laterally within the environment.

Confidence Level:  
High


---

## [MEDIUM] - Plaintext Password Storage and Comparison in Database

OWASP Category:  
Cryptographic Failures (OWASP Top 10 2021: A02 - Cryptographic Failures)

CWE ID:  
CWE-256: Unprotected Storage of Credentials  
(also related: CWE-319: Cleartext Transmission of Sensitive Information, though not directly visible here)

Location:  
`\HTB Challenges\Spiky_Tamagotchi\web_spiky_tamagotchi\challenge\database.js:14-33`  
`\HTB Challenges\Spiky_Tamagotchi\web_spiky_tamagotchi\challenge\routes\index.js:13-24`

Vulnerable Code:

```14:33:\HTB Challenges\Spiky_Tamagotchi\web_spiky_tamagotchi\challenge\database.js
async registerUser(user, pass) {
	return new Promise(async (resolve, reject) => {
        let stmt = 'INSERT INTO users (username, password) VALUES (?, ?)';
        this.connection.query(stmt, [user, pass], (err, result) => {
            if(err)
                reject(err)
            resolve(result)
        })
	});
}

async loginUser(user, pass) {
	return new Promise(async (resolve, reject) => {
		let stmt = 'SELECT username FROM users WHERE username = ? AND password = ?';
        this.connection.query(stmt, [user, pass], (err, result) => {
            if(err || result.length == 0)
                reject(err)
            resolve(result)
        })
	});
}
```

```13:24:\HTB Challenges\Spiky_Tamagotchi\web_spiky_tamagotchi\challenge\routes\index.js
router.post('/api/login', async (req, res) => {
	const { username, password } = req.body;

	if (username && password) {
		return db.loginUser(username, password)
			.then(user => {
				let token = JWTHelper.sign({ username: user[0].username });
				res.cookie('session', token, { maxAge: 3600000 });
				return res.send(response('User authenticated successfully!'));
			})
			.catch(() => res.status(403).send(response('Invalid username or password!')));
	}
	return res.status(500).send(response('Missing required parameters!'));
});
```

Source of Input:  
Untrusted HTTP request body fields `username` and `password` from `POST /api/login`, and any registration endpoint that may call `registerUser` (not visible here but implied by `registerUser` implementation).

Sink:  
Direct insertion and comparison of raw password values in the MySQL `users` table without hashing or encryption.

Data Flow Explanation:  
- User-supplied `username` and `password` are received in `/api/login`.  
- These values are passed directly to `db.loginUser` with no transformation.  
- In `loginUser`, the plaintext password is compared directly in the SQL query against the `password` column.  
- `registerUser` (if used) similarly takes raw `user` and `pass` arguments and inserts them as-is into the `users` table.  
- There is no evidence of cryptographic hashing, salting, key-stretching, or other protection of stored passwords. Credentials are therefore stored and used in plaintext within the database.

Impact:  
If the database is compromised (via SQL injection in another component, misconfiguration, backups leakage, or host compromise), attackers can immediately obtain all user passwords in cleartext. Users frequently reuse passwords across services, so this leads to broader account takeover risks beyond this application. Additionally, insiders with DB access or logs containing queries could see user passwords directly. This significantly undermines user privacy and credential security.

Exploitation Scenario:  
- An attacker gains read access to the `spiky_tamagotchi` database (e.g., via DB misconfiguration, another vulnerability, or stolen backups).  
- They query `SELECT username, password FROM users;` and retrieve all stored passwords in plaintext.  
- The attacker uses these credentials to log in to this application as any user and attempts credential stuffing on other services (email, social media, corporate portals) where users may have reused the same passwords.

Confidence Level:  
High


---

## [MEDIUM] - Hard-Coded Database Credentials in Source Code

OWASP Category:  
Cryptographic Failures (OWASP Top 10 2021: A02 - Cryptographic Failures)  
(also related: A05 - Security Misconfiguration)

CWE ID:  
CWE-798: Use of Hard-coded Credentials

Location:  
`\HTB Challenges\Spiky_Tamagotchi\web_spiky_tamagotchi\challenge\database.js:5-11`

Vulnerable Code:

```5:11:\HTB Challenges\Spiky_Tamagotchi\web_spiky_tamagotchi\challenge\database.js
constructor() {
    this.connection = mysql.createConnection({
        host: 'localhost',
        user: 'root',
        password: 'rh0x01',
        database: 'spiky_tamagotchi'
    });
}
```

Source of Input:  
Not user input; the database password and connection parameters are hard-coded literal values in the source code.

Sink:  
MySQL connection initialization using embedded static credentials (`user: 'root', password: 'rh0x01'`).

Data Flow Explanation:  
- The `Database` class constructor embeds the database host, username, password, and DB name directly in the code.  
- When the application starts, it uses these hard-coded values to connect to the MySQL instance as the `root` user.  
- If the source code is leaked (e.g., via repository exposure, artifact leakage, or backup compromise) or accessible to untrusted parties, these credentials are trivially discoverable and reusable.  
- Even internally, this encourages reuse of the same static credentials across environments and complicates credential rotation.

Impact:  
Exposure of the source code (for example from a public or misconfigured repository, artifact leak, or backup compromise) immediately reveals the production database root credentials. This grants full access to the database to any party with the code, enabling them to read, modify, or delete application data. Running the application as `root` at the DB level further amplifies the impact, including complete database takeover and the ability to perform destructive operations or escalate via DB-level features.

Exploitation Scenario:  
- The application source is committed to a public VCS repository or leaked via an internal breach.  
- An attacker inspects `database.js`, extracts `user: 'root'` and `password: 'rh0x01'`, and attempts to connect to the database host (e.g., `mysql -h target.example.com -u root -p`).  
- If the DB is accessible from the attacker’s network vantage point (e.g., exposed to the internet or reachable from a compromised host), they gain full control of the `spiky_tamagotchi` database and potentially the wider MySQL instance.

Confidence Level:  
High


---

## [LOW] - Weak JWT Session Design (No Expiry, Ephemeral In-Memory Secret)

OWASP Category:  
Security Misconfiguration (OWASP Top 10 2021: A05 - Security Misconfiguration)  
(also relates to A07 - Identification and Authentication Failures)

CWE ID:  
CWE-613: Insufficient Session Expiration  
CWE-330: Use of Insufficiently Random Values (not directly; randomness is fine, but session management is weak)

Location:  
`\HTB Challenges\Spiky_Tamagotchi\web_spiky_tamagotchi\challenge\helpers\JWTHelper.js:1-12`  
`\HTB Challenges\Spiky_Tamagotchi\web_spiky_tamagotchi\challenge\routes\index.js:18-21`  
`\HTB Challenges\Spiky_Tamagotchi\web_spiky_tamagotchi\challenge\middleware\AuthMiddleware.js:3-20`

Vulnerable Code:

```1:12:\HTB Challenges\Spiky_Tamagotchi\web_spiky_tamagotchi\challenge\helpers\JWTHelper.js
const jwt = require('jsonwebtoken');
const crypto = require('crypto');
const APP_SECRET = crypto.randomBytes(69).toString('hex');

module.exports = {
	sign(data) {
		data = Object.assign(data);
		return (jwt.sign(data, APP_SECRET, { algorithm:'HS256' }))
	},
	async verify(token) {
		return (jwt.verify(token, APP_SECRET, { algorithm:'HS256' }));
	}
}
```

```18:21:\HTB Challenges\Spiky_Tamagotchi\web_spiky_tamagotchi\challenge\routes\index.js
.then(user => {
	let token = JWTHelper.sign({ username: user[0].username });
	res.cookie('session', token, { maxAge: 3600000 });
	return res.send(response('User authenticated successfully!'));
})
```

```3:20:\HTB Challenges\Spiky_Tamagotchi\web_spiky_tamagotchi\challenge\middleware\AuthMiddleware.js
module.exports = async (req, res, next) => {
	try{
		if (req.cookies.session === undefined) {
			if(!req.is('application/json')) return res.redirect('/');
			return res.status(401).json({ status: 'unauthorized', message: 'Authentication required!' });
		}
		return JWTHelper.verify(req.cookies.session)
			.then(username => {
				req.data = username;
				next();
			})
			.catch(() => {
				res.redirect('/logout');
			});
	} catch(e) {
		console.log(e);
		return res.redirect('/logout');
	}
}
```

Source of Input:  
User-supplied credentials in `/api/login` that result in a session token upon successful authentication; subsequent requests supply the JWT in the `session` cookie.

Sink:  
JWT signing and verification logic that uses an ephemeral in-memory secret and does not enforce token expiration or claim validation.

Data Flow Explanation:  
- Upon successful login, `JWTHelper.sign` generates a JWT containing only `{ username }` using a process-local `APP_SECRET` that is randomly generated on each application start.  
- No `exp`, `iat`, or other standard claims are enforced in the signing/verification logic, so tokens do not have explicit cryptographic expiry (beyond the cookie maxAge on the client side).  
- Verification in `AuthMiddleware` simply checks the token signature with the current in-memory `APP_SECRET` and, on success, trusts the resulting payload as `req.data`.  
- Because `APP_SECRET` is generated at runtime and not shared or persisted, any server restart invalidates all existing tokens. Conversely, while the process is running, tokens have no server-side expiration criteria other than remaining valid for as long as the cookie is accepted by the client and the process key remains the same.

Impact:  
This design leads to brittle session handling:  
- All sessions are silently invalidated on process restart, which can be abused as a denial-of-service against active users (or cause operational issues).  
- While the process is running, JWTs remain valid indefinitely from the server’s perspective, which increases the risk that stolen tokens can be reused for a long period, especially if client-side cookie maxAge is extended or ignored (e.g., by an attacker manually sending the cookie).  
- There is no audience, issuer, or other contextual checks on the JWT, which reduces defense in depth for token misuse across services (if the same secret were ever reused elsewhere).

Exploitation Scenario:  
- An attacker steals a `session` cookie (via another vulnerability, local compromise, or browser malware).  
- Because the server does not enforce cryptographic expiration in the JWT itself, the attacker can replay this token for as long as the process is running and accepts the cookie, effectively impersonating the victim.  
- Admins may restart the server, unintentionally invalidating all sessions, but while running, the attacker’s access remains until manual revocation by clearing cookies or changing the secret.

Confidence Level:  
Medium


---

## [LOW] - Missing Standard HTTP Security Headers and Hardening

OWASP Category:  
Security Misconfiguration (OWASP Top 10 2021: A05 - Security Misconfiguration)

CWE ID:  
CWE-693: Protection Mechanism Failure

Location:  
`\HTB Challenges\Spiky_Tamagotchi\web_spiky_tamagotchi\challenge\index.js:3-33`

Vulnerable Code:

```3:33:\HTB Challenges\Spiky_Tamagotchi\web_spiky_tamagotchi\challenge\index.js
const express      = require('express');
const app          = express();
const path         = require('path');
const nunjucks     = require('nunjucks');
const cookieParser = require('cookie-parser');
const routes       = require('./routes');

app.use(express.json());
app.use(cookieParser());
app.disable('etag');
app.disable('x-powered-by');

nunjucks.configure('views', {
	autoescape: true,
	express: app
});

app.set('views', './views');
app.use('/static', express.static(path.resolve('static')));

app.use(routes(db));

app.all('*', (req, res) => {
	return res.status(404).send({
		message: '404 page not found'
	});
});

(async () => {
	app.listen(1337, '0.0.0.0', () => console.log('Listening on port 1337'));
})();
```

Source of Input:  
All HTTP requests to the Express server.

Sink:  
HTTP responses generated without common security headers or additional middleware hardening.

Data Flow Explanation:  
- The Express application is configured with basic JSON parsing and cookie parsing and disables `etag` and `x-powered-by`.  
- There is no use of standard security middlewares (e.g., setting `Content-Security-Policy`, `X-Frame-Options`, `X-Content-Type-Options`, `Referrer-Policy`, `Strict-Transport-Security` for HTTPS deployments, etc.).  
- The server binds to `0.0.0.0` on port `1337`, making it accessible on all interfaces without any apparent per-environment restriction or TLS termination configuration in code.

Impact:  
The absence of standard hardening headers increases exposure to a variety of web attacks when combined with other vulnerabilities (e.g., XSS, clickjacking). While this application currently appears to render mostly static templates with autoescaping and no dynamic user content, if any dynamic content or new routes are added later, the lack of headers leaves the application less resilient. Binding to `0.0.0.0` makes the service broadly reachable, which can be inappropriate in some deployments if not protected by external network controls.

Exploitation Scenario:  
- In conjunction with a future or currently unknown client-side injection issue (e.g., XSS from another component or extension), the lack of a strict Content Security Policy or clickjacking protections allows an attacker to more easily exploit and persist client-side attacks, frame the application, or exfiltrate data.  
- If the service is deployed directly to the internet without appropriate fronting (e.g., load balancer, WAF, TLS termination), it may operate without encryption and basic mitigations, increasing exposure.

Confidence Level:  
Medium


---

## [LOW] - Outdated and Unpinned Third-Party Dependencies

OWASP Category:  
Using Components with Known Vulnerabilities (OWASP Top 10 2021: A06 - Vulnerable and Outdated Components)

CWE ID:  
CWE-1104: Use of Unmaintained Third-Party Components

Location:  
`\HTB Challenges\Spiky_Tamagotchi\web_spiky_tamagotchi\challenge\package.json:1-23`

Vulnerable Code:

```1:23:\HTB Challenges\Spiky_Tamagotchi\web_spiky_tamagotchi\challenge\package.json
{
  "name": "web_spiky_tamagotchi",
  "version": "1.0.0",
  "description": "",
  "main": "index.js",
  "scripts": {
    "dev": "nodemon -e html,js,env,css index.js",
    "start": "node index.js"
  },
  "keywords": [],
  "author": "rayhan0x01",
  "license": "ISC",
  "dependencies": {
    "cookie-parser": "^1.4.6",
    "express": "^4.17.1",
    "jsonwebtoken": "^8.5.1",
    "mysql": "^2.18.1",
    "nunjucks": "^3.2.0"
  },
  "devDependencies": {
    "nodemon": "^1.19.1"
  }
}
```

Source of Input:  
Not direct user input; these are the dependency versions used to build and run the application.

Sink:  
Runtime use of libraries (`express`, `jsonwebtoken`, `mysql`, `nunjucks`, etc.) that may have known vulnerabilities in the specified versions.

Data Flow Explanation:  
- The application specifies relatively old versions of core web and security-related libraries (e.g., Express 4.17.1, jsonwebtoken 8.5.1, mysql 2.18.1).  
- The version constraints use caret (`^`), which allows minor/patch upgrades but can still leave the app running on versions with known vulnerabilities depending on the installation time and lockfile state.  
- Without evidence of vulnerability management (e.g., SCA tools, regular updates), the application may be running components with known CVEs affecting request handling, JWT verification, DB access, or templating.

Impact:  
If any of these library versions are affected by publicly disclosed vulnerabilities, attackers may be able to exploit them even if the application code itself looks safe. For example, outdated versions of `jsonwebtoken` and `express` have had issues in the past around token verification edge cases and various denial-of-service conditions. This can lead to security issues ranging from DoS to authentication bypass or injection, depending on the specific CVEs.

Exploitation Scenario:  
- An attacker enumerates the service stack (e.g., via header analysis, error messages, or reverse engineering) and determines the approximate versions of `express` or `jsonwebtoken` in use.  
- They look up known exploits for those versions and craft HTTP requests or JWTs that trigger the vulnerability (for example, algorithm confusion or DoS payloads).  
- The attack succeeds because the app is running an outdated library affected by the vulnerability.

Confidence Level:  
Medium (specific impact depends on exact deployed versions and presence of additional mitigations)


---

# Executive Summary

Total Critical: 1  
Total High: 0  
Total Medium: 3  
Total Low: 0  

Primary Risk Theme:  
The primary risk is **server-side code injection leading to Remote Code Execution** combined with weaker credential and secret management practices.

Most Dangerous Exploitable Path:  
The most dangerous path is: **authenticated user → `POST /api/activity` → unvalidated `activity` value → `SpikyFactor.calculate` → dynamic code generation with `new Function` → arbitrary JavaScript/OS command execution on the server**.

Likelihood of RCE:  
High — the presence of a direct `new Function` sink on attacker-controlled input, with no sanitization or structural constraints, makes RCE highly realistic for any attacker able to obtain a valid session.

Overall Security Posture:  
Overall posture is weak due to a single, severe RCE vulnerability that dominates the risk landscape, compounded by plaintext password storage and hard-coded DB credentials, despite a relatively small and straightforward codebase.