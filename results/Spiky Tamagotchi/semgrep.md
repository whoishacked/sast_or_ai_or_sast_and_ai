```
docker run --rm -v "${PWD}:/src" semgrep/semgrep:latest semgrep scan


┌─────────────┐
│ Scan Status │
└─────────────┘
  Scanning 24 files tracked by git with 1064 Code rules:

  Language      Rules   Files          Origin      Rules
 ─────────────────────────────        ───────────────────
  <multilang>      61      24          Community    1064
  js              156       8
  html              1       2
  json              4       1



┌─────────────────┐
│ 3 Code Findings │
└─────────────────┘

    helpers/JWTHelper.js
    ❯❱ javascript.jsonwebtoken.security.audit.jwt-exposed-data.jwt-exposed-data
          ❰❰ Blocking ❱❱
          The object is passed strictly to jsonwebtoken.sign(...) Make sure that sensitive information is not
          exposed through JWT token payload.
          Details: https://sg.run/5Qkj

            8┆ return (jwt.sign(data, APP_SECRET, { algorithm:'HS256' }))

    index.js
     ❱ javascript.express.security.audit.express-check-csurf-middleware-usage.express-check-csurf-middleware-usage
          ❰❰ Blocking ❱❱
          A CSRF middleware was not detected in your express application. Ensure you are either using one such
          as `csurf` or `csrf` (see rule references) and/or you are properly doing CSRF validation in your
          routes with a token or cookies.
          Details: https://sg.run/BxzR

            4┆ const app          = express();

    views/interface.html
    ❯❱ html.security.audit.missing-integrity.missing-integrity
          ❰❰ Blocking ❱❱
          This tag is missing an 'integrity' subresource integrity attribute. The 'integrity' attribute allows
          for the browser to verify that externally hosted files (for example from a CDN) are delivered
          without unexpected manipulation. Without this attribute, if an attacker can modify the externally
          hosted resource, this could lead to XSS and other types of attacks. To prevent this, include the
          base64-encoded cryptographic hash of the resource (file) you’re telling the browser to fetch in the
          'integrity' attribute for all externally hosted files.
          Details: https://sg.run/krXA

            9┆ <link rel="stylesheet" type="text/css" href="https://cdnjs.cloudflare.com/ajax/libs/font-
               awesome/4.7.0/css/font-awesome.css">



┌──────────────┐
│ Scan Summary │
└──────────────┘
✅ Scan completed successfully.
 • Findings: 3 (3 blocking)
 • Rules run: 221
 • Targets scanned: 24
 • Parsed lines: ~100.0%
 • Scan skipped:
   ◦ Files larger than  files 1.0 MB: 1
   ◦ Files matching .semgrepignore patterns: 1
 • For a detailed list of skipped files and lines, run semgrep with the --verbose flag
Ran 221 rules on 24 files: 3 findings.
```