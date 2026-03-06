```
docker run --rm -v "${PWD}:/src" semgrep/semgrep:latest semgrep scan


┌─────────────┐
│ Scan Status │
└─────────────┘
  Scanning 62 files tracked by git with 1064 Code rules:

  Language      Rules   Files          Origin      Rules
 ─────────────────────────────        ───────────────────
  <multilang>      59      42          Community    1064
  php              38      27
  js              156       5
  json              4       5
  bash              4       2
  dockerfile        6       1
  c                 5       1



┌─────────────────┐
│ 3 Code Findings │
└─────────────────┘

    Dockerfile
   ❯❯❱ dockerfile.security.missing-user-entrypoint.missing-user-entrypoint
          ❰❰ Blocking ❱❱
          By not specifying a USER, a program in the container may run as 'root'. This is a security hazard.
          If an attacker can control a process running as root, they may have control over the container.
          Ensure that the last USER in a Dockerfile is a USER other than 'root'.
          Details: https://sg.run/k281

           ▶▶┆ Autofix ▶ USER non-root ENTRYPOINT ["/entrypoint.sh"]
           42┆ ENTRYPOINT ["/entrypoint.sh"]

    challenge/backend/models/UserModel.php
    ❯❱ php.lang.security.unserialize-use.unserialize-use
          ❰❰ Blocking ❱❱
          Calling `unserialize()` with user input in the pattern can lead to arbitrary code execution.
          Consider using JSON or structured data approaches (e.g. Google Protocol Buffers).
          Details: https://sg.run/b24E

            9┆ $this->access   = unserialize($_SESSION['access'] ?? '');

    config/nginx.conf
    ❯❱ generic.nginx.security.alias-path-traversal.alias-path-traversal
          ❰❰ Blocking ❱❱
          The alias in this location block is subject to a path traversal because the location path does not
          end in a path separator (e.g., '/'). To fix, add a path separator to the end of the path.
          Details: https://sg.run/ZvNL

           33┆ location /admin {
           34┆     alias /www/backend/;
           35┆     index index.php;
           36┆     try_files $uri $uri/ @admin;
           37┆     location ~ \.php$ {
           38┆         try_files $uri =404;
           39┆         fastcgi_pass unix:/run/php-fpm.sock;
           40┆         fastcgi_index index.php;
           41┆         fastcgi_param SCRIPT_FILENAME $request_filename;
           42┆         include fastcgi_params;
             [hid 2 additional lines, adjust with --max-lines-per-finding]



┌──────────────┐
│ Scan Summary │
└──────────────┘
✅ Scan completed successfully.
 • Findings: 3 (3 blocking)
 • Rules run: 268
 • Targets scanned: 62
 • Parsed lines: ~100.0%
 • Scan skipped:
   ◦ Files larger than  files 1.0 MB: 2
   ◦ Files matching .semgrepignore patterns: 20
 • For a detailed list of skipped files and lines, run semgrep with the --verbose flag
Ran 268 rules on 62 files: 3 findings.
```