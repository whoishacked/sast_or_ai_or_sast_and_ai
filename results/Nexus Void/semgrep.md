```
docker run --rm -v "${PWD}:/src" semgrep/semgrep:latest semgrep scan


┌─────────────┐
│ Scan Status │
└─────────────┘
  Scanning 582 files tracked by git with 1064 Code rules:

  Language      Rules   Files          Origin      Rules
 ─────────────────────────────        ───────────────────
  <multilang>      63     388          Community    1064
  csharp           33      30
  json              4      18
  js              156       8
  dockerfile        6       1
  bash              4       1

Warning: 3 timeout error(s) in Nexus_Void/obj/Release/net7.0/PubTmp/Out/wwwroot/js/tailwind.js when running the
following rules: [javascript.aws-lambda.security.tainted-eval.tainted-eval, javascript.aws-lambda.security.tainted-html-
string.tainted-html-string, javascript.express.security.express-insecure-template-usage.express-insecure-template-usage]
Semgrep stopped running rules on Nexus_Void/obj/Release/net7.0/PubTmp/Out/wwwroot/js/tailwind.js after 3 timeout
error(s). See `--timeout-threshold` for more info.
Warning: 3 timeout error(s) in Nexus_Void/wwwroot/js/tailwind.js when running the following rules: [javascript.aws-
lambda.security.tainted-eval.tainted-eval, javascript.aws-lambda.security.tainted-html-string.tainted-html-string,
javascript.express.security.express-insecure-template-usage.express-insecure-template-usage]
Semgrep stopped running rules on Nexus_Void/wwwroot/js/tailwind.js after 3 timeout error(s). See `--timeout-threshold`
for more info.


┌──────────────────┐
│ 10 Code Findings │
└──────────────────┘

    Dockerfile
   ❯❯❱ dockerfile.security.missing-user-entrypoint.missing-user-entrypoint
          ❰❰ Blocking ❱❱
          By not specifying a USER, a program in the container may run as 'root'. This is a security hazard.
          If an attacker can control a process running as root, they may have control over the container.   
          Ensure that the last USER in a Dockerfile is a USER other than 'root'.
          Details: https://sg.run/k281

           ▶▶┆ Autofix ▶ USER non-root ENTRYPOINT ["/usr/bin/supervisord", "-c", "/etc/supervisord.conf"]
           39┆ ENTRYPOINT ["/usr/bin/supervisord", "-c", "/etc/supervisord.conf"]

    Nexus_Void/Controllers/HomeController.cs
    ❯❱ csharp.dotnet.security.mvc-missing-antiforgery.mvc-missing-antiforgery
          ❰❰ Blocking ❱❱
          Wishlist is a state-changing MVC method that does not validate the antiforgery token or do strict   
          content-type checking. State-changing controller methods should either enforce antiforgery tokens or
          do strict content-type checking to prevent simple HTTP request types from bypassing CORS preflight
          controls.
          Details: https://sg.run/Y0Jy

           58┆ [HttpPost]
           59┆ public IActionResult Wishlist(string name, string sellerName)
           60┆ {
           61┆     string ID = HttpContext.Items["ID"].ToString();
           62┆
           63┆     string sqlQueryGetWishlist = $"SELECT * from Wishlist WHERE ID={ID}";
           64┆     var wishlist = _db.Wishlist.FromSqlRaw(sqlQueryGetWishlist).FirstOrDefault();
           65┆
           66┆     string sqlQueryProduct = $"SELECT * from Products WHERE name='{name}' AND
               sellerName='{sellerName}'";
           67┆     var product = _db.Products.FromSqlRaw(sqlQueryProduct).FirstOrDefault();
             [hid 43 additional lines, adjust with --max-lines-per-finding]
    ❯❱ csharp.dotnet.security.mvc-missing-antiforgery.mvc-missing-antiforgery
          ❰❰ Blocking ❱❱
          Setting is a state-changing MVC method that does not validate the antiforgery token or do strict
          content-type checking. State-changing controller methods should either enforce antiforgery tokens or
          do strict content-type checking to prevent simple HTTP request types from bypassing CORS preflight
          controls.
          Details: https://sg.run/Y0Jy

          120┆ [HttpPost]
          121┆ public IActionResult Setting(UserModel user)
          122┆ {
          123┆     string ID = HttpContext.Items["ID"].ToString();
          124┆     JWTHelper jwt = new JWTHelper(_configuration);
          125┆
          126┆     string jwtToken = jwt.GenerateJwtToken(user.username, ID);
          127┆
          128┆     string sqlQuery = $"UPDATE Users SET username='{user.username}' WHERE ID={ID}";
          129┆     _db.Database.ExecuteSqlRaw(sqlQuery);
             [hid 8 additional lines, adjust with --max-lines-per-finding]
    ❯❱ csharp.dotnet.security.mvc-missing-antiforgery.mvc-missing-antiforgery
          ❰❰ Blocking ❱❱
          WishlistRemove is a state-changing MVC method that does not validate the antiforgery token or do
          strict content-type checking. State-changing controller methods should either enforce antiforgery
          tokens or do strict content-type checking to prevent simple HTTP request types from bypassing CORS
          preflight controls.
          Details: https://sg.run/Y0Jy

          139┆ [HttpPost]
          140┆ public IActionResult WishlistRemove(string name, string sellerName)
          141┆ {
          142┆     string ID = HttpContext.Items["ID"].ToString();
          143┆
          144┆     string sqlQueryGetWishlist = $"SELECT * from Wishlist WHERE ID='{ID}'";
          145┆     var wishlist = _db.Wishlist.FromSqlRaw(sqlQueryGetWishlist).FirstOrDefault();
          146┆
          147┆     List<ProductModel> products = SerializeHelper.Deserialize(wishlist.data);
          148┆
             [hid 12 additional lines, adjust with --max-lines-per-finding]

    Nexus_Void/Controllers/LoginController.cs
    ❯❱ csharp.dotnet.security.mvc-missing-antiforgery.mvc-missing-antiforgery
          ❰❰ Blocking ❱❱
          Index is a state-changing MVC method that does not validate the antiforgery token or do strict
          content-type checking. State-changing controller methods should either enforce antiforgery tokens or
          do strict content-type checking to prevent simple HTTP request types from bypassing CORS preflight
          controls.
          Details: https://sg.run/Y0Jy

           30┆ [HttpPost]
           31┆ public IActionResult Index(UserModel userModel)
           32┆ {
           33┆     string sqlQuery = $"SELECT * FROM Users WHERE username='{userModel.username}' AND
               password='{userModel.password}'";
           34┆
           35┆     var result = _db.Users.FromSqlRaw(sqlQuery).FirstOrDefault();
           36┆
           37┆     if (result != null)
           38┆     {
           39┆         JWTHelper jwt = new JWTHelper(_configuration);
             [hid 11 additional lines, adjust with --max-lines-per-finding]
    ❯❱ csharp.dotnet.security.mvc-missing-antiforgery.mvc-missing-antiforgery
          ❰❰ Blocking ❱❱
          Create is a state-changing MVC method that does not validate the antiforgery token or do strict
          content-type checking. State-changing controller methods should either enforce antiforgery tokens or
          do strict content-type checking to prevent simple HTTP request types from bypassing CORS preflight
          controls.
          Details: https://sg.run/Y0Jy

           59┆ [HttpPost]
           60┆ public IActionResult Create(UserModel userModel)
           61┆ {
           62┆
           63┆     if (string.IsNullOrEmpty(userModel.username) ||
               string.IsNullOrEmpty(userModel.password))
           64┆     {
           65┆         ViewData["Message"] = "Username and Password cannot be empty!";
           66┆         return View();
           67┆     }
           68┆
             [hid 16 additional lines, adjust with --max-lines-per-finding]

    Nexus_Void/Helpers/SerializeHelper.cs
    ❯❱ csharp.lang.security.insecure-deserialization.newtonsoft.insecure-newtonsoft-deserialization
          ❰❰ Blocking ❱❱
          TypeNameHandling All is unsafe and can lead to arbitrary code execution in the context of the
          process. Use a custom SerializationBinder whenever using a setting other than TypeNameHandling.None.
          Details: https://sg.run/8n2g

           12┆ TypeNameHandling = TypeNameHandling.All
            ⋮┆----------------------------------------
           25┆ TypeNameHandling = TypeNameHandling.All

    Nexus_Void/obj/Release/net7.0/PubTmp/Out/wwwroot/lib/jquery-validation-unobtrusive/jquery.validate.unobtrusive.js   
    ❯❱ javascript.lang.security.audit.detect-non-literal-regexp.detect-non-literal-regexp
          ❰❰ Blocking ❱❱
          RegExp() called with a `params` function argument, this might allow an attacker to cause a Regular
          Expression Denial-of-Service (ReDoS) within your application as RegExP blocks the main thread. For
          this reason, it is recommended to use hardcoded regexes instead. If your regex is run on user-
          controlled input, consider performing input validation or use a regex checking/sanitization library
          such as https://www.npmjs.com/package/recheck to verify that the regex does not appear vulnerable to
          ReDoS.
          Details: https://sg.run/gr65

          349┆ match = new RegExp(params).exec(value);

    Nexus_Void/wwwroot/lib/jquery-validation-unobtrusive/jquery.validate.unobtrusive.js
    ❯❱ javascript.lang.security.audit.detect-non-literal-regexp.detect-non-literal-regexp
          ❰❰ Blocking ❱❱
          RegExp() called with a `params` function argument, this might allow an attacker to cause a Regular
          Expression Denial-of-Service (ReDoS) within your application as RegExP blocks the main thread. For
          this reason, it is recommended to use hardcoded regexes instead. If your regex is run on user-
          controlled input, consider performing input validation or use a regex checking/sanitization library
          such as https://www.npmjs.com/package/recheck to verify that the regex does not appear vulnerable to
          ReDoS.
          Details: https://sg.run/gr65

          349┆ match = new RegExp(params).exec(value);



┌──────────────┐
│ Scan Summary │
└──────────────┘
✅ Scan completed successfully.
 • Findings: 10 (10 blocking)
 • Rules run: 263
 • Targets scanned: 582
 • Parsed lines: ~100.0%
 • Scan skipped:
   ◦ Files larger than  files 1.0 MB: 45
   ◦ Files matching .semgrepignore patterns: 20
 • For a detailed list of skipped files and lines, run semgrep with the --verbose flag
Ran 263 rules on 582 files: 10 findings.
```