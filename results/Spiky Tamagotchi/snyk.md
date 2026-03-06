```
Testing \HTB Challenges\Spiky_Tamagotchi\web_spiky_tamagotchi\challenge ...

Open Issues

 ✗ [LOW] Sensitive Cookie Without 'HttpOnly' Flag
   Path: routes/index.js, line 20
   Info: Cookie misses the HttpOnly attribute (it is false by default). Set it to true to protect the cookie from possible malicious code on client side.

 ✗ [LOW] Sensitive Cookie in HTTPS Session Without 'Secure' Attribute
   Path: routes/index.js, line 20
   Info: Cookie misses the Secure attribute (it is false by default). Set it to true to protect the cookie from man-in-the-middle attacks.

 ✗ [MEDIUM] Use of Hardcoded Passwords
   Path: database.js, line 9
   Info: Do not hardcode passwords in code. Found hardcoded password used in mysql.createConnection.

 ✗ [MEDIUM] Allocation of Resources Without Limits or Throttling
   Path: routes/index.js, line 9
   Info: Expensive operation (a file system operation) is performed by an endpoint handler which does not use a rate-limiting mechanism. It may enable the attackers to perform Denial-of-service attacks. Consider using a rate-limiting middleware such as express-limit.

 ✗ [MEDIUM] Allocation of Resources Without Limits or Throttling
   Path: routes/index.js, line 28
   Info: Expensive operation (a file system operation) is performed by an endpoint handler which does not use a rate-limiting mechanism. It may enable the attackers to perform Denial-of-service attacks. Consider using a rate-limiting middleware such as express-limit.

 ✗ [MEDIUM] Cross-Site Request Forgery (CSRF)
   Path: index.js, line 4
   Info: CSRF protection is disabled for your Express app. This allows the attackers to execute requests on a user's behalf.

 ✗ [HIGH] Code Injection
   Path: routes/index.js, line 35
   Info: Unsanitized input from the HTTP request body flows into Function, where it is executed as JavaScript code. This may result in a Code Injection vulnerability.



╭──────────────────────────────────────────────────────────────────────────────────────────────────────────────╮
│ Test Summary                                                                                                 │
│                                                                                                              │
│   Organization:      ________                                                                                │
│   Test type:         Static code analysis                                                                    │
│   Project path:      \HTB Challenges\Spiky_Tamagotchi\web_spiky_tamagotchi\challenge    │
│                                                                                                              │
│   Total issues:   7                                                                                          │
│   Ignored issues: 0 [ 0 HIGH  0 MEDIUM  0 LOW ]                                                              │
│   Open issues:    7 [ 1 HIGH  4 MEDIUM  2 LOW ]                                                              │
╰──────────────────────────────────────────────────────────────────────────────────────────────────────────────╯

💡 Tip

   To view ignored issues, use the --include-ignores option.



💡 Tip

   Some capabilities, including the ability to apply ignores, are unavailable. Retest the project with the --remote-repo-url parameter or from within a repository to enable full functionality.
```