```
Testing \HTB Challenges\Medium\Nexus_Void\web_nexus_void ...

Open Issues

 ✗ [LOW] Anti-forgery token validation disabled
   Path: Nexus_Void/Controllers/HomeController.cs, line 59
   Info: This ASP.NET MVC action should use an anti-forgery validation attribute. Not using this attribute disables Cross Site Request Forgery (CSRF) protection and allows CSRF attacks.

 ✗ [LOW] Anti-forgery token validation disabled
   Path: Nexus_Void/Controllers/HomeController.cs, line 121
   Info: This ASP.NET MVC action should use an anti-forgery validation attribute. Not using this attribute disables Cross Site Request Forgery (CSRF) protection and allows CSRF attacks.

 ✗ [LOW] Anti-forgery token validation disabled
   Path: Nexus_Void/Controllers/HomeController.cs, line 140
   Info: This ASP.NET MVC action should use an anti-forgery validation attribute. Not using this attribute disables Cross Site Request Forgery (CSRF) protection and allows CSRF attacks.

 ✗ [LOW] Anti-forgery token validation disabled
   Path: Nexus_Void/Controllers/LoginController.cs, line 31
   Info: This ASP.NET MVC action should use an anti-forgery validation attribute. Not using this attribute disables Cross Site Request Forgery (CSRF) protection and allows CSRF attacks.

 ✗ [LOW] Anti-forgery token validation disabled
   Path: Nexus_Void/Controllers/LoginController.cs, line 60
   Info: This ASP.NET MVC action should use an anti-forgery validation attribute. Not using this attribute disables Cross Site Request Forgery (CSRF) protection and allows CSRF attacks.

 ✗ [LOW] Anti-forgery token validation disabled
   Path: Nexus_Void/Controllers/LoginController.cs, line 87
   Info: This ASP.NET MVC action should use an anti-forgery validation attribute. Not using this attribute disables Cross Site Request Forgery (CSRF) protection and allows CSRF attacks.

 ✗ [MEDIUM] Deserialization of Untrusted Data
   Path: Nexus_Void/Helpers/SerializeHelper.cs, line 12
   Info: Using JsonSerializerSettings with TypeNameHandling property set to TypeNameHandling.All, may result in an Unsafe Deserialization vulnerability where it is used to deserialize untrusted object.

 ✗ [MEDIUM] Deserialization of Untrusted Data
   Path: Nexus_Void/Helpers/SerializeHelper.cs, line 25
   Info: Using JsonSerializerSettings with TypeNameHandling property set to TypeNameHandling.All, may result in an Unsafe Deserialization vulnerability where it is used to deserialize untrusted object.

 ✗ [HIGH] SQL Injection
   Path: Nexus_Void/Controllers/HomeController.cs, line 67
   Info: Unsanitized input from an HTTP parameter flows into FromSqlRaw, where it is used in an SQL query. This may result in an SQL Injection vulnerability.

 ✗ [HIGH] SQL Injection
   Path: Nexus_Void/Controllers/LoginController.cs, line 35
   Info: Unsanitized input from an HTTP parameter flows into FromSqlRaw, where it is used in an SQL query. This may result in an SQL Injection vulnerability.

 ✗ [HIGH] SQL Injection
   Path: Nexus_Void/Controllers/LoginController.cs, line 70
   Info: Unsanitized input from an HTTP parameter flows into FromSqlRaw, where it is used in an SQL query. This may result in an SQL Injection vulnerability.

 ✗ [HIGH] SQL Injection
   Path: Nexus_Void/Controllers/HomeController.cs, line 129
   Info: Unsanitized input from an HTTP parameter flows into ExecuteSqlRaw, where it is used in an SQL query. This may result in an SQL Injection vulnerability.

 ✗ [HIGH] SQL Injection
   Path: Nexus_Void/Controllers/LoginController.cs, line 75
   Info: Unsanitized input from an HTTP parameter flows into ExecuteSqlRaw, where it is used in an SQL query. This may result in an SQL Injection vulnerability.



╭───────────────────────────────────────────────────────────────────────────────────────────────╮
│ Test Summary                                                                                  │
│                                                                                               │
│   Organization:      __________                                                                 │
│   Test type:         Static code analysis                                                     │
│   Project path:      \HTB Challenges\Medium\Nexus_Void\web_nexus_void    │
│                                                                                               │
│   Total issues:   13                                                                          │
│   Ignored issues: 0 [ 0 HIGH  0 MEDIUM  0 LOW ]                                               │
│   Open issues:    13 [ 5 HIGH  2 MEDIUM  6 LOW ]                                              │
╰───────────────────────────────────────────────────────────────────────────────────────────────╯

💡 Tip

   To view ignored issues, use the --include-ignores option.



💡 Tip

   Some capabilities, including the ability to apply ignores, are unavailable. Retest the project with the --remote-repo-url parameter or from within a repository to enable full functionality.
```