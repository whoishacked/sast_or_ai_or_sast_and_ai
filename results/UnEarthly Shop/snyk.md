```
Testing \HTB Challenges\HARD\UnEarthly_Shop\web_unearthly_shop ...

Open Issues

 ✗ [LOW] Code Injection
   Path: challenge/backend/vendor/mongodb/mongodb/tests/Operation/WatchFunctionalTest.php, line 815
   Info: Unsanitized input from an HTTP parameter flows into assert, where it is executed as php code. This may result in a Code Injection vulnerability.

 ✗ [LOW] Code Injection
   Path: challenge/backend/vendor/mongodb/mongodb/tests/Operation/WatchFunctionalTest.php, line 866
   Info: Unsanitized input from an HTTP parameter flows into assert, where it is executed as php code. This may result in a Code Injection vulnerability.

 ✗ [LOW] Use of Password Hash With Insufficient Computational Effort
   Path: challenge/frontend/vendor/mongodb/mongodb/src/GridFS/WritableStream.php, line 143
   Info: hash_init hash (used in hash_init) is insecure. Consider changing it to a secure hashing algorithm.

 ✗ [LOW] Use of Password Hash With Insufficient Computational Effort
   Path: challenge/frontend/vendor/aws/aws-sdk-php/src/Middleware.php, line 207
   Info: MD5 hash (used in md5) is insecure. Consider changing it to a secure hashing algorithm.

 ✗ [LOW] Use of Password Hash With Insufficient Computational Effort
   Path: challenge/frontend/vendor/aws/aws-sdk-php/src/S3/SSECMiddleware.php, line 72
   Info: MD5 hash (used in md5) is insecure. Consider changing it to a secure hashing algorithm.

 ✗ [LOW] Use of Hardcoded Credentials
   Path: challenge/frontend/vendor/guzzlehttp/psr7/tests/ServerRequestTest.php, line 425
   Info: Do not hardcode credentials in code. Found a hardcoded credential used in an URL.

 ✗ [LOW] Use of Password Hash With Insufficient Computational Effort
   Path: challenge/frontend/vendor/aws/aws-sdk-php/src/Sqs/SqsClient.php, line 146
   Info: MD5 hash (used in md5) is insecure. Consider changing it to a secure hashing algorithm.

 ✗ [LOW] Use of Password Hash With Insufficient Computational Effort
   Path: challenge/frontend/vendor/aws/aws-sdk-php/src/Sqs/SqsClient.php, line 151
   Info: MD5 hash (used in md5) is insecure. Consider changing it to a secure hashing algorithm.

 ✗ [LOW] Use of Password Hash With Insufficient Computational Effort
   Path: challenge/frontend/vendor/monolog/monolog/src/Monolog/Handler/DeduplicationHandler.php, line 76
   Info: MD5 hash (used in md5) is insecure. Consider changing it to a secure hashing algorithm.

 ✗ [LOW] Use of Password Hash With Insufficient Computational Effort
   Path: challenge/frontend/vendor/mtdowling/jmespath.php/src/CompilerRuntime.php, line 54
   Info: MD5 hash (used in md5) is insecure. Consider changing it to a secure hashing algorithm.

 ✗ [LOW] Use of Password Hash With Insufficient Computational Effort
   Path: challenge/frontend/vendor/mtdowling/jmespath.php/src/DebugRuntime.php, line 87
   Info: MD5 hash (used in md5) is insecure. Consider changing it to a secure hashing algorithm.

 ✗ [LOW] Use of Password Hash With Insufficient Computational Effort
   Path: challenge/frontend/vendor/aws/aws-sdk-php/src/S3/PostObject.php, line 151
   Info: hash_hmac hash (used in hash_hmac) is insecure. Consider changing it to a secure hashing algorithm.

 ✗ [LOW] Use of Password Hash With Insufficient Computational Effort
   Path: challenge/frontend/vendor/guzzlehttp/psr7/src/MultipartStream.php, line 33
   Info: SHA1 hash (used in sha1) is insecure. Consider changing it to a secure hashing algorithm.

 ✗ [LOW] Use of Password Hash With Insufficient Computational Effort
   Path: challenge/backend/vendor/mongodb/mongodb/tests/GridFS/BucketFunctionalTest.php, line 836
   Info: hash_init hash (used in hash_init) is insecure. Consider changing it to a secure hashing algorithm.

 ✗ [LOW] Use of Password Hash With Insufficient Computational Effort
   Path: challenge/frontend/vendor/mongodb/mongodb/tests/GridFS/BucketFunctionalTest.php, line 836
   Info: hash_init hash (used in hash_init) is insecure. Consider changing it to a secure hashing algorithm.

 ✗ [LOW] Use of Password Hash With Insufficient Computational Effort
   Path: challenge/backend/vendor/mongodb/mongodb/tests/TestCase.php, line 164
   Info: hash hash (used in hash) is insecure. Consider changing it to a secure hashing algorithm.

 ✗ [LOW] Use of Password Hash With Insufficient Computational Effort
   Path: challenge/frontend/vendor/mongodb/mongodb/tests/TestCase.php, line 164
   Info: hash hash (used in hash) is insecure. Consider changing it to a secure hashing algorithm.

 ✗ [LOW] Use of Password Hash With Insufficient Computational Effort
   Path: challenge/frontend/vendor/aws/aws-sdk-php/tests/HashingStreamTest.php, line 18
   Info: MD5 hash (used in md5) is insecure. Consider changing it to a secure hashing algorithm.

 ✗ [LOW] Use of Password Hash With Insufficient Computational Effort
   Path: challenge/frontend/vendor/aws/aws-sdk-php/tests/HashingStreamTest.php, line 46
   Info: MD5 hash (used in md5) is insecure. Consider changing it to a secure hashing algorithm.

 ✗ [LOW] Use of Password Hash With Insufficient Computational Effort
   Path: challenge/frontend/vendor/aws/aws-sdk-php/tests/PhpHashTest.php, line 17
   Info: MD5 hash (used in md5) is insecure. Consider changing it to a secure hashing algorithm.

 ✗ [LOW] Use of Password Hash With Insufficient Computational Effort
   Path: challenge/frontend/vendor/aws/aws-sdk-php/tests/PhpHashTest.php, line 26
   Info: MD5 hash (used in md5) is insecure. Consider changing it to a secure hashing algorithm.

 ✗ [LOW] Use of Password Hash With Insufficient Computational Effort
   Path: challenge/frontend/vendor/aws/aws-sdk-php/tests/PhpHashTest.php, line 37
   Info: MD5 hash (used in md5) is insecure. Consider changing it to a secure hashing algorithm.

 ✗ [LOW] Use of Password Hash With Insufficient Computational Effort
   Path: challenge/frontend/vendor/aws/aws-sdk-php/tests/PhpHashTest.php, line 47
   Info: MD5 hash (used in md5) is insecure. Consider changing it to a secure hashing algorithm.

 ✗ [LOW] Use of Password Hash With Insufficient Computational Effort
   Path: challenge/frontend/vendor/aws/aws-sdk-php/tests/S3/SSECMiddlewareTest.php, line 48
   Info: MD5 hash (used in md5) is insecure. Consider changing it to a secure hashing algorithm.

 ✗ [LOW] Use of Password Hash With Insufficient Computational Effort
   Path: challenge/frontend/vendor/aws/aws-sdk-php/tests/S3/SSECMiddlewareTest.php, line 50
   Info: MD5 hash (used in md5) is insecure. Consider changing it to a secure hashing algorithm.

 ✗ [LOW] Use of Password Hash With Insufficient Computational Effort
   Path: challenge/frontend/vendor/guzzlehttp/psr7/tests/UtilsTest.php, line 157
   Info: MD5 hash (used in md5) is insecure. Consider changing it to a secure hashing algorithm.

 ✗ [LOW] Use of Password Hash With Insufficient Computational Effort
   Path: challenge/frontend/vendor/guzzlehttp/psr7/tests/UtilsTest.php, line 174
   Info: MD5 hash (used in md5) is insecure. Consider changing it to a secure hashing algorithm.

 ✗ [LOW] Use of Password Hash With Insufficient Computational Effort
   Path: challenge/frontend/vendor/guzzlehttp/psr7/tests/UploadedFileTest.php, line 262
   Info: SHA1 hash (used in sha1) is insecure. Consider changing it to a secure hashing algorithm.

 ✗ [LOW] Use of Hardcoded Credentials
   Path: challenge/frontend/vendor/guzzlehttp/psr7/tests/ServerRequestTest.php, line 340
   Info: Do not hardcode credentials in code. Found a hardcoded credential used in an URL.

 ✗ [LOW] Use of Hardcoded Credentials
   Path: challenge/frontend/vendor/guzzlehttp/psr7/tests/ServerRequestTest.php, line 336
   Info: Do not hardcode credentials in code. Found a hardcoded credential used in an URL.

 ✗ [LOW] Use of Hardcoded Credentials
   Path: challenge/frontend/vendor/guzzlehttp/psr7/tests/ServerRequestTest.php, line 332
   Info: Do not hardcode credentials in code. Found a hardcoded credential used in an URL.

 ✗ [LOW] Use of Hardcoded Credentials
   Path: challenge/frontend/vendor/guzzlehttp/psr7/tests/ServerRequestTest.php, line 328
   Info: Do not hardcode credentials in code. Found a hardcoded credential used in an URL.

 ✗ [LOW] Code Injection
   Path: challenge/backend/vendor/mongodb/mongodb/tests/Operation/WatchFunctionalTest.php, line 884
   Info: Unsanitized input from an HTTP parameter flows into assert, where it is executed as php code. This may result in a Code Injection vulnerability.

 ✗ [LOW] Use of Hardcoded Credentials
   Path: challenge/frontend/vendor/guzzlehttp/psr7/tests/ServerRequestTest.php, line 324
   Info: Do not hardcode credentials in code. Found a hardcoded credential used in an URL.

 ✗ [LOW] Use of Hardcoded Credentials
   Path: challenge/frontend/vendor/guzzlehttp/psr7/tests/ServerRequestTest.php, line 312
   Info: Do not hardcode credentials in code. Found a hardcoded credential used in an URL.

 ✗ [LOW] Use of Hardcoded Credentials
   Path: challenge/frontend/vendor/guzzlehttp/psr7/tests/ServerRequestTest.php, line 308
   Info: Do not hardcode credentials in code. Found a hardcoded credential used in an URL.

 ✗ [LOW] Use of Password Hash With Insufficient Computational Effort
   Path: challenge/frontend/vendor/guzzlehttp/guzzle/tests/server.js, line 58
   Info: crypto.createHash hash (used in crypto.createHash) is insecure. Consider changing it to a secure hashing algorithm.

 ✗ [LOW] Path Traversal
   Path: challenge/frontend/vendor/guzzlehttp/psr7/tests/UploadedFileTest.php, line 76
   Info: Unsanitized input from data from a remote resource flows into move_uploaded_file, where it is used as a path. This may result in a Path Traversal vulnerability and allow an attacker to move arbitrary files.

 ✗ [LOW] Path Traversal
   Path: challenge/frontend/vendor/guzzlehttp/psr7/tests/UploadedFileTest.php, line 101
   Info: Unsanitized input from data from a remote resource flows into move_uploaded_file, where it is used as a path. This may result in a Path Traversal vulnerability and allow an attacker to move arbitrary files.

 ✗ [LOW] Path Traversal
   Path: challenge/frontend/vendor/guzzlehttp/psr7/tests/UploadedFileTest.php, line 123
   Info: Unsanitized input from data from a remote resource flows into move_uploaded_file, where it is used as a path. This may result in a Path Traversal vulnerability and allow an attacker to move arbitrary files.

 ✗ [LOW] Path Traversal
   Path: challenge/frontend/vendor/guzzlehttp/psr7/tests/UploadedFileTest.php, line 133
   Info: Unsanitized input from data from a remote resource flows into move_uploaded_file, where it is used as a path. This may result in a Path Traversal vulnerability and allow an attacker to move arbitrary files.

 ✗ [LOW] Path Traversal
   Path: challenge/frontend/vendor/guzzlehttp/psr7/tests/UploadedFileTest.php, line 147
   Info: Unsanitized input from data from a remote resource flows into move_uploaded_file, where it is used as a path. This may result in a Path Traversal vulnerability and allow an attacker to move arbitrary files.

 ✗ [LOW] Path Traversal
   Path: challenge/frontend/vendor/monolog/monolog/tests/Monolog/Handler/StreamHandlerTest.php, line 27
   Info: Unsanitized input from data from a remote resource flows into fopen, where it is used as a path. This may result in a Path Traversal vulnerability and allow an attacker to open arbitrary files.

 ✗ [LOW] Path Traversal
   Path: challenge/frontend/vendor/monolog/monolog/tests/Monolog/Handler/StreamHandlerTest.php, line 42
   Info: Unsanitized input from data from a remote resource flows into fopen, where it is used as a path. This may result in a Path Traversal vulnerability and allow an attacker to open arbitrary files.

 ✗ [LOW] Information Exposure - Server Error Message
   Path: challenge/backend/vendor/mongodb/mongodb/tests/DocumentationExamplesTest.php, line 1764
   Info: An exception object flows to the echo statement and is leaked to the attacker. This may disclose important information about the application to an attacker.

 ✗ [LOW] Information Exposure - Server Error Message
   Path: challenge/frontend/vendor/aws/aws-sdk-php/features/bootstrap/Aws/Test/Integ/S3Context.php, line 251
   Info: An exception object flows to the echo statement and is leaked to the attacker. This may disclose important information about the application to an attacker.

 ✗ [LOW] Information Exposure - Server Error Message
   Path: challenge/frontend/vendor/aws/aws-sdk-php/tests/Integ/S3Context.php, line 251
   Info: An exception object flows to the echo statement and is leaked to the attacker. This may disclose important information about the application to an attacker.

 ✗ [LOW] Information Exposure - Server Error Message
   Path: challenge/frontend/vendor/mongodb/mongodb/tests/DocumentationExamplesTest.php, line 1764
   Info: An exception object flows to the echo statement and is leaked to the attacker. This may disclose important information about the application to an attacker.

 ✗ [LOW] Use of Hardcoded Credentials
   Path: challenge/frontend/vendor/guzzlehttp/psr7/tests/ServerRequestTest.php, line 304
   Info: Do not hardcode credentials in code. Found a hardcoded credential used in an URL.

 ✗ [LOW] Use of Hardcoded Credentials
   Path: challenge/frontend/vendor/guzzlehttp/psr7/tests/ServerRequestTest.php, line 300
   Info: Do not hardcode credentials in code. Found a hardcoded credential used in an URL.

 ✗ [LOW] Use of Hardcoded Credentials
   Path: challenge/frontend/vendor/guzzlehttp/psr7/tests/ServerRequestTest.php, line 296
   Info: Do not hardcode credentials in code. Found a hardcoded credential used in an URL.

 ✗ [LOW] Use of Hardcoded Credentials
   Path: challenge/frontend/vendor/aws/aws-sdk-php/tests/CognitoIdentity/CognitoIdentityProviderTest.php, line 50       
   Info: Do not hardcode credentials in code. Found a hardcoded credential used in updateLogin.

 ✗ [LOW] Code Injection
   Path: challenge/backend/vendor/mongodb/mongodb/tests/UnifiedSpecTests/Operation.php, line 164
   Info: Unsanitized input from data from a remote resource flows into assert, where it is executed as php code. This may result in a Code Injection vulnerability.

 ✗ [LOW] Code Injection
   Path: challenge/frontend/vendor/mongodb/mongodb/tests/Operation/WatchFunctionalTest.php, line 1524
   Info: Unsanitized input from an HTTP parameter flows into assert, where it is executed as php code. This may result in a Code Injection vulnerability.

 ✗ [LOW] Cross-site Scripting (XSS)
   Path: challenge/frontend/vendor/guzzlehttp/guzzle/tests/server.js, line 206
   Info: Unsanitized input from the HTTP request body flows into end, where it is used to render an HTML page returned to the user. This may result in a Cross-Site Scripting attack (XSS).

 ✗ [LOW] Code Injection
   Path: challenge/backend/vendor/mongodb/mongodb/tests/Operation/CountDocumentsFunctionalTest.php, line 13
   Info: Unsanitized input from an HTTP parameter flows into assert, where it is executed as php code. This may result in a Code Injection vulnerability.

 ✗ [LOW] Code Injection
   Path: challenge/backend/vendor/mongodb/mongodb/tests/Operation/CountDocumentsFunctionalTest.php, line 27
   Info: Unsanitized input from an HTTP parameter flows into assert, where it is executed as php code. This may result in a Code Injection vulnerability.

 ✗ [LOW] Code Injection
   Path: challenge/backend/vendor/mongodb/mongodb/tests/Operation/MapReduceFunctionalTest.php, line 42
   Info: Unsanitized input from an HTTP parameter flows into assert, where it is executed as php code. This may result in a Code Injection vulnerability.

 ✗ [LOW] Code Injection
   Path: challenge/backend/vendor/mongodb/mongodb/tests/Operation/MapReduceFunctionalTest.php, line 66
   Info: Unsanitized input from an HTTP parameter flows into assert, where it is executed as php code. This may result in a Code Injection vulnerability.

 ✗ [LOW] Code Injection
   Path: challenge/backend/vendor/mongodb/mongodb/tests/Operation/MapReduceFunctionalTest.php, line 74
   Info: Unsanitized input from an HTTP parameter flows into assert, where it is executed as php code. This may result in a Code Injection vulnerability.

 ✗ [LOW] Code Injection
   Path: challenge/backend/vendor/mongodb/mongodb/tests/Operation/MapReduceFunctionalTest.php, line 87
   Info: Unsanitized input from an HTTP parameter flows into assert, where it is executed as php code. This may result in a Code Injection vulnerability.

 ✗ [LOW] Code Injection
   Path: challenge/backend/vendor/mongodb/mongodb/tests/Operation/MapReduceFunctionalTest.php, line 101
   Info: Unsanitized input from an HTTP parameter flows into assert, where it is executed as php code. This may result in a Code Injection vulnerability.

 ✗ [LOW] Code Injection
   Path: challenge/backend/vendor/mongodb/mongodb/tests/Operation/MapReduceFunctionalTest.php, line 124
   Info: Unsanitized input from an HTTP parameter flows into assert, where it is executed as php code. This may result in a Code Injection vulnerability.

 ✗ [LOW] Code Injection
   Path: challenge/backend/vendor/mongodb/mongodb/tests/Operation/MapReduceFunctionalTest.php, line 145
   Info: Unsanitized input from an HTTP parameter flows into assert, where it is executed as php code. This may result in a Code Injection vulnerability.

 ✗ [LOW] Cleartext Transmission - HTTP Instead of HTTPS
   Path: challenge/frontend/vendor/guzzlehttp/guzzle/tests/server.js, line 212
   Info: http.createServer uses HTTP which is an insecure protocol and should not be used in code due to cleartext transmission of information. Data in cleartext in a communication channel can be sniffed by unauthorized actors. Consider using the https module instead.

 ✗ [LOW] Code Injection
   Path: challenge/backend/vendor/mongodb/mongodb/tests/Operation/MapReduceFunctionalTest.php, line 191
   Info: Unsanitized input from an HTTP parameter flows into assert, where it is executed as php code. This may result in a Code Injection vulnerability.

 ✗ [LOW] Code Injection
   Path: challenge/backend/vendor/mongodb/mongodb/tests/Operation/MapReduceFunctionalTest.php, line 215
   Info: Unsanitized input from an HTTP parameter flows into assert, where it is executed as php code. This may result in a Code Injection vulnerability.

 ✗ [LOW] Code Injection
   Path: challenge/backend/vendor/mongodb/mongodb/tests/Operation/MapReduceFunctionalTest.php, line 235
   Info: Unsanitized input from an HTTP parameter flows into assert, where it is executed as php code. This may result in a Code Injection vulnerability.

 ✗ [LOW] Code Injection
   Path: challenge/backend/vendor/mongodb/mongodb/tests/Operation/MapReduceFunctionalTest.php, line 282
   Info: Unsanitized input from an HTTP parameter flows into assert, where it is executed as php code. This may result in a Code Injection vulnerability.

 ✗ [LOW] Code Injection
   Path: challenge/backend/vendor/mongodb/mongodb/tests/Operation/MapReduceFunctionalTest.php, line 287
   Info: Unsanitized input from an HTTP parameter flows into assert, where it is executed as php code. This may result in a Code Injection vulnerability.

 ✗ [LOW] Code Injection
   Path: challenge/backend/vendor/mongodb/mongodb/tests/Operation/MapReduceFunctionalTest.php, line 292
   Info: Unsanitized input from an HTTP parameter flows into assert, where it is executed as php code. This may result in a Code Injection vulnerability.

 ✗ [LOW] Code Injection
   Path: challenge/backend/vendor/mongodb/mongodb/tests/Operation/WatchFunctionalTest.php, line 69
   Info: Unsanitized input from an HTTP parameter flows into assert, where it is executed as php code. This may result in a Code Injection vulnerability.

 ✗ [LOW] Code Injection
   Path: challenge/backend/vendor/mongodb/mongodb/tests/Operation/WatchFunctionalTest.php, line 171
   Info: Unsanitized input from an HTTP parameter flows into assert, where it is executed as php code. This may result in a Code Injection vulnerability.

 ✗ [LOW] Code Injection
   Path: challenge/backend/vendor/mongodb/mongodb/tests/Operation/WatchFunctionalTest.php, line 358
   Info: Unsanitized input from an HTTP parameter flows into assert, where it is executed as php code. This may result in a Code Injection vulnerability.

 ✗ [LOW] Code Injection
   Path: challenge/backend/vendor/mongodb/mongodb/tests/Operation/WatchFunctionalTest.php, line 405
   Info: Unsanitized input from an HTTP parameter flows into assert, where it is executed as php code. This may result in a Code Injection vulnerability.

 ✗ [LOW] Code Injection
   Path: challenge/backend/vendor/mongodb/mongodb/tests/Operation/WatchFunctionalTest.php, line 440
   Info: Unsanitized input from an HTTP parameter flows into assert, where it is executed as php code. This may result in a Code Injection vulnerability.

 ✗ [LOW] Code Injection
   Path: challenge/backend/vendor/mongodb/mongodb/tests/Operation/WatchFunctionalTest.php, line 486
   Info: Unsanitized input from an HTTP parameter flows into assert, where it is executed as php code. This may result in a Code Injection vulnerability.

 ✗ [LOW] Code Injection
   Path: challenge/backend/vendor/mongodb/mongodb/tests/Operation/WatchFunctionalTest.php, line 605
   Info: Unsanitized input from an HTTP parameter flows into assert, where it is executed as php code. This may result in a Code Injection vulnerability.

 ✗ [LOW] Code Injection
   Path: challenge/backend/vendor/mongodb/mongodb/tests/Operation/WatchFunctionalTest.php, line 646
   Info: Unsanitized input from an HTTP parameter flows into assert, where it is executed as php code. This may result in a Code Injection vulnerability.

 ✗ [LOW] Code Injection
   Path: challenge/backend/vendor/mongodb/mongodb/tests/Operation/WatchFunctionalTest.php, line 671
   Info: Unsanitized input from an HTTP parameter flows into assert, where it is executed as php code. This may result in a Code Injection vulnerability.

 ✗ [LOW] Code Injection
   Path: challenge/backend/vendor/mongodb/mongodb/tests/Operation/WatchFunctionalTest.php, line 709
   Info: Unsanitized input from an HTTP parameter flows into assert, where it is executed as php code. This may result in a Code Injection vulnerability.

 ✗ [LOW] Code Injection
   Path: challenge/backend/vendor/mongodb/mongodb/tests/Operation/WatchFunctionalTest.php, line 737
   Info: Unsanitized input from an HTTP parameter flows into assert, where it is executed as php code. This may result in a Code Injection vulnerability.

 ✗ [LOW] Code Injection
   Path: challenge/backend/vendor/mongodb/mongodb/tests/Operation/WatchFunctionalTest.php, line 760
   Info: Unsanitized input from an HTTP parameter flows into assert, where it is executed as php code. This may result in a Code Injection vulnerability.

 ✗ [LOW] Code Injection
   Path: challenge/backend/vendor/mongodb/mongodb/tests/Operation/WatchFunctionalTest.php, line 788
   Info: Unsanitized input from an HTTP parameter flows into assert, where it is executed as php code. This may result in a Code Injection vulnerability.

 ✗ [LOW] Code Injection
   Path: challenge/backend/vendor/mongodb/mongodb/tests/Operation/MapReduceFunctionalTest.php, line 168
   Info: Unsanitized input from an HTTP parameter flows into assert, where it is executed as php code. This may result in a Code Injection vulnerability.

 ✗ [LOW] Use of Password Hash With Insufficient Computational Effort
   Path: challenge/backend/vendor/mongodb/mongodb/src/GridFS/WritableStream.php, line 143
   Info: hash_init hash (used in hash_init) is insecure. Consider changing it to a secure hashing algorithm.

 ✗ [LOW] Code Injection
   Path: challenge/frontend/vendor/mongodb/mongodb/tests/Operation/WatchFunctionalTest.php, line 1515
   Info: Unsanitized input from an HTTP parameter flows into assert, where it is executed as php code. This may result in a Code Injection vulnerability.

 ✗ [LOW] Code Injection
   Path: challenge/backend/vendor/mongodb/mongodb/tests/Operation/WatchFunctionalTest.php, line 926
   Info: Unsanitized input from an HTTP parameter flows into assert, where it is executed as php code. This may result in a Code Injection vulnerability.

 ✗ [LOW] Code Injection
   Path: challenge/backend/vendor/mongodb/mongodb/tests/Operation/WatchFunctionalTest.php, line 940
   Info: Unsanitized input from an HTTP parameter flows into assert, where it is executed as php code. This may result in a Code Injection vulnerability.

 ✗ [LOW] Code Injection
   Path: challenge/backend/vendor/mongodb/mongodb/tests/Operation/WatchFunctionalTest.php, line 972
   Info: Unsanitized input from an HTTP parameter flows into assert, where it is executed as php code. This may result in a Code Injection vulnerability.

 ✗ [LOW] Code Injection
   Path: challenge/backend/vendor/mongodb/mongodb/tests/Operation/WatchFunctionalTest.php, line 986
   Info: Unsanitized input from an HTTP parameter flows into assert, where it is executed as php code. This may result in a Code Injection vulnerability.

 ✗ [LOW] Code Injection
   Path: challenge/backend/vendor/mongodb/mongodb/tests/Operation/WatchFunctionalTest.php, line 1017
   Info: Unsanitized input from an HTTP parameter flows into assert, where it is executed as php code. This may result in a Code Injection vulnerability.

 ✗ [LOW] Code Injection
   Path: challenge/backend/vendor/mongodb/mongodb/tests/Operation/WatchFunctionalTest.php, line 1066
   Info: Unsanitized input from an HTTP parameter flows into assert, where it is executed as php code. This may result in a Code Injection vulnerability.

 ✗ [LOW] Code Injection
   Path: challenge/backend/vendor/mongodb/mongodb/tests/Operation/WatchFunctionalTest.php, line 1087
   Info: Unsanitized input from an HTTP parameter flows into assert, where it is executed as php code. This may result in a Code Injection vulnerability.

 ✗ [LOW] Code Injection
   Path: challenge/backend/vendor/mongodb/mongodb/tests/Operation/WatchFunctionalTest.php, line 1186
   Info: Unsanitized input from an HTTP parameter flows into assert, where it is executed as php code. This may result in a Code Injection vulnerability.

 ✗ [LOW] Code Injection
   Path: challenge/backend/vendor/mongodb/mongodb/tests/Operation/WatchFunctionalTest.php, line 1373
   Info: Unsanitized input from an HTTP parameter flows into assert, where it is executed as php code. This may result in a Code Injection vulnerability.

 ✗ [LOW] Code Injection
   Path: challenge/backend/vendor/mongodb/mongodb/tests/Operation/WatchFunctionalTest.php, line 1386
   Info: Unsanitized input from an HTTP parameter flows into assert, where it is executed as php code. This may result in a Code Injection vulnerability.

 ✗ [LOW] Code Injection
   Path: challenge/backend/vendor/mongodb/mongodb/tests/Operation/WatchFunctionalTest.php, line 1436
   Info: Unsanitized input from an HTTP parameter flows into assert, where it is executed as php code. This may result in a Code Injection vulnerability.

 ✗ [LOW] Code Injection
   Path: challenge/backend/vendor/mongodb/mongodb/tests/Operation/WatchFunctionalTest.php, line 1443
   Info: Unsanitized input from an HTTP parameter flows into assert, where it is executed as php code. This may result in a Code Injection vulnerability.

 ✗ [LOW] Code Injection
   Path: challenge/backend/vendor/mongodb/mongodb/tests/Operation/WatchFunctionalTest.php, line 1450
   Info: Unsanitized input from an HTTP parameter flows into assert, where it is executed as php code. This may result in a Code Injection vulnerability.

 ✗ [LOW] Code Injection
   Path: challenge/backend/vendor/mongodb/mongodb/tests/Operation/WatchFunctionalTest.php, line 1468
   Info: Unsanitized input from an HTTP parameter flows into assert, where it is executed as php code. This may result in a Code Injection vulnerability.

 ✗ [LOW] Code Injection
   Path: challenge/backend/vendor/mongodb/mongodb/tests/Operation/WatchFunctionalTest.php, line 1478
   Info: Unsanitized input from an HTTP parameter flows into assert, where it is executed as php code. This may result in a Code Injection vulnerability.

 ✗ [LOW] Code Injection
   Path: challenge/backend/vendor/mongodb/mongodb/tests/Operation/WatchFunctionalTest.php, line 1515
   Info: Unsanitized input from an HTTP parameter flows into assert, where it is executed as php code. This may result in a Code Injection vulnerability.

 ✗ [LOW] Code Injection
   Path: challenge/backend/vendor/mongodb/mongodb/tests/Operation/WatchFunctionalTest.php, line 1524
   Info: Unsanitized input from an HTTP parameter flows into assert, where it is executed as php code. This may result in a Code Injection vulnerability.

 ✗ [LOW] Code Injection
   Path: challenge/frontend/vendor/mongodb/mongodb/tests/Operation/CountDocumentsFunctionalTest.php, line 13
   Info: Unsanitized input from an HTTP parameter flows into assert, where it is executed as php code. This may result in a Code Injection vulnerability.

 ✗ [LOW] Code Injection
   Path: challenge/frontend/vendor/mongodb/mongodb/tests/Operation/CountDocumentsFunctionalTest.php, line 27
   Info: Unsanitized input from an HTTP parameter flows into assert, where it is executed as php code. This may result in a Code Injection vulnerability.

 ✗ [LOW] Code Injection
   Path: challenge/frontend/vendor/mongodb/mongodb/tests/Operation/MapReduceFunctionalTest.php, line 42
   Info: Unsanitized input from an HTTP parameter flows into assert, where it is executed as php code. This may result in a Code Injection vulnerability.

 ✗ [LOW] Code Injection
   Path: challenge/frontend/vendor/mongodb/mongodb/tests/Operation/MapReduceFunctionalTest.php, line 66
   Info: Unsanitized input from an HTTP parameter flows into assert, where it is executed as php code. This may result in a Code Injection vulnerability.

 ✗ [LOW] Code Injection
   Path: challenge/frontend/vendor/mongodb/mongodb/tests/Operation/MapReduceFunctionalTest.php, line 74
   Info: Unsanitized input from an HTTP parameter flows into assert, where it is executed as php code. This may result in a Code Injection vulnerability.

 ✗ [LOW] Code Injection
   Path: challenge/frontend/vendor/mongodb/mongodb/tests/Operation/MapReduceFunctionalTest.php, line 87
   Info: Unsanitized input from an HTTP parameter flows into assert, where it is executed as php code. This may result in a Code Injection vulnerability.

 ✗ [LOW] Code Injection
   Path: challenge/frontend/vendor/mongodb/mongodb/tests/Operation/MapReduceFunctionalTest.php, line 101
   Info: Unsanitized input from an HTTP parameter flows into assert, where it is executed as php code. This may result in a Code Injection vulnerability.

 ✗ [LOW] Code Injection
   Path: challenge/frontend/vendor/mongodb/mongodb/tests/Operation/MapReduceFunctionalTest.php, line 124
   Info: Unsanitized input from an HTTP parameter flows into assert, where it is executed as php code. This may result in a Code Injection vulnerability.

 ✗ [LOW] Code Injection
   Path: challenge/frontend/vendor/mongodb/mongodb/tests/Operation/MapReduceFunctionalTest.php, line 145
   Info: Unsanitized input from an HTTP parameter flows into assert, where it is executed as php code. This may result in a Code Injection vulnerability.

 ✗ [LOW] Code Injection
   Path: challenge/frontend/vendor/mongodb/mongodb/tests/Operation/MapReduceFunctionalTest.php, line 168
   Info: Unsanitized input from an HTTP parameter flows into assert, where it is executed as php code. This may result in a Code Injection vulnerability.

 ✗ [LOW] Code Injection
   Path: challenge/frontend/vendor/mongodb/mongodb/tests/Operation/MapReduceFunctionalTest.php, line 191
   Info: Unsanitized input from an HTTP parameter flows into assert, where it is executed as php code. This may result in a Code Injection vulnerability.

 ✗ [LOW] Code Injection
   Path: challenge/frontend/vendor/mongodb/mongodb/tests/Operation/MapReduceFunctionalTest.php, line 215
   Info: Unsanitized input from an HTTP parameter flows into assert, where it is executed as php code. This may result in a Code Injection vulnerability.

 ✗ [LOW] Code Injection
   Path: challenge/frontend/vendor/mongodb/mongodb/tests/Operation/MapReduceFunctionalTest.php, line 235
   Info: Unsanitized input from an HTTP parameter flows into assert, where it is executed as php code. This may result in a Code Injection vulnerability.

 ✗ [LOW] Code Injection
   Path: challenge/frontend/vendor/mongodb/mongodb/tests/Operation/MapReduceFunctionalTest.php, line 282
   Info: Unsanitized input from an HTTP parameter flows into assert, where it is executed as php code. This may result in a Code Injection vulnerability.

 ✗ [LOW] Code Injection
   Path: challenge/frontend/vendor/mongodb/mongodb/tests/Operation/MapReduceFunctionalTest.php, line 287
   Info: Unsanitized input from an HTTP parameter flows into assert, where it is executed as php code. This may result in a Code Injection vulnerability.

 ✗ [LOW] Code Injection
   Path: challenge/frontend/vendor/mongodb/mongodb/tests/Operation/MapReduceFunctionalTest.php, line 292
   Info: Unsanitized input from an HTTP parameter flows into assert, where it is executed as php code. This may result in a Code Injection vulnerability.

 ✗ [LOW] Code Injection
   Path: challenge/frontend/vendor/mongodb/mongodb/tests/Operation/WatchFunctionalTest.php, line 69
   Info: Unsanitized input from an HTTP parameter flows into assert, where it is executed as php code. This may result in a Code Injection vulnerability.

 ✗ [LOW] Code Injection
   Path: challenge/frontend/vendor/mongodb/mongodb/tests/Operation/WatchFunctionalTest.php, line 171
   Info: Unsanitized input from an HTTP parameter flows into assert, where it is executed as php code. This may result in a Code Injection vulnerability.

 ✗ [LOW] Code Injection
   Path: challenge/frontend/vendor/mongodb/mongodb/tests/Operation/WatchFunctionalTest.php, line 358
   Info: Unsanitized input from an HTTP parameter flows into assert, where it is executed as php code. This may result in a Code Injection vulnerability.

 ✗ [LOW] Code Injection
   Path: challenge/frontend/vendor/mongodb/mongodb/tests/Operation/WatchFunctionalTest.php, line 405
   Info: Unsanitized input from an HTTP parameter flows into assert, where it is executed as php code. This may result in a Code Injection vulnerability.

 ✗ [LOW] Code Injection
   Path: challenge/frontend/vendor/mongodb/mongodb/tests/Operation/WatchFunctionalTest.php, line 440
   Info: Unsanitized input from an HTTP parameter flows into assert, where it is executed as php code. This may result in a Code Injection vulnerability.

 ✗ [LOW] Code Injection
   Path: challenge/frontend/vendor/mongodb/mongodb/tests/Operation/WatchFunctionalTest.php, line 486
   Info: Unsanitized input from an HTTP parameter flows into assert, where it is executed as php code. This may result in a Code Injection vulnerability.

 ✗ [LOW] Code Injection
   Path: challenge/frontend/vendor/mongodb/mongodb/tests/Operation/WatchFunctionalTest.php, line 605
   Info: Unsanitized input from an HTTP parameter flows into assert, where it is executed as php code. This may result in a Code Injection vulnerability.

 ✗ [LOW] Code Injection
   Path: challenge/frontend/vendor/mongodb/mongodb/tests/Operation/WatchFunctionalTest.php, line 646
   Info: Unsanitized input from an HTTP parameter flows into assert, where it is executed as php code. This may result in a Code Injection vulnerability.

 ✗ [LOW] Code Injection
   Path: challenge/frontend/vendor/mongodb/mongodb/tests/Operation/WatchFunctionalTest.php, line 671
   Info: Unsanitized input from an HTTP parameter flows into assert, where it is executed as php code. This may result in a Code Injection vulnerability.

 ✗ [LOW] Code Injection
   Path: challenge/frontend/vendor/mongodb/mongodb/tests/Operation/WatchFunctionalTest.php, line 709
   Info: Unsanitized input from an HTTP parameter flows into assert, where it is executed as php code. This may result in a Code Injection vulnerability.

 ✗ [LOW] Code Injection
   Path: challenge/frontend/vendor/mongodb/mongodb/tests/Operation/WatchFunctionalTest.php, line 737
   Info: Unsanitized input from an HTTP parameter flows into assert, where it is executed as php code. This may result in a Code Injection vulnerability.

 ✗ [LOW] Code Injection
   Path: challenge/frontend/vendor/mongodb/mongodb/tests/Operation/WatchFunctionalTest.php, line 760
   Info: Unsanitized input from an HTTP parameter flows into assert, where it is executed as php code. This may result in a Code Injection vulnerability.

 ✗ [LOW] Code Injection
   Path: challenge/frontend/vendor/mongodb/mongodb/tests/Operation/WatchFunctionalTest.php, line 788
   Info: Unsanitized input from an HTTP parameter flows into assert, where it is executed as php code. This may result in a Code Injection vulnerability.

 ✗ [LOW] Code Injection
   Path: challenge/frontend/vendor/mongodb/mongodb/tests/Operation/WatchFunctionalTest.php, line 815
   Info: Unsanitized input from an HTTP parameter flows into assert, where it is executed as php code. This may result in a Code Injection vulnerability.

 ✗ [LOW] Code Injection
   Path: challenge/frontend/vendor/mongodb/mongodb/tests/Operation/WatchFunctionalTest.php, line 866
   Info: Unsanitized input from an HTTP parameter flows into assert, where it is executed as php code. This may result in a Code Injection vulnerability.

 ✗ [LOW] Code Injection
   Path: challenge/frontend/vendor/mongodb/mongodb/tests/Operation/WatchFunctionalTest.php, line 884
   Info: Unsanitized input from an HTTP parameter flows into assert, where it is executed as php code. This may result in a Code Injection vulnerability.

 ✗ [LOW] Code Injection
   Path: challenge/frontend/vendor/mongodb/mongodb/tests/Operation/WatchFunctionalTest.php, line 926
   Info: Unsanitized input from an HTTP parameter flows into assert, where it is executed as php code. This may result in a Code Injection vulnerability.

 ✗ [LOW] Code Injection
   Path: challenge/frontend/vendor/mongodb/mongodb/tests/Operation/WatchFunctionalTest.php, line 940
   Info: Unsanitized input from an HTTP parameter flows into assert, where it is executed as php code. This may result in a Code Injection vulnerability.

 ✗ [LOW] Code Injection
   Path: challenge/frontend/vendor/mongodb/mongodb/tests/Operation/WatchFunctionalTest.php, line 972
   Info: Unsanitized input from an HTTP parameter flows into assert, where it is executed as php code. This may result in a Code Injection vulnerability.

 ✗ [LOW] Code Injection
   Path: challenge/frontend/vendor/mongodb/mongodb/tests/Operation/WatchFunctionalTest.php, line 986
   Info: Unsanitized input from an HTTP parameter flows into assert, where it is executed as php code. This may result in a Code Injection vulnerability.

 ✗ [LOW] Code Injection
   Path: challenge/frontend/vendor/mongodb/mongodb/tests/Operation/WatchFunctionalTest.php, line 1017
   Info: Unsanitized input from an HTTP parameter flows into assert, where it is executed as php code. This may result in a Code Injection vulnerability.

 ✗ [LOW] Code Injection
   Path: challenge/frontend/vendor/mongodb/mongodb/tests/Operation/WatchFunctionalTest.php, line 1066
   Info: Unsanitized input from an HTTP parameter flows into assert, where it is executed as php code. This may result in a Code Injection vulnerability.

 ✗ [LOW] Code Injection
   Path: challenge/frontend/vendor/mongodb/mongodb/tests/Operation/WatchFunctionalTest.php, line 1087
   Info: Unsanitized input from an HTTP parameter flows into assert, where it is executed as php code. This may result in a Code Injection vulnerability.

 ✗ [LOW] Code Injection
   Path: challenge/frontend/vendor/mongodb/mongodb/tests/Operation/WatchFunctionalTest.php, line 1186
   Info: Unsanitized input from an HTTP parameter flows into assert, where it is executed as php code. This may result in a Code Injection vulnerability.

 ✗ [LOW] Code Injection
   Path: challenge/frontend/vendor/mongodb/mongodb/tests/Operation/WatchFunctionalTest.php, line 1373
   Info: Unsanitized input from an HTTP parameter flows into assert, where it is executed as php code. This may result in a Code Injection vulnerability.

 ✗ [LOW] Code Injection
   Path: challenge/frontend/vendor/mongodb/mongodb/tests/Operation/WatchFunctionalTest.php, line 1386
   Info: Unsanitized input from an HTTP parameter flows into assert, where it is executed as php code. This may result in a Code Injection vulnerability.

 ✗ [LOW] Code Injection
   Path: challenge/frontend/vendor/mongodb/mongodb/tests/Operation/WatchFunctionalTest.php, line 1436
   Info: Unsanitized input from an HTTP parameter flows into assert, where it is executed as php code. This may result in a Code Injection vulnerability.

 ✗ [LOW] Code Injection
   Path: challenge/frontend/vendor/mongodb/mongodb/tests/Operation/WatchFunctionalTest.php, line 1443
   Info: Unsanitized input from an HTTP parameter flows into assert, where it is executed as php code. This may result in a Code Injection vulnerability.

 ✗ [LOW] Code Injection
   Path: challenge/frontend/vendor/mongodb/mongodb/tests/Operation/WatchFunctionalTest.php, line 1450
   Info: Unsanitized input from an HTTP parameter flows into assert, where it is executed as php code. This may result in a Code Injection vulnerability.

 ✗ [LOW] Code Injection
   Path: challenge/frontend/vendor/mongodb/mongodb/tests/Operation/WatchFunctionalTest.php, line 1468
   Info: Unsanitized input from an HTTP parameter flows into assert, where it is executed as php code. This may result in a Code Injection vulnerability.

 ✗ [LOW] Code Injection
   Path: challenge/frontend/vendor/mongodb/mongodb/tests/Operation/WatchFunctionalTest.php, line 1478
   Info: Unsanitized input from an HTTP parameter flows into assert, where it is executed as php code. This may result in a Code Injection vulnerability.

 ✗ [MEDIUM] DOM-based Cross-site Scripting (XSS)
   Path: challenge/frontend/static/js/shop.js, line 67
   Info: Unsanitized input from data from a remote resource flows into append, where it is used to dynamically construct the HTML page on client side. This may result in a DOM Based Cross-Site Scripting attack (DOMXSS).

 ✗ [MEDIUM] DOM-based Cross-site Scripting (XSS)
   Path: challenge/frontend/static/js/products.js, line 32
   Info: Unsanitized input from data from a remote resource flows into append, where it is used to dynamically construct the HTML page on client side. This may result in a DOM Based Cross-Site Scripting attack (DOMXSS).

 ✗ [MEDIUM] Use of Hardcoded Passwords
   Path: challenge/frontend/vendor/aws/aws-sdk-php/src/data/iam/2010-05-08/examples-1.json.php, line 3
   Info: Do not hardcode passwords in code. Found a hardcoded password used in variable.

 ✗ [MEDIUM] DOM-based Cross-site Scripting (XSS)
   Path: challenge/frontend/static/js/shop.js, line 68
   Info: Unsanitized input from data from a remote resource flows into append, where it is used to dynamically construct the HTML page on client side. This may result in a DOM Based Cross-Site Scripting attack (DOMXSS).

 ✗ [MEDIUM] Use of Hardcoded Passwords
   Path: challenge/frontend/vendor/aws/aws-sdk-php/src/data/iam/2010-05-08/examples-1.json.php, line 3
   Info: Do not hardcode passwords in code. Found a hardcoded password used in variable.

 ✗ [MEDIUM] Use of Hardcoded Passwords
   Path: challenge/frontend/vendor/aws/aws-sdk-php/src/data/iam/2010-05-08/examples-1.json.php, line 3
   Info: Do not hardcode passwords in code. Found a hardcoded password used in variable.

 ✗ [MEDIUM] Cross-site Scripting (XSS)
   Path: challenge/frontend/vendor/aws/aws-sdk-php/build/changelog/ChangelogBuilder.php, line 152
   Info: Unsanitized input from data from a remote resource flows into the echo statement, where it is used to render an HTML page returned to the user. This may result in a Cross-Site Scripting attack (XSS).

 ✗ [MEDIUM] Path Traversal
   Path: challenge/frontend/vendor/monolog/monolog/src/Monolog/Handler/StreamHandler.php, line 138
   Info: Unsanitized input from data from a remote resource flows into fopen, where it is used as a path. This may result in a Path Traversal vulnerability and allow an attacker to open arbitrary files.

 ✗ [MEDIUM] Open Redirect
   Path: challenge/frontend/vendor/aws/aws-sdk-php/build/docs/theme/js/main.js, line 83
   Info: Unsanitized input from the document location flows into window.location, where it is used as input for request redirection. This may result in an Open Redirect vulnerability.

 ✗ [MEDIUM] DOM-based Cross-site Scripting (XSS)
   Path: challenge/frontend/static/js/users.js, line 31
   Info: Unsanitized input from data from a remote resource flows into append, where it is used to dynamically construct the HTML page on client side. This may result in a DOM Based Cross-Site Scripting attack (DOMXSS).

 ✗ [MEDIUM] Use of Hardcoded Passwords
   Path: challenge/frontend/vendor/aws/aws-sdk-php/src/data/dms/2016-01-01/examples-1.json.php, line 3
   Info: Do not hardcode passwords in code. Found a hardcoded password used in variable.

 ✗ [MEDIUM] Path Traversal
   Path: challenge/frontend/vendor/aws/aws-sdk-php/build/changelog/ChangelogBuilder.php, line 106
   Info: Unsanitized input from data from a remote resource flows into fopen, where it is used as a path. This may result in a Path Traversal vulnerability and allow an attacker to open arbitrary files.

 ✗ [MEDIUM] Path Traversal
   Path: challenge/frontend/vendor/monolog/monolog/src/Monolog/Handler/StreamHandler.php, line 140
   Info: Unsanitized input from data from a remote resource flows into chmod, where it is used as a path. This may result in a Path Traversal vulnerability and allow an attacker to manipulate arbitrary files.

 ✗ [MEDIUM] DOM-based Cross-site Scripting (XSS)
   Path: challenge/frontend/static/js/users.js, line 84
   Info: Unsanitized input from data from a remote resource flows into append, where it is used to dynamically construct the HTML page on client side. This may result in a DOM Based Cross-Site Scripting attack (DOMXSS).

 ✗ [MEDIUM] DOM-based Cross-site Scripting (XSS)
   Path: challenge/frontend/static/js/orders.js, line 33
   Info: Unsanitized input from data from a remote resource flows into append, where it is used to dynamically construct the HTML page on client side. This may result in a DOM Based Cross-Site Scripting attack (DOMXSS).

 ✗ [HIGH] Cross-site Scripting (XSS)
   Path: challenge/backend/vendor/mongodb/mongodb/.evergreen/ocsp/mock_ocsp_responder.py, line 614
   Info: Unsanitized input from the HTTP request body flows into the return value of _handle_post, where it is used to render an HTML page returned to the user. This may result in a Cross-Site Scripting attack (XSS).

 ✗ [HIGH] Cross-site Scripting (XSS)
   Path: challenge/backend/vendor/mongodb/mongodb/.evergreen/ocsp/mock_ocsp_responder.py, line 604
   Info: Unsanitized input from an HTTP parameter flows into the return value of _handle_get, where it is used to render an HTML page returned to the user. This may result in a Cross-Site Scripting attack (XSS).

 ✗ [HIGH] Cross-site Scripting (XSS)
   Path: challenge/frontend/vendor/mongodb/mongodb/.evergreen/ocsp/mock_ocsp_responder.py, line 604
   Info: Unsanitized input from an HTTP parameter flows into the return value of _handle_get, where it is used to render an HTML page returned to the user. This may result in a Cross-Site Scripting attack (XSS).

 ✗ [HIGH] Cross-site Scripting (XSS)
   Path: challenge/frontend/vendor/mongodb/mongodb/.evergreen/ocsp/mock_ocsp_responder.py, line 614
   Info: Unsanitized input from the HTTP request body flows into the return value of _handle_post, where it is used to render an HTML page returned to the user. This may result in a Cross-Site Scripting attack (XSS).



╭─────────────────────────────────────────────────────────────────────────────────────────────────────╮
│ Test Summary                                                                                        │
│                                                                                                     │
│   Organization:      ______                                                                       │
│   Test type:         Static code analysis                                                           │
│   Project path:      \HTB Challenges\HARD\UnEarthly_Shop\web_unearthly_shop    │
│                                                                                                     │
│   Total issues:   170                                                                               │
│   Ignored issues: 0 [ 0 HIGH  0 MEDIUM  0 LOW ]                                                     │
│   Open issues:    170 [ 4 HIGH  15 MEDIUM  151 LOW ]                                                │
╰─────────────────────────────────────────────────────────────────────────────────────────────────────╯

💡 Tip

   To view ignored issues, use the --include-ignores option.



💡 Tip

   Some capabilities, including the ability to apply ignores, are unavailable. Retest the project with the --remote-repo-url parameter or from within a repository to enable full functionality.
```