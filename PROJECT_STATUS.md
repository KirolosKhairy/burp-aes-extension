# PROJECT STATUS

## Section 1: Project Overview

- Burp Suite Extension written in Java using the Montoya API.
- Transparently handles AES-CBC encrypted API traffic.
- Repository: https://github.com/KirolosKhairy/burp-aes-extension
- Primary goal: let Burp users view, edit, replay, log, and scan API traffic whose entire HTTP body is `Base64(AES-CBC ciphertext)`.

## Section 2: Architecture

### `src/main/java/burp/BurpAesExtension.java`

- Main Montoya extension entry point.
- Sets the extension name and registers every component at load time.
- Owns shared volatile configuration state:
  - AES key
  - AES IV
  - target host filter
- Loads and saves configuration through Burp extension persistence indirectly via `ConfigTab`.
- Creates the shared `CryptoHelper`.
- Registers:
  - `ConfigTab` as the `AES Config` suite tab.
  - `DecryptedMessageTabFactory` as request and response editor provider.
  - `AesHttpLogger` as the global HTTP handler.
  - `AesScanCheck` as the scanner insertion point provider.
  - `AesResponseScanCheck` as the scanner check.
- Maintains scanner request context in a `ConcurrentHashMap` so `AesHttpLogger` can repair scanner requests that Burp corrupts by injecting into ciphertext/Base64 instead of plaintext.

### `src/main/java/burp/CryptoHelper.java`

- Central AES utility used by the extension.
- Reads the current key and IV from `BurpAesExtension` at call time.
- Encrypts plaintext bytes to Base64 ciphertext.
- Decrypts Base64 ciphertext to plaintext bytes.
- Used by message tabs, scanner insertion points, response scan checks, and HTTP logging/encryption logic.

### `src/main/java/burp/ConfigTab.java`

- Swing UI for the `AES Config` suite tab.
- Lets the user configure AES key, IV, and target host.
- Validates key length and hex format:
  - key must be 32, 48, or 64 hex characters.
  - IV must be exactly 32 hex characters.
- Persists key, IV, and host via Burp extension persistence.
- Includes status display and saved configuration summary.
- Includes `Test Encryption` round-trip validation.
- Includes manual encrypt/decrypt panel for testing arbitrary text with the entered key and IV.
- Updates the shared `BurpAesExtension` state, which all other components read.

### `src/main/java/burp/DecryptedMessageTab.java`

- Custom `decrypted_message` editor tab for HTTP requests and responses.
- Implements both request and response editor interfaces.
- Host-gated: enabled only when the request host contains the configured target host.
- For requests:
  - HTTP History/read-only contexts show decrypted plaintext read-only.
  - Repeater/default editor contexts are editable.
  - `getRequest()` re-encrypts edited plaintext with `CryptoHelper.encrypt()` and returns a request with the encrypted body.
- For responses:
  - Always read-only.
  - Decrypts the response body for inspection.
- Shows clear UI status for success, failure, and non-encrypted bodies.
- If AES/Base64 decryption fails but the body is readable non-Base64 plaintext, displays it directly and sets status to `✓ Body displayed. Auto-encrypted before sending to server.`
- Base64-looking bodies that fail AES decryption are still treated as decryption failures so wrong-key/corrupt-ciphertext errors remain visible.

### `src/main/java/burp/DecryptedMessageTabFactory.java`

- Factory registered by `BurpAesExtension`.
- Creates request tabs and response tabs.
- Request tabs are editable only when Burp creates the editor in `EditorMode.DEFAULT` (Repeater).
- Request tabs in read-only modes and all response tabs are read-only.

### `src/main/java/burp/AesScanCheck.java`

- Scanner insertion point provider.
- Host-gated by the configured target host.
- Decrypts the encrypted request body before active scanning.
- Extracts insertion points from plaintext JSON and form-encoded bodies.
- JSON extraction currently supports string, numeric, and boolean leaf values using regex-based parsing.
- Form extraction supports `key=value&key2=value2`.
- Calls `extension.rememberScanRequest()` so the HTTP handler can later repair scanner mutations to the encrypted/Base64 body.
- Produces `AesInsertionPoint` instances for Burp Scanner.

### `src/main/java/burp/AesInsertionPoint.java`

- Represents one scanner insertion point inside the decrypted plaintext body.
- Receives Burp's payload bytes.
- Splices the payload into the original plaintext body at tracked offsets.
- Re-encrypts the modified plaintext using `CryptoHelper`.
- Returns a new request with the encrypted body.
- Adds marker header `X-AES-Scanner-Handled: 1` so `AesHttpLogger` can identify extension-handled scanner traffic and strip the marker before sending.
- Stores the last payload so `AesResponseScanCheck` can correlate probes with decrypted responses.

### `src/main/java/burp/AesResponseScanCheck.java`

- Scanner check that analyzes decrypted responses.
- Host-gated by configured target host.
- Passive audit:
  - decrypts response bodies.
  - looks for SQL error disclosure and stack trace disclosure in plaintext.
- Active audit:
  - sends reflection, SQL error, and stack trace probes through insertion points.
  - decrypts attack responses.
  - creates Burp `AuditIssue` objects with decrypted evidence markers.
- Uses Montoya `api.http().sendRequest()` for active probes.
- Does not feed synthetic plaintext responses into Burp built-in scanners; it creates extension-owned issues instead.

### `src/main/java/burp/AesHttpLogger.java`

- Global HTTP handler registered by `BurpAesExtension`.
- Handles every request and response passing through Burp.
- Host-gated by configured target host.
- Requests:
  - strips scanner marker header.
  - if body decrypts successfully, logs plaintext preview and highlights the row.
  - if scanner traffic appears corrupted by ciphertext/Base64 mutation, attempts to repair it using remembered scanner context.
  - otherwise attempts to encrypt plaintext body before sending.
- Confirmed to encrypt plaintext request bodies before they leave Burp; the server receives ciphertext.
- Auto-encrypted requests are highlighted and annotated with note `Auto-encrypted by AES Traffic Decryptor`.
- Proxy HTTP History can still show the original plaintext because Burp records what the client sent before this handler's outbound modification is reflected in History.
- Responses:
  - attempts to decrypt encrypted response body.
  - logs plaintext preview and highlights matching traffic.
  - never modifies response body.

### `build.gradle`

- Java Gradle build.
- Java source and target compatibility are set to 11.
- Uses `mavenCentral()`.
- Burp dependency is local and compile-only:
  - `compileOnly files('/usr/share/burpsuite/burpsuite.jar')`
- Produces `build/libs/burp-aes-extension.jar`.
- Must remain compatible with Gradle 4.x–9.x.

## Section 3: Technical Specs

- Algorithm: `AES/CBC/PKCS5Padding`
- Key: hex string, 32/48/64 chars
- IV: hex string, 32 chars
- Body format: `Base64(AES-encrypted bytes)`
- Build: Gradle, must work 4.x–9.x
- Java: 11+
- Dependency: `compileOnly files('/usr/share/burpsuite/burpsuite.jar')`
- Target filtering: all extension features should only process traffic whose request host contains the configured target host string.

## Section 4: What Works (Tested & Confirmed)

- Config Tab with validation, persistence, test encryption
- `decrypted_message` tab in HTTP History (read-only)
- `decrypted_message` tab in Repeater (editable, auto re-encrypt on Send)
- Host filtering across all components
- HTTP Logger with highlight
- Scanner insertion points (code written, tested with 15/15 repair tests)
- Scanner response analysis (code written)
- Crypto tests: 40/40 passed
- Scanner repair tests: 15/15 passed
- Manual Encrypt/Decrypt panel in Config Tab (tested, works)

## Section 5: Current Bug (CRITICAL — Must Fix Next)

The original auto-encrypt bug was in `AesHttpLogger.java`.

What should happen:

- ANY request going to the target host with a plaintext body should be automatically encrypted before leaving Burp.
- This applies to ALL tools: Scanner, API Scan, Intruder, Repeater, Proxy, etc.
- The server should only receive `Base64(AES-encrypted bytes)`.
- Burp Proxy HTTP History may show the original plaintext that the client sent; this is accepted because the server receives ciphertext.
- The `decrypted_message` tab should still show readable content for both encrypted bodies and plaintext history entries.

What actually happens:

- Initial result: plaintext bodies were sent to the server without encryption.
- After fixing `AesHttpLogger.java`, the server confirmed it receives encrypted bodies.
- Burp Proxy HTTP History still shows the original plaintext because it records what the client sent.
- Proxy handler attempts (`continueWith`, `doNotIntercept`, and raw request rebuilding) were removed because they did not change the History display.

Test that proved the bug:

- A request to the configured target host was sent with a plaintext body.
- Expected result: `AesHttpLogger.handleHttpRequestToBeSent()` should replace the body with AES-CBC encrypted Base64 before the request leaves Burp.
- Actual result: the plaintext body left Burp unchanged.
- Result: body arrived at server as plaintext, not encrypted.
- UI symptom: `decrypted_message` failed to decrypt the request and showed `Illegal base64 character 7b`.
- Server-side symptom: the server received the original plaintext body instead of encrypted Base64.

Follow-up test result:

- Server confirmed the body now arrives encrypted.
- Burp Proxy HTTP History still showed plaintext because proxy history was recorded before the `HttpHandler` modification.
- `decrypted_message` now displays readable plaintext history bodies directly instead of showing `Illegal base64 character 7b`, with status `✓ Body displayed. Auto-encrypted before sending to server.`
- Auto-encrypted requests get the History Notes annotation `Auto-encrypted by AES Traffic Decryptor`.

The fix needed in `handleHttpRequestToBeSent()`:

1. Check if request host matches target host.
2. Get request body.
3. Try Base64-decode and decrypt to check whether the body is already encrypted.
4. If decrypt succeeds, the body is already encrypted: pass through.
5. If decrypt fails, treat the body as plaintext: encrypt with `CryptoHelper` and replace the body.
6. Return the modified request.

Final accepted architecture:

- `AesProxyRequestHandler` was removed.
- `AesHttpLogger` remains responsible for encrypting outbound requests before they reach the server.
- `DecryptedMessageTab` handles plaintext bodies gracefully when HTTP History shows the client-side plaintext request.
- `AutoEncryptTest` verifies plaintext -> encrypt -> Base64 -> decrypt -> original plaintext.

Most relevant next investigation points:

- Confirm whether Montoya accepts `RequestToBeSentAction.continueWith(outboundRequest, annotations)` as used here for every tool source, or whether the request modification is being dropped for some tools.
- Confirm that `HttpRequestToBeSent` can safely be passed to `stripScannerMarkerHeader(HttpRequest request)` and then returned as an `HttpRequest` replacement.
- Confirm that `outboundRequest.withBody(encryptedBody)` updates the outgoing request body in this handler path.
- Check whether plaintext detection should avoid trying `decrypt()` first for obvious JSON/form bodies and directly encrypt them.
- Add a focused regression test or Burp-side diagnostic logging around `encryptPlaintextRequest()` showing original body, encrypted body length, and whether the modified request is returned.

## Section 6: Previous Issues (Already Fixed)

- `build.gradle` Gradle version compatibility fixed: works with Gradle 4.x-9.x.
- Scanner Base64 corruption by default insertion points fixed: repair logic added.
- Repeater dirty-state bug fixed: loading flag added.
- Host matching case sensitivity fixed: case-insensitive matching added.
- Config persistence fixed: Burp persistence API used.
- Clear All not clearing state fixed.
- Dead code in `ConfigTab` removed.
- `CryptoHelper` hex validation added.

## Section 7: Supervisor Feedback History

1. First review: "Everything works, well done"
2. Second review: "Active Scan inserts payload into encrypted body" -> Fixed
3. Third review: "Active Scan now stable. But ALL requests to target host must be encrypted regardless of source. Also add manual encrypt/decrypt panel" -> Manual panel done, auto-encrypt has a bug

## Section 8: Test Server

- Location: `test-server/server.py`
- Port: `8888`
- Key: `0123456789abcdef0123456789abcdef`
- IV: `abcdef0123456789abcdef0123456789`
- Endpoints:
  - `GET /api/health`
  - `POST /api/login`
  - `POST /api/profile`

## Section 9: Build & Deploy

- Build command: `gradle build` or `./gradlew build`.
- Full clean build command: `gradle clean build` or `./gradlew clean build`.
- Output JAR: `build/libs/burp-aes-extension.jar`.
- Burp deploy steps:
  1. Open Burp Suite.
  2. Go to `Extensions` -> `Installed` -> `Add`.
  3. Choose extension type `Java`.
  4. Select `build/libs/burp-aes-extension.jar`.
  5. Confirm that Burp reports the extension loaded successfully.

## Section 10: Important Notes

- We do NOT have Burp Professional, only Community Edition.
- Active Scanner cannot be tested locally because it requires Burp Professional.
- The supervisor has Burp Professional and tests scanner behavior himself.
- Scanner registration is wrapped in try/catch for Community compatibility.
- Do NOT change UI styling unless specifically asked.
- Do NOT run Gradle or Java commands in the sandbox because of network issues; the developer builds locally.
