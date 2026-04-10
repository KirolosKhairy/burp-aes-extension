# 🔐 AES Traffic Decryptor — Burp Suite Extension

**Transparent AES-CBC decryption, replay, and scan-aware analysis for Burp Suite.**

A professional Burp Suite extension that enables penetration testers to work seamlessly with APIs that encrypt request/response bodies using AES-CBC. The extension automatically decrypts traffic for viewing and editing, and re-encrypts it before transmission — making encryption completely transparent.

---

## 📋 Table of Contents

- [Problem](#-problem)
- [Solution](#-solution)
- [Features](#-features)
- [Requirements](#-requirements)
- [Installation](#-installation)
- [Configuration](#-configuration)
- [Usage](#-usage)
- [Project Structure](#-project-structure)
- [Building from Source](#-building-from-source)
- [How It Works](#-how-it-works)
- [Compatibility](#-compatibility)
- [Limitations](#-limitations)
- [Testing](#-testing)

---

## ❓ Problem

Many modern APIs encrypt their HTTP request and response bodies using AES encryption (Base64-encoded ciphertext). This creates major challenges during penetration testing:

- **HTTP History** shows unreadable encrypted data instead of actual JSON content
- **Repeater** cannot be used to modify parameters — the body is ciphertext
- **Active Scanner** cannot identify injection points or analyze responses
- Manual testing requires constant encrypt/decrypt operations outside Burp

---

## ✅ Solution

This extension acts as a **transparent translation layer** between the tester and the encrypted API:

```
You (plaintext) → Extension encrypts → Server receives encrypted request
Server responds (encrypted) → Extension decrypts → You see plaintext
```

From the tester's perspective, the API appears to communicate in plaintext.

---

## 🚀 Features

### Configuration & Cryptography
- AES Key input (128/192/256-bit via hex string)
- Initialization Vector (IV) input (128-bit hex)
- Target Host filtering — only matching traffic is processed
- PKCS5Padding for dynamic data lengths
- Real-time input validation with visual feedback
- Built-in "Test Encryption" button to verify key/IV before use
- Configuration persistence across Burp restarts

### UI Integration
- **`decrypted_message` tab** in HTTP History — view decrypted requests and responses
- **`decrypted_message` tab** in Repeater — edit plaintext, auto-encrypt on Send, auto-decrypt response
- **HTTP Logger** — logs decrypted traffic summaries and highlights matching requests in cyan
- Clean status indicators: `[EDITABLE]` / `[READ-ONLY]` mode labels
- Professional error display when decryption fails

### Active Scanner (Burp Professional)
- Custom insertion points from decrypted request bodies
- JSON parameter extraction (strings, numbers, booleans)
- Form-encoded parameter extraction
- JSON-aware payload escaping
- URL-encoding for form payloads
- Response decryption for vulnerability analysis
- Dashboard reporting with decrypted evidence
- Detects: Reflected Input, SQL Errors, Stack Trace Disclosure

---

## 📦 Requirements

| Requirement | Version |
|---|---|
| Java JDK | 11 or higher |
| Burp Suite | Community or Professional (2023+) |
| Gradle | 4.x+ (included via wrapper) |

---

## 📥 Installation

### Option 1: Download JAR (Recommended)

1. Download `burp-aes-extension.jar` from [Releases](https://github.com/KirolosKhairy/burp-aes-extension/releases)
2. Open Burp Suite
3. Go to **Extensions** → **Installed** → **Add**
4. Extension Type: **Java**
5. Select the downloaded JAR file
6. Click **Next** — verify "Extension loaded" appears

### Option 2: Build from Source

```bash
git clone https://github.com/KirolosKhairy/burp-aes-extension.git
cd burp-aes-extension
gradle build
```

Then load `build/libs/burp-aes-extension.jar` in Burp as described above.

---

## ⚙️ Configuration

1. Click the **"AES Config"** tab in Burp's top navigation bar
2. Enter your settings:

| Field | Format | Example |
|---|---|---|
| AES Key | Hex string (32/48/64 chars) | `0123456789abcdef0123456789abcdef` |
| IV | Hex string (32 chars) | `abcdef0123456789abcdef0123456789` |
| Target Host | Hostname substring | `api.target.com` |

3. Click **"Save Configuration"**
4. Status indicator turns green: **"Active — Extension is configured and ready"**

### Optional: Test Your Key

Click **"Test Encryption"** before saving — it runs a full encrypt→decrypt round-trip to verify your key and IV are correct.

### Where to Find the Key and IV

In a real penetration test, you obtain the AES key and IV from:

- JavaScript source code of the web application
- Reverse engineering the mobile application (APK/IPA)
- Intercepting the key exchange mechanism
- Configuration files or hardcoded values

---

## 🔧 Usage

### Viewing Decrypted Traffic (HTTP History)

1. Send a request to the target API through Burp Proxy
2. Go to **Proxy → HTTP History**
3. Click on the request — find the **"decrypted_message"** tab next to Pretty/Raw/Hex
4. Click it to see the plaintext JSON body
5. Do the same for the Response side

### Editing and Resending (Repeater)

1. Right-click a request in HTTP History → **Send to Repeater**
2. In Repeater, click the **"decrypted_message"** tab
3. Edit the plaintext JSON (e.g., change parameter values)
4. Click **Send**
5. The extension automatically encrypts the modified body before sending
6. The response **"decrypted_message"** tab shows the decrypted server response

### Active Scanning (Professional Edition)

1. Right-click a request → **Scan**
2. The extension automatically provides insertion points from the decrypted body
3. The Scanner injects payloads into plaintext parameters
4. The extension encrypts each payload before sending to the server
5. Responses are decrypted and analyzed for vulnerabilities
6. Findings appear on the **Dashboard** with decrypted evidence

---

## 📁 Project Structure

```
burp-aes-extension/
├── build.gradle                          # Build configuration
├── gradle/wrapper/                       # Gradle wrapper
├── gradlew / gradlew.bat                 # Build scripts
├── settings.gradle                       # Project settings
├── README.md                             # This file
└── src/
    ├── main/java/burp/
    │   ├── BurpAesExtension.java         # Main entry point, shared state
    │   ├── CryptoHelper.java             # AES/CBC/PKCS5Padding utility
    │   ├── ConfigTab.java                # Configuration UI tab
    │   ├── DecryptedMessageTab.java      # Decrypted view/edit tab
    │   ├── DecryptedMessageTabFactory.java  # Tab factory
    │   ├── AesScanCheck.java             # Scanner insertion point provider
    │   ├── AesInsertionPoint.java        # Custom insertion points
    │   ├── AesResponseScanCheck.java     # Response analysis for Dashboard
    │   └── AesHttpLogger.java            # Traffic logger
    └── test/java/burp/
        └── CryptoTest.java              # Crypto unit tests (40 tests)
```

---

## 🏗️ Building from Source

```bash
# Clone the repository
git clone https://github.com/KirolosKhairy/burp-aes-extension.git
cd burp-aes-extension

# Build
gradle build

# Output JAR location
ls -la build/libs/burp-aes-extension.jar

# Run crypto tests
javac src/test/java/burp/CryptoTest.java -d /tmp/cryptotest/
java -cp /tmp/cryptotest burp.CryptoTest
```

---

## 🔍 How It Works

### Encryption Flow

```
┌─────────────┐     ┌──────────────┐     ┌──────────┐
│  You edit    │     │  Extension   │     │  Server  │
│  plaintext   │ ──→ │  encrypts    │ ──→ │ receives │
│  in Repeater │     │  with AES    │     │ encrypted│
└─────────────┘     └──────────────┘     └──────────┘
                                               │
┌─────────────┐     ┌──────────────┐           │
│  You see    │     │  Extension   │     ┌─────▼────┐
│  plaintext  │ ◀── │  decrypts    │ ◀── │  Server  │
│  response   │     │  response    │     │ responds │
└─────────────┘     └──────────────┘     └──────────┘
```

### Scanner Flow

```
┌──────────┐     ┌────────────┐     ┌──────────┐     ┌───────────┐
│ Scanner  │     │ Extension  │     │ Extension│     │  Server   │
│ provides │ ──→ │ inserts    │ ──→ │ encrypts │ ──→ │ receives  │
│ payload  │     │ into JSON  │     │ body     │     │ encrypted │
└──────────┘     └────────────┘     └──────────┘     └───────────┘
                                                           │
┌──────────┐     ┌────────────┐     ┌──────────┐          │
│Dashboard │     │ Extension  │     │ Extension│     ┌─────▼─────┐
│ shows    │ ◀── │ creates    │ ◀── │ decrypts │ ◀── │  Server   │
│ issues   │     │ AuditIssue │     │ response │     │ responds  │
└──────────┘     └────────────┘     └──────────┘     └───────────┘
```

### Technical Details

| Component | Details |
|---|---|
| Algorithm | AES (128/192/256-bit) |
| Mode | CBC (Cipher Block Chaining) |
| Padding | PKCS5Padding |
| Encoding | Base64 for transport |
| Key Format | Hexadecimal string |
| IV Format | Hexadecimal string (32 hex chars = 16 bytes) |
| API | Burp Montoya API |

---

## 🔄 Compatibility

| Feature | Community Edition | Professional Edition |
|---|---|---|
| Configuration UI | ✅ | ✅ |
| decrypted_message tab | ✅ | ✅ |
| Repeater editing | ✅ | ✅ |
| HTTP Logger | ✅ | ✅ |
| Active Scanner | ❌ | ✅ |
| Dashboard issues | ❌ | ✅ |

Scanner registration is wrapped in try/catch for safe Community Edition loading.

---

## ⚠️ Limitations

- **Whole-body encryption**: Assumes the entire request/response body is a Base64-encoded AES ciphertext. Does not support partial encryption (e.g., only one JSON field encrypted).
- **JSON parsing**: Scanner uses regex-based parameter extraction. Works well for flat JSON objects; deeply nested structures may have limited coverage.
- **Static Key/IV**: Uses a single key and IV pair. Does not support per-request key derivation or key rotation.
- **Plaintext logging**: Decrypted content is logged to Burp's output. Be aware when handling sensitive data.
- **Host matching**: Uses case-insensitive substring matching. Setting target to "api" would match any host containing "api".

---

## 🧪 Testing

### Automated Crypto Tests

40 tests covering:
- Round-trip encryption/decryption
- Empty and long strings (1000+ chars)
- Special characters and Unicode
- Invalid Base64, wrong key/IV lengths
- Padding boundaries (1–33 bytes)

**Result: 40/40 PASSED**

### Manual Testing with Test Server

A Python Flask test server (`test-aes-server/server.py`) was used for functional testing with endpoints:

- `POST /api/login` — Authentication with encrypted credentials
- `POST /api/profile` — Profile lookup with reflected user_id
- `GET /api/health` — Plain text connectivity check

All functional tests passed: decryption, editing, re-encryption, host filtering, and config persistence.

---

## 👤 Author

**Kirolos** — Penetration Tester & Security Tool Developer

---

## 📄 License

This project is provided for educational and authorized security testing purposes only.
