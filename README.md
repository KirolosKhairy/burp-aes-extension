# AES Traffic Decryptor

AES Traffic Decryptor is a Burp Suite extension for inspecting and testing traffic whose entire HTTP request or response body is AES-CBC encrypted and Base64 encoded. It adds a configuration tab, a decrypted message editor, passive logging, and AES-aware scanner insertion points.

## Features

- Configure AES key, IV, and target host from a Burp suite tab
- Persist configuration across Burp restarts
- View decrypted request and response bodies in a custom `decrypted_message` tab
- Edit decrypted request bodies in Repeater and have them re-encrypted automatically
- Highlight matching encrypted traffic in Burp HTTP history
- Log plaintext previews for matching requests and responses
- Provide scanner insertion points inside decrypted JSON and form bodies

## Requirements

- Java 11 or later
- Burp Suite with Montoya API support
- Burp Suite Professional for Active Scan insertion point functionality

## Build

Build the extension with Gradle:

```bash
./gradlew build
```

The output JAR is:

```text
build/libs/burp-aes-extension.jar
```

## Installation

1. Build the project with Gradle.
2. Open Burp Suite.
3. Go to `Extensions`.
4. Add a new extension as a Java extension.
5. Select `build/libs/burp-aes-extension.jar`.
6. Confirm the extension loads successfully in the Burp output tab.

## Usage

### 1. Configure

Open the `AES Config` tab in Burp and enter:

- AES key as hex
- IV as hex
- Target host substring

Save the configuration. The values are persisted with Burp's extension persistence API.

### 2. HTTP History

For matching hosts, requests and responses whose full body is encrypted Base64 AES data can be viewed in the `decrypted_message` tab. Matching traffic is also highlighted and logged.

### 3. Repeater

Send a matching request to Repeater. The `decrypted_message` tab becomes editable for requests. Modify the plaintext and Burp will send the re-encrypted body.

### 4. Scanner

In Burp Suite Professional, Active Scan can fuzz decrypted parameters extracted from supported plaintext formats. The extension decrypts the body, injects payloads into plaintext fields, then re-encrypts the request before sending it.

## Limitations

- Assumes the entire request or response body is AES-encrypted Base64
- Scanner uses regex-based JSON parsing; it works for flat JSON and simple nested values but is limited for deeply nested or complex JSON structures
- Active Scan support requires Burp Suite Professional
- Plaintext is logged to Burp output; handle sensitive data accordingly

## Screenshots

- Placeholder: add `AES Config` tab screenshot
- Placeholder: add `decrypted_message` request/response screenshot
- Placeholder: add scanner insertion point screenshot
