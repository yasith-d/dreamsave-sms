**SMS Decryptor & Cloud Function**

This project provides tools for encrypting, decrypting, and storing DreamStart-style meeting SMS messages. It includes a local encryptor/decryptor for testing and a Google Cloud Function to receive, decrypt, and log messages in PostgreSQL.

Features

- AES-256-GCM encryption with HMAC-SHA256 key derivation per group.
- Local Java encryptor for generating test SMS messages.
- Local Node.js decryptor for offline testing.
- Cloud Function (decryptSMS) to securely receive SMS, decrypt, validate, and store messages.
- DB logging for both successfully decrypted messages and failed decryption attempts.
- Supports meeting_id as the unique key; duplicate messages are ignored.

Project Structure
.
├── gcp-function/             # Node.js cloud function
│   ├── index.js              # Main entry point
│   └── package.json
├── schemas/                  # DB Schema
│   └── tables.sql
├── test/
│   ├── Message.txt           # Test message to use
├──────decryptor/             # Node.js local decryptor
│       └── local_decrypt_test.js
├──────encryptor/             # Java AES-GCM local encryptor
│       └── SmsGcmEncryptTest.java

Usage
1. Local encryptor - Shared secret necessary
  cd test/encryptor/
  javac SmsGcmEncryptTest.java
  java SmsGcmEncryptTest

2. Local decryptor - Shared secret necessary
  cd test/decryptor
  node local_decrypt_test.js "DreamStart:UG-123-456:M#1:<Base64Payload>"

3. Cloud function - Shared secret necessary
  Cloud function is deployed on GCP
