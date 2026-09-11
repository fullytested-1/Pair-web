# ROMA Pairing Web

A Node.js 22+ web service for generating WhatsApp Multi-Device sessions with Baileys.

## Features

- Phone-number pairing code (no QR required)
- QR login
- MongoDB-backed Baileys auth state
- Encrypted auth-state values at rest
- Custom session IDs beginning with `ROMA~`
- Session ID is sent to the connected WhatsApp account
- Auth state is removed from MongoDB after WhatsApp logout
- Basic rate limiting and input validation

## Run

```bash
npm install
cp .env.example .env
# Set MONGODB_URI and SESSION_ENCRYPTION_KEY
npm start
```

For `SESSION_ENCRYPTION_KEY`, use 32 random bytes encoded as 64 hexadecimal characters.

Never commit `.env`, real session IDs, or database credentials.

## Pairing

Open the web page, choose Pair Code, enter country code and phone number, then enter the generated code in WhatsApp under Linked Devices.

## QR

Choose QR Code and scan the displayed QR using WhatsApp Linked Devices.

This project is intended as the session-generator service. The resulting `ROMA~...` value can be supplied to a separate bot through `SESSION_ID`.
