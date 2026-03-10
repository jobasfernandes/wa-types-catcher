# WhatsApp Types Catcher

A reverse-engineering utility built with Node.js and Playwright designed to intercept, decode, and catalog WhatsApp Web internal message payloads and XMPP stanzas in real time. 

Repository: [jobasfernandes/wa-types-catcher](https://github.com/jobasfernandes/wa-types-catcher)

## Overview

WhatsApp Web operates via an encrypted WebSocket connection, exchanging binary data encoded in a custom XMPP node implementation (Stanzas) that wraps underlying Protobuf payloads. This tool injects hooks directly into the minified WhatsApp Web JavaScript environment to capture this data stream precisely at the decryption and encoding stages.

By hooking into internal decoder methods (`decodeStanza` and `decodeProtobuf` for received messages, and their encoding counterparts for sent messages), the script can intercept the unencrypted binary nodes and JSON structures of every incoming and outgoing message. The intercepted data includes complex message types such as Native PIX buttons, interactive messages, polls, and rich media documents.

Each time a unique message type or configuration is detected, it is automatically serialized and saved into a local data directory, preventing duplicates for simple text while uniquely timestamping complex interactive permutations.

## Features

- **XMPP Stanza Interception:** Retrieves the complete surrounding XMPP node structure (`<biz>`, `<enc>`, etc.) alongside its attributes before it gets parsed out by the application.
- **Protobuf Payload Extraction:** Captures the decrypted JSON payload representing the internal WhatsApp state for a specific message.
- **Bi-directional Capture:** Intercepts both outgoing (Sent) and incoming (Received) traffic.
- **Zero-Overhead Architecture:** Utilizes strictly synchronous Javascript interceptors and lightweight `console.log` IPC to prevent blocking the WhatsApp Web pipeline, completely eliminating browser freezes.
- **Undetectable Execution:** Operates with Playwright's automation flags disabled to avoid triggering WhatsApp's anti-bot protections.
- **Automatic Cataloging:** Sorts and saves payloads as distinct JSON files into a `/data` folder based on message type and variant identifiers.
- **Resilient Execution:** Wraps all hooks with robust try/catch blocks protecting against lazy-getter evaluation exceptions.

## Installation

1. Clone or download this repository.
2. Ensure you have Node.js installed.
3. Install the required dependencies (primarily Playwright):

```bash
npm install
```

## Usage

Start the builder using npm:

```bash
npm start
```

1. A Chromium browser window will launch automatically, navigating to WhatsApp Web.
2. If this is your first time running the script, you will need to scan the QR code using your phone. (Playwright saves session data to the local `wa_session` directory, allowing for automatic login in subsequent runs).
3. Send or receive messages either from your phone or directly through the browser interface.
4. The Node.js console will log whenever a new message type structure is captured.
5. Inspect the generated `.json` files inside the `/data` directory to analyze the exact internal data structure of the captured messages.

## Credits & Inspiration

This project and its injection architecture were heavily inspired by the logging mechanisms found in [vinikjkkj/wa-logging-scripts](https://github.com/vinikjkkj/wa-logging-scripts). Special thanks to the original author for the foundational understanding of the WhatsApp Web inner decoders.
