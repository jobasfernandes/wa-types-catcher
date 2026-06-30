/**
 * WA Type Database Builder - Injection Script
 * Catch the Stanza XMPP (BinaryNode) + Payload Protobuf along the sending/receiving
 * to build the reference database with the complete structure.
 */
(function () {
  "use strict";

  if (window.top !== window.self) return;
  if (window.__WA_DB_INJECT) return;
  window.__WA_DB_INJECT = true;

  let lastRecvStanza = null;
  let pendingSentEntry = null;

  const PROTOCOL_KEYS = new Set([
    "serverHello", "ratchetKey", "preKeyId", "baseKey",
    "leaf", "serial", "field", "value", "timestamp",
    "currentMsg", "identityKey", "registrationId",
    "signedPreKey", "preKey", "senderKey",
    "encResultMessage", "preKeyWhisperMessage",
    "whiskeyTransport", "hsm"
  ]);

  const DECODE_BUFFER_TAGS = new Set([
    "reporting_token", "reporting_tag", "tc", "token",
    "privacy_token", "tctoken", "hash",
    "query", "result", "data", "variables", "error", "digest",
    "ref", "device-identity", "device", "biz", "platform", "key-index",
    "credential_id", "webauthn_assertion", "prologue_payload",
    "pairing_handoff_proof", "passkey_request_options",
    "primary_ephemeral_identity", "companion_nonce", "encrypted_pairing_request",
    "link_code_pairing_ref", "link_code_pairing_wrapped_companion_ephemeral_pub",
    "link_code_pairing_wrapped_primary_ephemeral_pub", "wrapped_key_bundle",
    "companion_identity_public", "companion_server_auth_key_pub",
    "integrity_challenge", "challenge", "passkey_challenge", "captcha_challenge"
  ]);

  // Tags de child que identificam stanzas de pareamento (handshake companion).
  const PAIRING_IQ_TAGS = new Set([
    "pair-device", "pair-success", "pair-device-sign",
    "passkey_prologue", "passkey_request_options", "companion_nonce",
    "encrypted_pairing_request", "ref", "link_code_companion_reg"
  ]);

  // Types de notification ligados a pareamento / passkey / integridade.
  const PAIRING_NOTIF_TYPES = new Set([
    "passkey_prologue_request", "crsc_continuation", "link_code_companion_reg"
  ]);

  const TRACKED_ERROR_CODES = new Set(["421", "463", "475", "479"]);

  const TRACKED_IQ_XMLNS = new Set([
    "privacy", "mex", "abt", "w:biz", "urn:xmpp:whatsapp:dirty",
    "w:profile:picture", "w:props"
  ]);

  function isBufferLike(node) {
    if (!node) return false;
    if (node instanceof Uint8Array || node instanceof ArrayBuffer) return true;
    const name = node.constructor && node.constructor.name;
    if (name === "Uint8Array" || name === "ArrayBuffer" || name === "Buffer") return true;
    if (node.buffer && typeof node.byteLength === "number") return true;
    return false;
  }

  function bufferToHex(buf) {
    try {
      const bytes = buf instanceof ArrayBuffer ? new Uint8Array(buf) : buf;
      if (!bytes || !bytes.length) return "";
      return Array.from(bytes).map(b => b.toString(16).padStart(2, "0")).join("");
    } catch (e) {
      return "<hex-error>";
    }
  }

  function bufferToBase64(buf) {
    try {
      const bytes = buf instanceof ArrayBuffer ? new Uint8Array(buf) : buf;
      if (!bytes || !bytes.length) return "";
      let binary = "";
      for (let i = 0; i < bytes.length; i++) binary += String.fromCharCode(bytes[i]);
      return btoa(binary);
    } catch (e) {
      return "<b64-error>";
    }
  }

  function tryDecodeBufferText(buf) {
    try {
      const bytes = buf instanceof ArrayBuffer ? new Uint8Array(buf) : buf;
      if (!bytes || !bytes.length) return { text: null, json: null };
      const text = new TextDecoder("utf-8", { fatal: false }).decode(bytes);
      let printable = 0;
      for (let i = 0; i < text.length; i++) {
        const c = text.charCodeAt(i);
        if ((c >= 32 && c < 127) || c === 9 || c === 10 || c === 13) printable++;
      }
      if (text.length === 0 || printable / text.length < 0.7) {
        return { text: null, json: null };
      }
      let json = null;
      try { json = JSON.parse(text); } catch (e) {}
      return { text, json };
    } catch (e) {
      return { text: null, json: null };
    }
  }

  function parseBinaryNode(node, depth = 0) {
    if (depth > 15) return "<Max Depth Exceeded>";
    if (!node || typeof node !== "object") return null;
    if (isBufferLike(node)) {
      return `<Buffer ${node.byteLength !== undefined ? node.byteLength : node.length}b>`;
    }

    const result = {};
    const tag = node.tag;
    if (tag) result._tag = tag;
    const shouldDecodeBuffer = tag && DECODE_BUFFER_TAGS.has(tag);

    if (node.attrs && typeof node.attrs === "object") {
      const cleanAttrs = {};
      for (const [k, v] of Object.entries(node.attrs)) {
        if (v === undefined || v === null) continue;
        if (v && typeof v === "object" && v.$1) {
          const j = v.$1;
          cleanAttrs[k] = j.server ? `${j.user}@${j.server}` : `${j.user}@lid`;
        } else {
          cleanAttrs[k] = String(v);
        }
      }
      if (Object.keys(cleanAttrs).length) result._attrs = cleanAttrs;
    }

    if (Array.isArray(node.content)) {
      result._children = node.content
        .map((c) => parseBinaryNode(c, depth + 1))
        .filter(Boolean);
    } else if (isBufferLike(node.content)) {
      if (shouldDecodeBuffer) {
        const len = node.content.byteLength !== undefined ? node.content.byteLength : node.content.length;
        result._content_hex = bufferToHex(node.content);
        result._content_b64 = bufferToBase64(node.content);
        result._content_len = len;
        const decoded = tryDecodeBufferText(node.content);
        if (decoded.text !== null) result._content_text = decoded.text;
        if (decoded.json !== null) result._content_json = decoded.json;
      } else {
        result._content = `<Buffer ${node.content.byteLength !== undefined ? node.content.byteLength : node.content.length}b>`;
      }
    } else if (node.content !== null && node.content !== undefined) {
      result._content = node.content;
    }

    return result;
  }

  function extractProtocolMeta(rawNode) {
    const meta = {};
    if (!rawNode || !Array.isArray(rawNode.content)) return meta;

    for (const child of rawNode.content) {
      if (!child || !child.tag) continue;

      if (child.tag === "reporting" && Array.isArray(child.content)) {
        for (const rc of child.content) {
          if (rc && rc.tag === "reporting_token" && isBufferLike(rc.content)) {
            meta.reportingToken = {
              version: rc.attrs?.v ? String(rc.attrs.v) : undefined,
              hex: bufferToHex(rc.content),
              b64: bufferToBase64(rc.content),
              len: rc.content.byteLength || rc.content.length
            };
          }
          if (rc && rc.tag === "reporting_tag" && isBufferLike(rc.content)) {
            meta.reportingTag = {
              hex: bufferToHex(rc.content),
              b64: bufferToBase64(rc.content),
              len: rc.content.byteLength || rc.content.length
            };
          }
        }
      }

      if (child.tag === "tc" || child.tag === "tctoken") {
        meta.tcToken = parseBinaryNode(child);
        if (isBufferLike(child.content)) {
          meta.tcToken._content_hex = bufferToHex(child.content);
        }
      }

      if (child.tag === "privacy") {
        meta.privacyNode = parseBinaryNode(child);
      }

      if (child.tag === "bot") {
        meta.botMeta = parseBinaryNode(child);
      }

      if (child.tag === "meta") {
        meta.metaNode = parseBinaryNode(child);
      }
    }

    return meta;
  }

  function extractMexMeta(rawNode) {
    if (!rawNode || !Array.isArray(rawNode.content)) return null;
    const found = [];
    for (const child of rawNode.content) {
      if (!child || (child.tag !== "query" && child.tag !== "result")) continue;
      const entry = { kind: child.tag };
      const attrs = child.attrs || {};
      if (attrs.op_name) entry.opName = String(attrs.op_name);
      if (attrs.query_id) entry.queryId = String(attrs.query_id);
      if (attrs.hash) entry.hash = String(attrs.hash);
      if (attrs.type) entry.queryType = String(attrs.type);
      if (isBufferLike(child.content)) {
        entry.bodyLen = child.content.byteLength || child.content.length;
        const decoded = tryDecodeBufferText(child.content);
        if (decoded.json !== null) entry.bodyJSON = decoded.json;
        else if (decoded.text !== null) entry.bodyText = decoded.text.slice(0, 8000);
        else entry.bodyHex = bufferToHex(child.content);
      } else if (typeof child.content === "string") {
        try {
          entry.bodyJSON = JSON.parse(child.content);
        } catch (e) {
          entry.bodyText = child.content.slice(0, 8000);
        }
      }
      found.push(entry);
    }
    return found.length ? found : null;
  }

  function classifySystemStanza(rawNode) {
    if (!rawNode || !rawNode.tag) return null;
    const tag = rawNode.tag;
    const attrs = rawNode.attrs || {};
    const attrsStr = {};
    for (const [k, v] of Object.entries(attrs)) {
      if (v === undefined || v === null) continue;
      if (v && typeof v === "object" && v.$1) {
        const j = v.$1;
        attrsStr[k] = j.server ? `${j.user}@${j.server}` : `${j.user}@lid`;
      } else {
        attrsStr[k] = String(v);
      }
    }

    if (tag === "failure" || tag === "stream:error") {
      const code = attrsStr.reason || attrsStr.code || "unknown";
      return { type: "ERROR", variant: `${tag}_${code}` };
    }

    if (tag === "iq") {
      const xmlns = attrsStr.xmlns || "";
      const type = attrsStr.type || "";

      let childXmlns = xmlns;
      if (!childXmlns && Array.isArray(rawNode.content)) {
        for (const child of rawNode.content) {
          if (child && child.attrs && child.attrs.xmlns) {
            childXmlns = String(child.attrs.xmlns);
            break;
          }
        }
      }

      if (Array.isArray(rawNode.content)) {
        for (const child of rawNode.content) {
          if (child && child.tag && PAIRING_IQ_TAGS.has(child.tag)) {
            return { type: "PAIRING", variant: `iq_${type}_${child.tag}` };
          }
        }
      }
      if (childXmlns === "md" || xmlns === "md") {
        return { type: "PAIRING", variant: `iq_${type}_md` };
      }

      if (childXmlns === "privacy" || xmlns === "privacy") {
        return { type: "TC_TOKEN", variant: `iq_${type}` };
      }

      if (childXmlns === "mex" || xmlns === "mex") {
        return { type: "LIMIT", variant: `mex_${type}` };
      }

      if (childXmlns === "abt" || xmlns === "abt" || childXmlns === "w:props" || xmlns === "w:props") {
        return { type: "AB_PROP", variant: `props_${type}` };
      }

      if (Array.isArray(rawNode.content)) {
        for (const child of rawNode.content) {
          if (child && child.tag === "error") {
            const errCode = child.attrs?.code ? String(child.attrs.code) : "unknown";
            if (TRACKED_ERROR_CODES.has(errCode)) {
              return { type: "ERROR", variant: `iq_error_${errCode}` };
            }
          }
        }
      }

      if (TRACKED_IQ_XMLNS.has(childXmlns) || TRACKED_IQ_XMLNS.has(xmlns)) {
        return { type: "IQ_SYSTEM", variant: `${childXmlns || xmlns}_${type}` };
      }

      return null;
    }

    if (tag === "notification") {
      const type = attrsStr.type || "unknown";
      if (PAIRING_NOTIF_TYPES.has(type)) {
        return { type: "PAIRING", variant: `notif_${type}` };
      }
      if (type === "mex") {
        return { type: "INTEGRITY", variant: "mex_notification" };
      }
      if (Array.isArray(rawNode.content)) {
        for (const child of rawNode.content) {
          if (child && child.tag && /integrity|passkey|checkpoint|challenge/i.test(child.tag)) {
            return { type: "INTEGRITY", variant: `${type}_${child.tag}` };
          }
        }
      }
      if (type === "privacy_token" || type === "encrypt" || type === "account_sync") {
        return { type: "NOTIFICATION", variant: type };
      }
      if (Array.isArray(rawNode.content)) {
        for (const child of rawNode.content) {
          if (child && (child.tag === "tc" || child.tag === "privacy" || child.tag === "add" || child.tag === "token")) {
            return { type: "NOTIFICATION", variant: `${type}_${child.tag}` };
          }
        }
      }
      return null;
    }

    return null;
  }

  function deepCloneSafe(node, depth = 0, seen = new WeakSet()) {
    if (depth > 12) return "<Max Depth Exceeded>";
    if (node === null || node === undefined) return node;

    if (typeof node !== "object") {
      if (typeof node === "bigint") return node.toString();
      return node;
    }

    if (seen.has(node)) return "[Circular]";

    if (isBufferLike(node)) {
      return `<Buffer ${node.byteLength !== undefined ? node.byteLength : node.length}b>`;
    }

    if (node.$1) {
      const j = node.$1;
      if (j.user && j.server) return `${j.user}@${j.server}`;
      if (j.user && j.type !== undefined) return `${j.user}@lid`;
      return node.toString ? node.toString() : node;
    }

    seen.add(node);

    if (Array.isArray(node)) {
      if (node.length > 500) {
        return `[Array length=${node.length}]`;
      }
      return node.map((child) => deepCloneSafe(child, depth + 1, seen));
    }

    const result = {};
    let keys = Object.keys(node);
    if (keys.length > 300) {
      return `<Large Object keys=${keys.length}>`;
    }

    for (const key of keys) {
      if (key === "$$unknownFieldCount" || key === "messageContextInfo" || key === "deviceListMetadata") continue;
      if (key === "messageSecret") {
        result[key] = "<Buffer 32b>";
        continue;
      }

      let val;
      try {
        val = node[key];
      } catch (e) {
        result[key] = "<Getter Error>";
        continue;
      }
      if (key === "buttonParamsJson" && typeof val === "string") {
        try {
          val = JSON.parse(val);
        } catch (e) {}
      }

      result[key] = deepCloneSafe(val, depth + 1, seen);
    }
    return result;
  }

  const DB_PREFIX = "__WA_DB__";

  function detectChatType(stanzaInfo, direction) {
    if (!stanzaInfo || !stanzaInfo._attrs) return "UNKNOWN";
    const jid = direction === "SENT" ? stanzaInfo._attrs.to : stanzaInfo._attrs.from;
    if (!jid) return "UNKNOWN";
    if (jid.endsWith("@g.us")) return "GRUPO";
    return "PRIVADO";
  }

  function emitEntry(obj) {
    try {
      obj.chatType = detectChatType(obj.stanzaInfo, obj.direction);
      console.log(DB_PREFIX + JSON.stringify(deepCloneSafe(obj)));
    } catch (e) {}
  }

  function classify(decoded) {
    if (!decoded || typeof decoded !== "object") return null;

    if (
      decoded.viewOnceMessage ||
      decoded.viewOnceMessageV2 ||
      decoded.viewOnceMessageV2Extension
    ) {
      const inner = (
        decoded.viewOnceMessage ||
        decoded.viewOnceMessageV2 ||
        decoded.viewOnceMessageV2Extension
      )?.message;
      const sub = inner ? classify(inner) : null;
      return {
        type: "VIEW_ONCE",
        subType: sub?.type,
        variant: sub?.variant,
        payload: decoded,
      };
    }
    if (decoded.ephemeralMessage)
      return classify(decoded.ephemeralMessage.message);
    if (decoded.documentWithCaptionMessage)
      return classify(decoded.documentWithCaptionMessage.message);
    if (decoded.deviceSentMessage)
      return classify(decoded.deviceSentMessage.message);

    if (decoded.protocolMessage) {
      const t = decoded.protocolMessage.type;
      if (t === 0 || t === "REVOKE")
        return { type: "DELETE", variant: "revoke", payload: decoded };
      if (t === 14 || t === "MESSAGE_EDIT") {
        const edited = decoded.protocolMessage.editedMessage;
        if (edited?.richResponseMessage) {
          const subs = edited.richResponseMessage.submessages || [];
          const hasTable = subs.some(s =>
            s.messageType === 4 || s.messageType === "AI_RICH_RESPONSE_TABLE" || s.tableMetadata
          );
          const hasCode = subs.some(s =>
            s.messageType === 5 || s.messageType === "AI_RICH_RESPONSE_CODE" || s.codeMetadata
          );
          let variant = "text";
          if (hasTable && hasCode) variant = "tableAndCode";
          else if (hasTable) variant = "table";
          else if (hasCode) variant = "code";
          return { type: "META_AI", variant, payload: decoded };
        }
        return { type: "EDIT", variant: "edit", payload: decoded };
      }
      return null;
    }

    if (decoded.senderKeyDistributionMessage) return null;
    if (decoded.conversation)
      return { type: "TEXT", variant: "simple", payload: decoded };
    if (decoded.extendedTextMessage) {
      if (decoded.extendedTextMessage.contextInfo?.isForwarded) {
        return { type: "FORWARD", variant: "send", payload: decoded };
      }
      const hasQuote = !!decoded.extendedTextMessage.contextInfo?.quotedMessage;
      const hasMentions =
        !!decoded.extendedTextMessage.contextInfo?.mentionedJid?.length;
      let variant = "simple";
      if (hasQuote && hasMentions) variant = "quotedWithMentions";
      else if (hasQuote) variant = "quoted";
      else if (hasMentions) variant = "withMentions";
      else if (decoded.extendedTextMessage.matchedText)
        variant = "withLinkPreview";
      return { type: "TEXT", variant, payload: decoded };
    }

    if (decoded.imageMessage)
      return {
        type: "IMAGE",
        variant: decoded.imageMessage.viewOnce ? "viewOnce" : "fromUrl",
        payload: decoded,
      };
    if (decoded.videoMessage) {
      const v = decoded.videoMessage;
      return {
        type: "VIDEO",
        variant: v.gifPlayback ? "asGif" : v.viewOnce ? "viewOnce" : "fromUrl",
        payload: decoded,
      };
    }
    if (decoded.audioMessage)
      return {
        type: "AUDIO",
        variant: decoded.audioMessage.ptt ? "voiceNote" : "audioFile",
        payload: decoded,
      };
    if (decoded.stickerMessage)
      return {
        type: "STICKER",
        variant: decoded.stickerMessage.isAnimated ? "animated" : "static",
        payload: decoded,
      };
    if (decoded.documentMessage)
      return { type: "DOCUMENT", variant: "send", payload: decoded };
    if (decoded.locationMessage)
      return { type: "LOCATION", variant: "static", payload: decoded };
    if (decoded.liveLocationMessage)
      return { type: "LOCATION", variant: "live", payload: decoded };
    if (decoded.contactMessage)
      return { type: "CONTACT", variant: "single", payload: decoded };
    if (decoded.contactsArrayMessage)
      return { type: "CONTACT", variant: "multiple", payload: decoded };
    if (decoded.reactionMessage) {
      return {
        type: "REACTION",
        variant: decoded.reactionMessage.text ? "add" : "remove",
        payload: decoded,
      };
    }
    if (decoded.eventMessage)
      return { type: "EVENT", variant: "create", payload: decoded };
    if (decoded.eventResponseMessage)
      return { type: "EVENT", variant: "response", payload: decoded };
    if (
      decoded.pollCreationMessage ||
      decoded.pollCreationMessageV2 ||
      decoded.pollCreationMessageV3
    ) {
      return { type: "POLL", variant: "create", payload: decoded };
    }
    if (decoded.pollUpdateMessage)
      return { type: "POLL", variant: "vote", payload: decoded };
    if (decoded.listMessage)
      return { type: "LIST", variant: "send", payload: decoded };
    if (decoded.listResponseMessage)
      return { type: "LIST", variant: "response", payload: decoded };
    if (decoded.buttonsMessage)
      return { type: "BUTTONS", variant: "send", payload: decoded };
    if (decoded.buttonsResponseMessage)
      return { type: "BUTTONS", variant: "response", payload: decoded };
    if (decoded.templateMessage)
      return { type: "BUTTONS", variant: "template", payload: decoded };
    if (decoded.interactiveMessage) {
      const im = decoded.interactiveMessage;
      const nf = im.nativeFlowMessage;
      let btnName = "nativeFlow";
      if (nf?.buttons?.length) btnName = nf.buttons[0].name || btnName;
      return { type: "INTERACTIVE", variant: btnName, payload: decoded };
    }
    if (decoded.interactiveResponseMessage)
      return { type: "INTERACTIVE", variant: "response", payload: decoded };
    if (decoded.productMessage)
      return { type: "INTERACTIVE", variant: "product", payload: decoded };
    if (decoded.botInvokeMessage)
      return { type: "BOT_INVOKE", variant: "invoke", payload: decoded };

    const unknownKey = Object.keys(decoded).filter(
      (k) => k !== "messageContextInfo" && k !== "$$unknownFieldCount",
    )[0];

    if (
      !unknownKey ||
      PROTOCOL_KEYS.has(unknownKey) ||
      decoded.preKeyId !== undefined ||
      decoded.baseKey !== undefined
    ) {
      return null;
    }

    return { type: "UNKNOWN", variant: unknownKey, payload: decoded };
  }

  function classifyReceipt(stanzaInfo) {
    if (!stanzaInfo || !stanzaInfo._attrs) return null;
    const attrs = stanzaInfo._attrs;
    const receiptType = attrs.type || "delivery";

    const variants = {
      "read": "read",
      "read-self": "readSelf",
      "played": "played",
      "played-self": "playedSelf",
      "delivery": "delivery",
      "inactive": "inactive",
      "server": "server"
    };

    return {
      type: "ACK",
      variant: variants[receiptType] || receiptType,
      payload: {
        messageId: attrs.id,
        from: attrs.from,
        to: attrs.to,
        participant: attrs.participant,
        timestamp: attrs.t
      }
    };
  }

  function installStanzaHooks() {
    if (window.__WA_DB_STANZA_HOOKED) return true;
    let WAWap;
    try { WAWap = require("WAWap"); } catch (e) { return false; }
    if (!WAWap || typeof WAWap.decodeStanza !== "function" || typeof WAWap.encodeStanza !== "function") return false;

  if (!window._dbinj_decodeStanza)
    window._dbinj_decodeStanza = WAWap.decodeStanza;
  WAWap.decodeStanza = async (e, t) => {
    const result = await window._dbinj_decodeStanza(e, t);
    try {
      if (result && result.tag === "message") {
        const stanzaJSON = parseBinaryNode(result);
        if (stanzaJSON) {
          lastRecvStanza = stanzaJSON;
          const protoMeta = extractProtocolMeta(result);
          if (protoMeta && Object.keys(protoMeta).length) {
            lastRecvStanza._protocolMeta = protoMeta;
          }
        }
      }

      if (result && (result.tag === "receipt" || result.tag === "ack")) {
        const stanzaJSON = parseBinaryNode(result);
        if (stanzaJSON) {
          const info = classifyReceipt(stanzaJSON);
          if (info) {
            emitEntry({
              direction: "RECV",
              timestamp: new Date().toISOString(),
              type: info.type,
              variant: info.variant,
              payload: info.payload,
              stanzaInfo: stanzaJSON
            });
          }
        }
      }

      if (result) {
        const sysInfo = classifySystemStanza(result);
        if (sysInfo) {
          const stanzaJSON = parseBinaryNode(result);
          const protoMeta = extractProtocolMeta(result);
          const mexMeta = sysInfo.type === "LIMIT" ? extractMexMeta(result) : null;
          if (mexMeta) {
            const opNames = mexMeta.map(m => m.opName || m.queryId || m.kind).join(",");
            console.log(`📡 MEX RECV: ${opNames}`);
          }
          emitEntry({
            direction: "RECV",
            timestamp: new Date().toISOString(),
            type: sysInfo.type,
            variant: sysInfo.variant,
            payload: stanzaJSON,
            protocolMeta: Object.keys(protoMeta).length ? protoMeta : undefined,
            mexMeta: mexMeta || undefined,
            stanzaInfo: stanzaJSON
          });
        }
      }
    } catch (err) {}
    return result;
  };

  if (!window._dbinj_encodeStanza)
    window._dbinj_encodeStanza = WAWap.encodeStanza;
  WAWap.encodeStanza = (stanza) => {
    try {
      if (stanza && stanza.tag === "message") {
        const stanzaJSON = parseBinaryNode(stanza);
        if (stanzaJSON && pendingSentEntry) {
          const protoMeta = extractProtocolMeta(stanza);
          if (protoMeta && Object.keys(protoMeta).length) {
            pendingSentEntry.protocolMeta = protoMeta;
          }
          pendingSentEntry.stanzaInfo = stanzaJSON;
          emitEntry(pendingSentEntry);
          pendingSentEntry = null;
        }
      }

      if (stanza && (stanza.tag === "receipt" || stanza.tag === "ack")) {
        const stanzaJSON = parseBinaryNode(stanza);
        if (stanzaJSON) {
          const info = classifyReceipt(stanzaJSON);
          if (info) {
            emitEntry({
              direction: "SENT",
              timestamp: new Date().toISOString(),
              type: info.type,
              variant: info.variant,
              payload: info.payload,
              stanzaInfo: stanzaJSON
            });
          }
        }
      }

      if (stanza) {
        const sysInfo = classifySystemStanza(stanza);
        if (sysInfo) {
          const stanzaJSON = parseBinaryNode(stanza);
          const protoMeta = extractProtocolMeta(stanza);
          const mexMeta = sysInfo.type === "LIMIT" ? extractMexMeta(stanza) : null;
          if (mexMeta) {
            const opNames = mexMeta.map(m => m.opName || m.queryId || m.kind).join(",");
            console.log(`📡 MEX SENT: ${opNames}`);
          }
          emitEntry({
            direction: "SENT",
            timestamp: new Date().toISOString(),
            type: sysInfo.type,
            variant: sysInfo.variant,
            payload: stanzaJSON,
            protocolMeta: Object.keys(protoMeta).length ? protoMeta : undefined,
            mexMeta: mexMeta || undefined,
            stanzaInfo: stanzaJSON
          });
        }
      }
    } catch (err) {}
    return window._dbinj_encodeStanza(stanza);
  };

    window.__WA_DB_STANZA_HOOKED = true;
    console.log("✅ WA DB: stanza hooks armed (pairing + integrity + system + receipts)");
    return true;
  }

  function installMessageHooks() {
    if (window.__WA_DB_MSG_HOOKED) return true;
    let sendApi, decProto;
    try {
      sendApi = require("WAWebSendMsgCommonApi");
      decProto = require("decodeProtobuf");
    } catch (e) { return false; }
    if (!sendApi || typeof sendApi.encodeAndPad !== "function") return false;
    if (!decProto || typeof decProto.decodeProtobuf !== "function") return false;

  if (!window._dbinj_encodePad)
    window._dbinj_encodePad = sendApi.encodeAndPad;
  sendApi.encodeAndPad = (a) => {
    const result = window._dbinj_encodePad(a);
    try {
      const info = classify(a);
      if (info) {
        const innerPayload =
          a.deviceSentMessage?.message || a.ephemeralMessage?.message || a;
        pendingSentEntry = {
          direction: "SENT",
          timestamp: new Date().toISOString(),
          type: info.type,
          variant: info.variant,
          payload: innerPayload,
          stanzaInfo: null,
        };
      }
    } catch (e) {}
    return result;
  };

  if (!window._dbinj_decodeProto)
    window._dbinj_decodeProto = decProto.decodeProtobuf;
  decProto.decodeProtobuf = (a, b) => {
    const result = window._dbinj_decodeProto(a, b);
    if (!result || typeof result !== "object") return result;
    const firstKey = Object.keys(result).find(
      (k) => k !== "$$unknownFieldCount" && k !== "messageContextInfo"
    );
    if (!firstKey || PROTOCOL_KEYS.has(firstKey)) return result;
    try {
      const info = classify(result);
      if (info) {
        const innerPayload =
          result.deviceSentMessage?.message ||
          result.ephemeralMessage?.message ||
          result;
        emitEntry({
          direction: "RECV",
          timestamp: new Date().toISOString(),
          type: info.type,
          variant: info.variant,
          payload: innerPayload,
          stanzaInfo: lastRecvStanza,
        });
      }
    } catch (e) {}
    return result;
  };

    window.__WA_DB_MSG_HOOKED = true;
    console.log("✅ WA DB: message payload hooks armed");
    return true;
  }

  let stanzaArmed = installStanzaHooks();
  let msgArmed = installMessageHooks();
  if (!stanzaArmed || !msgArmed) {
    let tries = 0;
    const iv = setInterval(() => {
      tries++;
      if (!stanzaArmed) stanzaArmed = installStanzaHooks();
      if (!msgArmed) msgArmed = installMessageHooks();
      if ((stanzaArmed && msgArmed) || tries > 1200) clearInterval(iv);
    }, 250);
  }

  console.log("✅ WA DB Injector loaded — pairing/integrity capture enabled; waiting for WA core modules.");
})();
