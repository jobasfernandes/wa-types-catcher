/**
 * WA Type Database Builder - Injection Script
 * Catch the Stanza XMPP (BinaryNode) + Payload Protobuf along the sending/receiving
 * to build the reference database with the complete structure.
 */
(function () {
  "use strict";

  if (window.__WA_DB_INJECT) return;
  window.__WA_DB_INJECT = true;

  let lastSentStanza = null;
  let lastRecvStanza = null;

  const PROTOCOL_KEYS = new Set([
    "serverHello", "ratchetKey", "preKeyId", "baseKey",
    "leaf", "serial", "field", "value", "timestamp",
    "currentMsg", "identityKey", "registrationId",
    "signedPreKey", "preKey", "senderKey",
    "encResultMessage", "preKeyWhisperMessage",
    "whiskeyTransport", "hsm"
  ]);

  function isBufferLike(node) {
    if (!node) return false;
    if (node instanceof Uint8Array || node instanceof ArrayBuffer) return true;
    const name = node.constructor && node.constructor.name;
    if (name === "Uint8Array" || name === "ArrayBuffer" || name === "Buffer") return true;
    if (node.buffer && typeof node.byteLength === "number") return true;
    return false;
  }

  function parseBinaryNode(node, depth = 0) {
    if (depth > 15) return "<Max Depth Exceeded>";
    if (!node || typeof node !== "object") return null;
    if (isBufferLike(node)) {
      return `<Buffer ${node.byteLength !== undefined ? node.byteLength : node.length}b>`;
    }

    const result = {};
    if (node.tag) result._tag = node.tag;

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
      result._content = `<Buffer ${node.content.byteLength !== undefined ? node.content.byteLength : node.content.length}b>`;
    } else if (node.content !== null && node.content !== undefined) {
      result._content = node.content;
    }

    return result;
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

  function emitEntry(obj) {
    try {
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
      if (t === 14 || t === "MESSAGE_EDIT")
        return { type: "EDIT", variant: "edit", payload: decoded };
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

  if (!window._dbinj_decodeStanza)
    window._dbinj_decodeStanza = require("WAWap").decodeStanza;
  require("WAWap").decodeStanza = async (e, t) => {
    const result = await window._dbinj_decodeStanza(e, t);
    try {
      if (result && result.tag === "message") {
        const stanzaJSON = parseBinaryNode(result);
        if (stanzaJSON) {
          lastRecvStanza = stanzaJSON;
        }
      }
    } catch (err) {}
    return result;
  };

  if (!window._dbinj_encodeStanza)
    window._dbinj_encodeStanza = require("WAWap").encodeStanza;
  require("WAWap").encodeStanza = (stanza) => {
    try {
      if (stanza && stanza.tag === "message") {
        const stanzaJSON = parseBinaryNode(stanza);
        if (stanzaJSON) {
          lastSentStanza = stanzaJSON;
        }
      }
    } catch (err) {}
    return window._dbinj_encodeStanza(stanza);
  };

  if (!window._dbinj_encodePad)
    window._dbinj_encodePad = require("WAWebSendMsgCommonApi").encodeAndPad;
  require("WAWebSendMsgCommonApi").encodeAndPad = (a) => {
    const result = window._dbinj_encodePad(a);
    try {
      const info = classify(a);
      if (info) {
        const innerPayload =
          a.deviceSentMessage?.message || a.ephemeralMessage?.message || a;
        emitEntry({
          direction: "SENT",
          timestamp: new Date().toISOString(),
          type: info.type,
          variant: info.variant,
          payload: innerPayload,
          stanzaInfo: lastSentStanza,
        });
      }
    } catch (e) {}
    return result;
  };

  if (!window._dbinj_decodeProto)
    window._dbinj_decodeProto = require("decodeProtobuf").decodeProtobuf;
  require("decodeProtobuf").decodeProtobuf = (a, b) => {
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

  console.log("✅ WA DB Injector operational! Intercepting Stanza + Payload.");
})();
