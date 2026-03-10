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

  function parseBinaryNode(node, depth = 0) {
    if (!node || typeof node !== "object") return null;
    if (node instanceof Uint8Array || node instanceof ArrayBuffer) {
      return `<Buffer ${node.byteLength || node.length}b>`;
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
    } else if (
      node.content instanceof Uint8Array ||
      node.content instanceof ArrayBuffer
    ) {
      result._content = `<Buffer ${node.content.byteLength || node.content.length}b>`;
    } else if (node.content !== null && node.content !== undefined) {
      result._content = node.content;
    }

    return result;
  }

  function toJSON(obj) {
    const seen = new WeakSet();
    return JSON.stringify(
      obj,
      function (key, value) {
        if (key === "$$unknownFieldCount") return undefined;
        if (key === "messageSecret") return "<Buffer 32b>";
        if (key === "deviceListMetadata") return undefined;
        if (key === "messageContextInfo") return undefined;
        if (value instanceof Uint8Array) return `<Buffer ${value.length}b>`;
        if (value instanceof ArrayBuffer)
          return `<Buffer ${value.byteLength}b>`;
        if (key === "buttonParamsJson" && typeof value === "string") {
          try {
            return JSON.parse(value);
          } catch (e) {
            return value;
          }
        }
        if (value && typeof value === "object" && value.$1) {
          const j = value.$1;
          if (j.user && j.server) return `${j.user}@${j.server}`;
          if (j.user && j.type !== undefined) return `${j.user}@lid`;
          return value.toString ? value.toString() : value;
        }
        if (typeof value === "object" && value !== null) {
          if (seen.has(value)) return "[Circular]";
          seen.add(value);
        }
        return typeof value === "bigint" ? value.toString() : value;
      },
      2,
    );
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
      const stanzaJSON = parseBinaryNode(result);
      if (stanzaJSON && stanzaJSON._tag === "message") {
        lastRecvStanza = stanzaJSON;
      }
    } catch (err) {
      console.error("Interceptor Error (decodeStanza):", err);
    }
    return result;
  };

  if (!window._dbinj_encodeStanza)
    window._dbinj_encodeStanza = require("WAWap").encodeStanza;
  require("WAWap").encodeStanza = async (stanza) => {
    try {
      const stanzaJSON = parseBinaryNode(stanza);
      if (stanzaJSON && stanzaJSON._tag === "message") {
        lastSentStanza = stanzaJSON;
      }
    } catch (err) {
      console.error("Interceptor Error (encodeStanza):", err);
    }
    return window._dbinj_encodeStanza(stanza);
  };

  if (!window._dbinj_encodePad)
    window._dbinj_encodePad = require("WAWebSendMsgCommonApi").encodeAndPad;
  require("WAWebSendMsgCommonApi").encodeAndPad = (a) => {
    const result = window._dbinj_encodePad(a);
    try {
      const info = classify(a);

      setTimeout(() => {
        try {
          if (info && window.saveToDatabase) {
            const innerPayload =
              a.deviceSentMessage?.message || a.ephemeralMessage?.message || a;
            const entryObj = {
              direction: "SENT",
              timestamp: new Date().toISOString(),
              type: info.type,
              variant: info.variant,
              payload: JSON.parse(toJSON(innerPayload)),
              stanzaInfo: lastSentStanza,
            };
            window.saveToDatabase(entryObj);
          }
        } catch (innerErr) {
          console.error("Async Error (encodeAndPad):", innerErr);
        }
      }, 50);
    } catch (err) {
      console.error("Interceptor Error (encodeAndPad):", err);
    }

    return result;
  };

  if (!window._dbinj_decodeProto)
    window._dbinj_decodeProto = require("decodeProtobuf").decodeProtobuf;
  require("decodeProtobuf").decodeProtobuf = (a, b) => {
    const result = window._dbinj_decodeProto(a, b);
    try {
      const info = classify(result);

      if (info && window.saveToDatabase) {
        const innerPayload =
          result.deviceSentMessage?.message ||
          result.ephemeralMessage?.message ||
          result;
        const entryObj = {
          direction: "RECV",
          timestamp: new Date().toISOString(),
          type: info.type,
          variant: info.variant,
          payload: JSON.parse(toJSON(innerPayload)),
          stanzaInfo: lastRecvStanza,
        };
        window.saveToDatabase(entryObj);
      }
    } catch (err) {
      console.error("Interceptor Error (decodeProtobuf):", err);
    }

    return result;
  };

  console.log("✅ WA DB Injector operational! Intercepting Stanza + Payload.");
})();
