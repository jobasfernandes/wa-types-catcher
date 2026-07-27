const { chromium } = require("playwright");
const fs = require("fs");
const path = require("path");

// Perfil separa sessao e captura para rodar duas contas ao mesmo tempo
// (remetente injetando <bot>, destinatario so' capturando). "default" mantem
// os caminhos antigos para nao invalidar a sessao ja' pareada.
const PROFILE = process.env.WA_PROFILE || "default";
const IS_DEFAULT_PROFILE = PROFILE === "default";

const DATA_DIR = IS_DEFAULT_PROFILE
  ? path.join(__dirname, "data")
  : path.join(__dirname, "data", PROFILE);

// Atributos do <bot> injetado.
// Precedencia: WA_BOT_ATTRS ("k=v,k=v") > WA_AUTOMATED_TYPE (local_automated_type=...) > default.
// Default = biz_bot="1", o unico que passa o filtro do servidor e faz o selo aparecer
// (local_automated_type e' filtrado de conta nao autorizada; ver docs/ai-bubble-flag.md).
function parseBotAttrs(spec, automatedType) {
  if (spec) {
    const out = {};
    for (const pair of spec.split(",")) {
      const i = pair.indexOf("=");
      if (i > 0) out[pair.slice(0, i).trim()] = pair.slice(i + 1).trim();
    }
    return out;
  }
  if (automatedType) return { local_automated_type: automatedType };
  return { biz_bot: "1" };
}

const LAB = {
  injectBot: process.env.WA_INJECT_BOT === "1",
  forceAiRendering: process.env.WA_FORCE_AI_UI === "1",
  botAttrs: parseBotAttrs(process.env.WA_BOT_ATTRS, process.env.WA_AUTOMATED_TYPE),
  dumpStanzas: process.env.WA_DUMP_STANZAS === "1",
};

function ensureDir(dir) {
  if (!fs.existsSync(dir)) fs.mkdirSync(dir, { recursive: true });
}

ensureDir(DATA_DIR);

const DB_PREFIX = "__WA_DB__";
const LAB_PREFIX = "__WA_LAB__";

// MSG_STANZA entra aqui de proposito: eventos "system" recebem nome de arquivo unico
// (timestamp + id) em vez de dedup por tipo+variante, que e' o que o dump precisa.
const SYSTEM_TYPES = new Set([
  "TC_TOKEN", "ERROR", "LIMIT", "AB_PROP", "NOTIFICATION", "IQ_SYSTEM",
  "PAIRING", "INTEGRITY", "CALL", "MSG_STANZA"
]);

function processEntry(raw) {
  try {
    const entry = typeof raw === "string" ? JSON.parse(raw) : raw;
    if (!entry || !entry.type) return;

    const safe = (s) => String(s).replace(/[^a-zA-Z0-9._-]/g, "-");
    const direction = safe(entry.direction.toUpperCase());
    const type = safe(entry.type.toUpperCase());
    const variant = safe(entry.variant || "default");
    const chatType = entry.chatType || "UNKNOWN";
    const isSystemEvent = SYSTEM_TYPES.has(type);

    let fileName;
    if (isSystemEvent) {
      const ts = new Date(entry.timestamp || Date.now()).getTime();
      const stanzaId = entry.stanzaInfo?._attrs?.id || "";
      fileName = `${direction}_${type}_${variant}_${ts}${stanzaId ? "_" + stanzaId : ""}.json`;
    } else if (["INTERACTIVE", "BUTTONS", "LIST", "POLL", "META_AI", "BOT_INVOKE"].includes(type)) {
      const uniqueId = entry.payload?.protocolMessage?.key?.id
        || entry.stanzaInfo?._attrs?.id
        || entry.payload?.key?.id
        || Date.now();
      fileName = `${direction}_${type}_${variant}_${uniqueId}.json`;
    } else {
      fileName = `${direction}_${type}_${variant}.json`;
    }

    const subDir = isSystemEvent
      ? path.join(DATA_DIR, "SYSTEM", type)
      : path.join(DATA_DIR, direction, chatType);
    ensureDir(subDir);

    const filePath = path.join(subDir, fileName);

    if (!isSystemEvent && fs.existsSync(filePath)) return;

    const relativePath = path.relative(__dirname, filePath).replace(/\\/g, "/");

    const icon = isSystemEvent ? "🔒" : "✅";
    console.log(`\n${icon} ${isSystemEvent ? "Protocol event" : "New unique type"} detected: ${relativePath}`);
    fs.writeFileSync(filePath, JSON.stringify(entry, null, 2), "utf-8");
    console.log(`Saved in: ${relativePath}`);
  } catch (err) {
    console.error("Error processing entry:", err.message);
  }
}

async function startScraper() {
  console.log(`Starting WA Type Database Builder [profile=${PROFILE}]...`);
  console.log(
    `Lab: injectBot=${LAB.injectBot} forceAiRendering=${LAB.forceAiRendering} ` +
    `dumpStanzas=${LAB.dumpStanzas} botAttrs=${JSON.stringify(LAB.botAttrs)}`,
  );
  if (LAB.injectBot && LAB.forceAiRendering) {
    console.warn(
      "AVISO: injectBot + forceAiRendering na MESMA conta gera falso positivo.\n" +
      "  O ramo `fromMe` do label le o modelo local, entao o selo aparece mesmo se\n" +
      "  o servidor descartar o <bot>. Use injectBot no remetente e forceAiRendering no destinatario.",
    );
  }

  const userDataDir = IS_DEFAULT_PROFILE
    ? path.join(__dirname, "wa_session")
    : path.join(__dirname, `wa_session_${PROFILE}`);

  const context = await chromium.launchPersistentContext(userDataDir, {
    headless: false,
    viewport: null,
    args: [
      "--start-maximized",
      "--disable-blink-features=AutomationControlled",
    ],
  });

  context.on("close", () => process.exit(0));

  const page = context.pages()[0] || (await context.newPage());

  page.on("console", (msg) => {
    const text = msg.text();
    if (text.startsWith(DB_PREFIX)) {
      processEntry(text.slice(DB_PREFIX.length));
    } else if (text.startsWith(LAB_PREFIX)) {
      console.log(`🧪 [${PROFILE}] ${text.slice(LAB_PREFIX.length)}`);
    }
  });

  const scriptPath = path.join(__dirname, "inject.js");
  const scriptContent =
    `window.__WA_LAB = ${JSON.stringify(LAB)};\n` +
    fs.readFileSync(scriptPath, "utf8");

  // Injeta ANTES de qualquer script da pagina, em todo documento/reload, para
  // armar os hooks ja' na tela de pareamento (pair-device/pair-success +
  // passkey_prologue_request + integrity challenge MEX), nao apenas apos o login.
  await page.addInitScript(scriptContent);

  console.log("Opening WhatsApp Web (pairing/integrity capture armed)...");
  await page.goto("https://web.whatsapp.com");

  console.log(
    "Capturando handshake de pareamento + eventos de protocolo (pair-device/pair-success, passkey_prologue, integrity MEX, tctoken, erros).",
  );
  const dataRel = path.relative(__dirname, DATA_DIR).replace(/\\/g, "/");
  console.log(
    `Para reproduzir o sintoma: escaneie o QR com a conta afetada. Eventos caem em ${dataRel}/SYSTEM/{PAIRING,INTEGRITY,ERROR,...}.`,
  );

  await page.waitForSelector("#pane-side", { timeout: 0 }).catch(() => {});
  console.log("Login detectado (ou ainda na tela de pareamento). Captura segue ativa ate' fechar o navegador.");
}

startScraper().catch(console.error);
