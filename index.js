const { chromium } = require("playwright");
const fs = require("fs");
const path = require("path");

const DATA_DIR = path.join(__dirname, "data");

function ensureDir(dir) {
  if (!fs.existsSync(dir)) fs.mkdirSync(dir, { recursive: true });
}

ensureDir(DATA_DIR);

const DB_PREFIX = "__WA_DB__";

const SYSTEM_TYPES = new Set([
  "TC_TOKEN", "ERROR", "LIMIT", "AB_PROP", "NOTIFICATION", "IQ_SYSTEM",
  "PAIRING", "INTEGRITY"
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

    const relativePath = isSystemEvent
      ? `data/SYSTEM/${type}/${fileName}`
      : `data/${direction}/${chatType}/${fileName}`;

    const icon = isSystemEvent ? "🔒" : "✅";
    console.log(`\n${icon} ${isSystemEvent ? "Protocol event" : "New unique type"} detected: ${relativePath}`);
    fs.writeFileSync(filePath, JSON.stringify(entry, null, 2), "utf-8");
    console.log(`Saved in: ${relativePath}`);
  } catch (err) {
    console.error("Error processing entry:", err.message);
  }
}

async function startScraper() {
  console.log("Starting WA Type Database Builder...");

  const userDataDir = path.join(__dirname, "wa_session");

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
    }
  });

  const scriptPath = path.join(__dirname, "inject.js");
  const scriptContent = fs.readFileSync(scriptPath, "utf8");

  // Injeta ANTES de qualquer script da pagina, em todo documento/reload, para
  // armar os hooks ja' na tela de pareamento (pair-device/pair-success +
  // passkey_prologue_request + integrity challenge MEX), nao apenas apos o login.
  await page.addInitScript(scriptContent);

  console.log("Opening WhatsApp Web (pairing/integrity capture armed)...");
  await page.goto("https://web.whatsapp.com");

  console.log(
    "Capturando handshake de pareamento + eventos de protocolo (pair-device/pair-success, passkey_prologue, integrity MEX, tctoken, erros).",
  );
  console.log(
    "Para reproduzir o sintoma: escaneie o QR com a conta afetada. Eventos caem em data/SYSTEM/{PAIRING,INTEGRITY,ERROR,...}.",
  );

  await page.waitForSelector("#pane-side", { timeout: 0 }).catch(() => {});
  console.log("Login detectado (ou ainda na tela de pareamento). Captura segue ativa ate' fechar o navegador.");
}

startScraper().catch(console.error);
