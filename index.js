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
  "TC_TOKEN", "ERROR", "LIMIT", "AB_PROP", "NOTIFICATION", "IQ_SYSTEM"
]);

function processEntry(raw) {
  try {
    const entry = typeof raw === "string" ? JSON.parse(raw) : raw;
    if (!entry || !entry.type) return;

    const direction = entry.direction.toUpperCase();
    const type = entry.type.toUpperCase();
    const variant = entry.variant || "default";
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

  const page = context.pages()[0] || (await context.newPage());

  page.on("console", (msg) => {
    const text = msg.text();
    if (text.startsWith(DB_PREFIX)) {
      processEntry(text.slice(DB_PREFIX.length));
    }
  });

  console.log("Opening WhatsApp Web...");
  await page.goto("https://web.whatsapp.com");

  console.log("Waiting for interface to load...");
  await page.waitForSelector("#pane-side", { timeout: 0 });

  console.log("WhatsApp Web loaded successfully!");

  await page.waitForTimeout(2000);

  const scriptPath = path.join(__dirname, "inject.js");
  const scriptContent = fs.readFileSync(scriptPath, "utf8");

  console.log("Injecting message type extractor (Stanza + Protobuf + tctoken/limits)...");
  await page.evaluate(scriptContent);

  console.log(
    "Listening for messages + protocol events... (tctoken, reporting, error codes, AB props)",
  );
}

startScraper().catch(console.error);
