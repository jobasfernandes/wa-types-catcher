const { chromium } = require("playwright");
const fs = require("fs");
const path = require("path");

const DATA_DIR = path.join(__dirname, "data");
if (!fs.existsSync(DATA_DIR)) {
  fs.mkdirSync(DATA_DIR, { recursive: true });
}

const DB_PREFIX = "__WA_DB__";

function processEntry(raw) {
  try {
    const entry = typeof raw === "string" ? JSON.parse(raw) : raw;
    if (!entry || !entry.type) return;

    const direction = entry.direction.toUpperCase();
    const type = entry.type.toUpperCase();
    const variant = entry.variant || "default";

    let fileName = `${direction}_${type}_${variant}.json`;
    if (["INTERACTIVE", "BUTTONS", "LIST", "POLL"].includes(type)) {
      const uniqueId = entry.payload?.key?.id || Date.now();
      fileName = `${direction}_${type}_${variant}_${uniqueId}.json`;
    }
    const filePath = path.join(DATA_DIR, fileName);

    if (fs.existsSync(filePath)) return;

    console.log(`\n✅ New unique type detected: ${fileName}`);
    fs.writeFileSync(filePath, JSON.stringify(entry, null, 2), "utf-8");
    console.log(`Saved in: data/${fileName}`);
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

  console.log("Injecting message type extractor (Stanza + Protobuf)...");
  await page.evaluate(scriptContent);

  console.log(
    "Listening for new messages... (Send/Receive messages on your phone to populate the DB)",
  );
}

startScraper().catch(console.error);
