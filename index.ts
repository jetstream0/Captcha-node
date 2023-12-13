const express = require("express");
const { createCanvas, loadImage } = require("canvas");
const { xsalsa20poly1305 } = require("@noble/ciphers/salsa");
const { randomInt, randomBytes } = require("crypto");
const fetch = require("node-fetch");
const path = require("path");

require("dotenv").config();

const app = express();

app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.set("view engine", "ejs");
app.set("views", path.join(__dirname, "templates"));
app.use(express.static("static"));
app.use(function(req, res, next) {
  res.setHeader("Access-Control-Allow-Origin", "*")
  next();
});

const port = 8080;

const hex_chars = ["0", "1", "2", "3", "4", "5", "6", "7", "8", "9", "A", "B", "C", "D", "E", "F"];

function uint8array_to_hex(uint8array: Uint8Array): string {
  let hex: string = "";
  for (let i = 0; i < uint8array.length; i++) {
    hex += hex_chars[Math.floor(uint8array[i] / 16)];
    hex += hex_chars[uint8array[i] % 16];
  }
  return hex;
}

function hex_to_uint8array(hex: string): Uint8Array {
  let uint8array: Uint8Array = new Uint8Array(hex.length / 2);
  for (let i = 0; i < hex.length / 2; i++) {
    uint8array[i] = hex_chars.indexOf(hex[i * 2]) * 16 + hex_chars.indexOf(hex[i * 2 + 1]);
  }
  return uint8array;
}

const chars: string[] = ["1", "2", "3", "4", "5", "6", "7", "8", "9", "0", "a", "b", "c", "d", "e", "f", "g", "h", "i", "j", "k", "l", "m", "n", "o", "p", "q", "r", "s", "t", "u", "v", "w", "x", "y", "z"];

function gen_code(length: number): string {
  let code = "";
  for (let i = 0; i < length; i++) {
    code += chars[randomInt(0, chars.length)].toUpperCase();
  }
  return code;
}

function _gen_key(): string {
  return uint8array_to_hex(new Uint8Array(randomBytes(32).buffer));
}

function get_time(): number {
  return Math.round((Date.now()) / 1000);
}

function gen_nonce(bytes: number): Uint8Array {
  return new Uint8Array(randomBytes(bytes).buffer);
}

function encrypt(code: string, nonce: Uint8Array): string {
  const to_encrypt: string = `${code}-${String(get_time())}`;
  return uint8array_to_hex(xsalsa20poly1305(hex_to_uint8array(process.env.KEY), nonce).encrypt(new TextEncoder().encode(to_encrypt)));
}

function decrypt(encrypted: string, nonce: string): string {
  return new TextDecoder().decode(xsalsa20poly1305(hex_to_uint8array(process.env.KEY), hex_to_uint8array(nonce)).decrypt(hex_to_uint8array(encrypted)));
}

app.get("/", async (_req, res) => {
  const response = await (await fetch(`${process.env.BASE_URL}/captcha`)).json();
  const challenge_url: string = `${process.env.BASE_URL}/challenge/${response.image}?nonce=${response.nonce}`;
  const challenge_code: string = response.code;
  const challenge_nonce: string = response.nonce;
  return res.render("index", {
    challenge_url,
    challenge_code,
    challenge_nonce,
    completed: false,
  });
});

app.post("/", async (req, res) => {
  const response = await (await fetch(`${process.env.BASE_URL}/captcha`,
    {
      method: "POST",
      headers: {
        "Accept": "application/json",
        "Content-Type": "application/json",
      },
      body: JSON.stringify({
        code: req.body.code,
        nonce: req.body.nonce,
        guess: req.body.answer,
      }),
    }
  )).json();
  if (response.success) {
    return res.render("index", {
      completed: true,
      success: true,
    });
  } else {
    return res.render("index", {
      completed: true,
      success: false,
    });
  }
});

app.get("/captcha", (_req, res) => {
  const nonce: Uint8Array = gen_nonce(24);
  const encrypted: string = encrypt(gen_code(6), nonce);
  return res.json({
    image: `${encrypted}.png`,
    code: encrypted,
    nonce: uint8array_to_hex(nonce),
  });
})

app.post("/captcha", (req, res) => {
  const current_time: number = get_time(); //in seconds
  if (!req.body.code || !req.body.nonce || !req.body.guess) return res.json({ success: false, error: "Missing code, nonce, or guess" });
  const decrypted: string = decrypt(req.body.code, req.body.nonce);
  const code: string = decrypted.split("-")[0];
  const time: string | undefined = decrypted.split("-")[1];
  if (Number(time) > current_time || Number(time) + 60 * 5 < current_time) {
    return res.json({ success: false });
  } else if (code === req.body.guess) {
    return res.json({ success: true });
  } else {
    return res.json({ success: false });
  }
});

app.get("/challenge/:encrypted.png", async (req, res) => {
  const decrypted = decrypt(req.params.encrypted, req.query.nonce);
  const code: string = decrypted.split("-")[0];
  if (!code.split("").every((c) => chars.includes(c.toLowerCase()))) {
    return "Error: invalid code";
  }
  const canvas = createCanvas(210, 70)
  const context = canvas.getContext("2d");
  for (let i = 0; i < code.length; i++) {
    const char_image = await loadImage(`./chars/${code[i].toUpperCase()}.png`);
    let width: number = char_image.width + randomInt(0, 8);
    let height: number = char_image.height + randomInt(0, 8);
    if (Math.random() > 0.5) {
      width = Math.round(width / (1 + Math.random()));
      height = Math.round(height / (1 + Math.random()));
    }
    context.drawImage(char_image, i * 30 + 4 + randomInt(5), 14 + randomInt(12), width, height);
    //unlike og ruby one, do not include the squiggly lines and obusfucations,
    //since this was made for astral credits project which does not want it
  }
  const data_url: string = await canvas.toDataURL("image/png");
  res.send(Buffer.from(data_url.split(",")[1], "base64"));
});

app.listen(port, () => {
  console.log(`Listening on port ${port}`)
});
