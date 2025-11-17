import { authenticator } from "otplib";
import QRCode from "qrcode";

export function generateSecret(): string {
  return authenticator.generateSecret(40);
}

export function buildURI(secret: string, account: string, issuer: string) {
  return authenticator.keyuri(account, issuer, secret);
}

export async function generateQRCode(otpauth: string): Promise<string> {
  return QRCode.toDataURL(otpauth);
}

export function verifyToken(secret: string, token: string) {
  return authenticator.check(token, secret);
}

export function generateToken(secret: string) {
  return authenticator.generate(secret);
}

export async function generateTOTP(secretBase32: string, forTime?: number, digits = 6) {
  const step = 30;
  const time = Math.floor((forTime ?? Date.now()) / 1000 / step);

  const msg = new ArrayBuffer(8);
  const view = new DataView(msg);
  view.setUint32(4, time);

  const key = base32ToBytes(secretBase32);

  const cryptoKey = await crypto.subtle.importKey(
    "raw",
    key,
    { name: "HMAC", hash: "SHA-1" },
    false,
    ["sign"]
  );

  const hmac = new Uint8Array(await crypto.subtle.sign("HMAC", cryptoKey, msg));
  const offset = hmac[hmac.length - 1] & 0xf;

  const binary =
    ((hmac[offset] & 0x7f) << 24) |
    ((hmac[offset + 1] & 0xff) << 16) |
    ((hmac[offset + 2] & 0xff) << 8) |
    (hmac[offset + 3] & 0xff);

  return (binary % 10 ** digits).toString().padStart(digits, "0");
}

// Base32 decode
function base32ToBytes(base32: string): Uint8Array<ArrayBuffer> {
  const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
  let bits = "";
  for (const char of base32.replace(/=+$/, "")) {
    const val = alphabet.indexOf(char.toUpperCase());
    if (val < 0) continue;
    bits += val.toString(2).padStart(5, "0");
  }
  const bytes = bits.match(/.{8}/g)?.map(b => parseInt(b, 2)) ?? [];
  return new Uint8Array(bytes);
}

export async function verifyTOTP(userPIN: string, secret: string, window = 1) {
  const now = Date.now();
  const step = 30 * 1000;

  for (let w = -window; w <= window; w++) {
    const time = now + w * step;
    const expected = await generateTOTP(secret, time);
    if (userPIN === expected) return true;
  }

  return false;
}