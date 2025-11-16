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
