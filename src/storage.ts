import * as fs from "fs";
import * as path from "path";

export interface StoredSecret {
  account: string;
  issuer: string;
  secret: string;
}

const FILE = path.join(process.cwd(), "totp-secrets.json");

export function loadSecrets(): StoredSecret[] {
  if (!fs.existsSync(FILE)) return [];
  const text = fs.readFileSync(FILE, "utf8");
  return JSON.parse(text);
}

export function saveSecrets(secrets: StoredSecret[]) {
  fs.writeFileSync(FILE, JSON.stringify(secrets, null, 2), "utf8");
}

export function addSecret(item: StoredSecret) {
  const list = loadSecrets();
  const exists = list.find(s => s.account === item.account);
  if (exists) throw new Error(`Account ${item.account} already exists`);
  list.push(item);
  saveSecrets(list);
}

export function removeSecret(account: string) {
  const list = loadSecrets();
  const filtered = list.filter(s => s.account !== account);
  saveSecrets(filtered);
}

export function findSecret(account: string): StoredSecret | undefined {
  return loadSecrets().find(s => s.account === account);
}
