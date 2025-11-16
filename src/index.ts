import { Command } from "commander";
import * as fs from "fs";
import * as path from "path";
import * as readline from "readline";

import {
  generateSecret,
  buildURI,
  generateQRCode,
  verifyToken,
  generateToken
} from "./totp";

function ask(q: string): Promise<string> {
  const rl = readline.createInterface({ input: process.stdin, output: process.stdout });
  return new Promise(resolve => rl.question(q, ans => { rl.close(); resolve(ans); }));
}

const program = new Command();

program
  .name("totp-setup")
  .description("Create & manage TOTP secrets")
  .version("0.2.0");


program
  .command("new")
  .argument("<account>", "Account name, e.g., email / username")
  .option("--issuer <issuer>", "Application name", "MyDemoApp")
  .description("Create a new TOTP secret and provide a web QR code")
  .action(async (account, options) => {
    const issuer = options.issuer;

    console.log(`Creating TOTP secret for account ${account}...`);

    const secret = generateSecret();
    const uri = buildURI(secret, account, issuer);
    const dataUrl = await generateQRCode(uri);

    const htmlContent = `
<!DOCTYPE html>
<html>
<head><meta charset="utf-8"><title>TOTP Setup</title></head>
<body>
  <h2>${issuer} - QRCode</h2>
  <p>Account: ${account}</p>
  <img src="${dataUrl}" />
  <p>otpauth:// URI:</p>
  <pre>${uri}</pre>
  <p>After scanning, please enter the code in the command line.</p>
</body></html>
`;

    const tmpHtmlPath = path.join(process.cwd(), "otp-temp.html");
    fs.writeFileSync(tmpHtmlPath, htmlContent, "utf8");

    const http = await import("http");
    const server = http.createServer((req, res) => {
      if (req.url === "/" || req.url === "/otp") {
        res.writeHead(200, { "Content-Type": "text/html; charset=utf-8" });
        return res.end(htmlContent);
      }
      res.writeHead(404);
      res.end("Not Found");
    });

    const PORT = 3000;

    server.listen(PORT, () => {
      console.log(`Server Start at:  http://127.0.0.1:${PORT}/otp`);
      console.log("Please open the QR code page in your browser and scan it with the authenticator.");
    });

    const token = (await ask("Please Input the code in Authenticator: ")).trim();

    if (!/^[0-9]{6}$/.test(token)) {
      console.error("❌ Wrong format! Expected a 6-digit code. Shutting down server.");
      server.close();
      fs.unlinkSync(tmpHtmlPath);
      process.exit(1);
    }

    if (!verifyToken(secret, token)) {
      console.error("❌ Verification failed! Shutting down server.");
      server.close();
      fs.unlinkSync(tmpHtmlPath);
      process.exit(1);
    }

    console.log("✅ Success!");
    console.log(`Account ${account} / ${issuer} \n secret: ${secret}`);

    server.close();
    fs.unlinkSync(tmpHtmlPath);

    console.log("Server Shutdown");

    return;
  });

program.parse();
