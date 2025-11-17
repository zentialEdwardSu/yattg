import { Command } from "commander";
import * as fs from "fs";
import * as path from "path";
import * as readline from "readline";

import {
  generateSecret,
  buildURI,
  generateQRCode,
  verifyToken,
  generateToken,
  generateTOTP,
  verifyTOTP
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

    process.exit(0);
  });

program
  .command("compare")
  .argument("[secret]", "Base32 secret to test; prompts when omitted")
  .description("Compare otplib authenticator output with the custom TOTP implementation")
  .action(async secretArg => {
    const provided = secretArg ?? (await ask("Please input the base32 secret: "));
    const secret = provided.trim();

    if (!secret) {
      console.error("❌ Secret is required for comparison.");
      process.exit(1);
    }

    const stepSeconds = 30;
    let lastLineLength = 0;
    let ticking = true;
    let rendering = false;
    let intervalId: NodeJS.Timeout | undefined;

    const render = async () => {
      if (!ticking || rendering) return;
      rendering = true;
      try {
        const now = Date.now();
        const msIntoWindow = now % (stepSeconds * 1000);
        const remaining = Math.ceil((stepSeconds * 1000 - msIntoWindow) / 1000);

        const [fromAuthenticator, fromCustom] = await Promise.all([
          Promise.resolve(generateToken(secret)),
          generateTOTP(secret, now)
        ]);

        const match = fromAuthenticator === fromCustom;
        const line = `authenticator: ${fromAuthenticator} | custom: ${fromCustom} | remaining: ${remaining}s | ${match ? "✅ match" : "❌ mismatch"}`;

        const padding = Math.max(0, lastLineLength - line.length);
        process.stdout.write(`\r${line}${" ".repeat(padding)}`);
        lastLineLength = line.length;
        if (!match) process.exitCode = 1;
      } catch (err) {
        console.error("\n❌ Error while generating tokens:", err);
        stop(1);
      } finally {
        rendering = false;
      }
    };

    const stop = (code = 0) => {
      if (!ticking) return;
      ticking = false;
      if (intervalId) clearInterval(intervalId);
      process.stdout.write("\nExiting comparator.\n");
      if (process.stdin.isTTY) {
        process.stdin.setRawMode(false);
      }
      process.stdin.pause();
      process.exit(code);
    };

    console.log("Press q to quit.");
    await render();
    intervalId = setInterval(render, 1000);

    if (process.stdin.isTTY) {
      process.stdin.setRawMode(true);
      process.stdin.resume();
      process.stdin.setEncoding("utf8");
      process.stdin.on("data", chunk => {
        const input = typeof chunk === "string" ? chunk : chunk.toString("utf8");
        if (input === "q" || input === "Q") {
          stop(0);
        } else if (input === "\u0003") {
          stop(0);
        }
      });
    } else {
      await new Promise(resolve => setTimeout(resolve, stepSeconds * 1000));
      stop(0);
    }
  });

program
  .command("verify")
  .argument("[secret]", "Base32 secret to test; prompts when omitted")
  .option("--token <token>", "Token code to validate; prompts when omitted")
  .option("--window <steps>", "Number of 30s windows to tolerate on each side", "1")
  .description("Check custom verify implementation against otplib")
  .action(async (secretArg, options) => {
    const providedSecret = secretArg ?? (await ask("Please input the base32 secret: "));
    const secret = providedSecret.trim();

    if (!secret) {
      console.error("❌ Secret is required for verification.");
      process.exit(1);
    }

    const providedToken = options.token ?? (await ask("Please input the token to verify: "));
    const token = providedToken.trim();

    if (!token) {
      console.error("❌ Token is required for verification.");
      process.exit(1);
    }

    const parsedWindow = Number.parseInt(String(options.window ?? "1"), 10);
    if (Number.isNaN(parsedWindow) || parsedWindow < 0) {
      console.error("❌ Window must be a non-negative integer.");
      process.exit(1);
    }

    const otplibResult = verifyToken(secret, token);
    const customResult = await verifyTOTP(token, secret, parsedWindow);

    console.log(`otplib: ${otplibResult ? "✅ valid" : "❌ invalid"}`);
    console.log(`custom : ${customResult ? "✅ valid" : "❌ invalid"}`);

    if (otplibResult === customResult) {
      console.log("✅ Results match.");
    } else {
      console.error("❌ Results differ between implementations.");
      process.exitCode = 1;
    }
  });

program.parse();
