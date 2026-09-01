import { copyFileSync, mkdirSync } from "node:fs";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { spawnSync } from "node:child_process";

const desktopDir = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const repositoryDir = resolve(desktopDir, "..");
const debug = process.argv.includes("--debug");
const buildDescription = "cargo build --release --bin devicelane-service";
const cargoArguments = ["build", ...(debug ? [] : ["--release"]), "--locked", "--bin", "devicelane-service", "--message-format=json"];

function checked(program, args) {
  const result = spawnSync(program, args, { cwd: repositoryDir, encoding: "utf8", shell: false });
  if (result.status !== 0) throw new Error(`${program} failed: ${result.stderr.trim()}`);
  return result.stdout;
}

const rustcInfo = checked("rustc", ["-vV"]);
const targetTriple = rustcInfo.match(/^host: (.+)$/m)?.[1];
if (!targetTriple) throw new Error("rustc did not report a host target triple");

const messages = checked("cargo", cargoArguments).trim().split(/\r?\n/);
const artifact = messages.map((line) => JSON.parse(line)).find((message) =>
  message.reason === "compiler-artifact" && message.target?.name === "devicelane-service" && message.executable
);
if (!artifact) throw new Error(`No executable produced by ${buildDescription}`);

const executableSuffix = targetTriple.includes("windows") ? ".exe" : "";
const destination = join(desktopDir, "src-tauri", "binaries", `devicelane-service-${targetTriple}${executableSuffix}`);
mkdirSync(dirname(destination), { recursive: true });
copyFileSync(artifact.executable, destination);
console.log(`Staged DeviceLane sidecar: ${destination}`);
