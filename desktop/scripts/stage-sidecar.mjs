import { copyFileSync, mkdirSync } from "node:fs";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { spawnSync } from "node:child_process";

const desktopDir = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const repositoryDir = resolve(desktopDir, "..");
const debug = process.argv.includes("--debug");
const serviceBuildDescription = "cargo build --release --bin devicelane-service";
const buildDescription = "cargo build --release --locked --bin devicelane --bin devicelane-service";
const cargoArguments = ["build", ...(debug ? [] : ["--release"]), "--locked", "--bin", "devicelane", "--bin", "devicelane-service", "--message-format=json"];

function checked(program, args) {
  const result = spawnSync(program, args, { cwd: repositoryDir, encoding: "utf8", shell: false });
  if (result.status !== 0) throw new Error(`${program} failed: ${result.stderr.trim()}`);
  return result.stdout;
}

const rustcInfo = checked("rustc", ["-vV"]);
const targetTriple = rustcInfo.match(/^host: (.+)$/m)?.[1];
if (!targetTriple) throw new Error("rustc did not report a host target triple");

const messages = checked("cargo", cargoArguments).trim().split(/\r?\n/);
const executableSuffix = targetTriple.includes("windows") ? ".exe" : "";
for (const binary of ["devicelane-service", "devicelane"]) {
  const artifact = messages.map((line) => JSON.parse(line)).find((message) =>
    message.reason === "compiler-artifact" && message.target?.name === binary && message.executable
  );
  if (!artifact) throw new Error(`No ${binary} executable produced by ${buildDescription}; service command: ${serviceBuildDescription}`);
  const destination = join(desktopDir, "src-tauri", "binaries", `${binary}-${targetTriple}${executableSuffix}`);
  mkdirSync(dirname(destination), { recursive: true });
  copyFileSync(artifact.executable, destination);
  console.log(`Staged DeviceLane sidecar: ${destination}`);
}
