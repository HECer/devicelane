const ASSETS = new Map([
  ['win32:x64', 'devicelane-windows-x64.zip'],
  ['linux:x64', 'devicelane-linux-x64.tar.gz'],
  ['darwin:arm64', 'devicelane-macos-arm64.tar.gz'],
  ['darwin:x64', 'devicelane-macos-x64.tar.gz'],
]);

export function assetFor(platform, arch) {
  const asset = ASSETS.get(`${platform}:${arch}`);
  if (!asset) {
    throw new Error(`Unsupported platform: ${platform}/${arch}`);
  }
  return asset;
}

export function executableName(binary, platform) {
  return platform === 'win32' ? `${binary}.exe` : binary;
}
