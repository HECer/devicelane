# DeviceLane for npm

Installs the DeviceLane command-line tools without compiling Rust locally.

```sh
npm install --global devicelane
devicelane --version
```

The first invocation downloads the matching native binary from the corresponding
[GitHub Release](https://github.com/HECer/devicelane/releases), verifies it against
the published SHA-256 manifest, and stores it in the user's cache directory. No
package lifecycle scripts run during installation.

Commands: `devicelane` (unified client with `mesh`, `activities`, `approvals`, `policy`, and
`audit` authenticated local dashboard commands), `devicelane-service`,
`devicelane-agent`, and `devicelane-registry`. The legacy `mesh-cli`,
`mesh-agent`, and `mesh-registry` command names remain available.

DeviceLane is an experimental developer preview. Use it only on a trusted LAN or
private VPN; do not expose its ports directly to the public internet.
