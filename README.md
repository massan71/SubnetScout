# SubnetScout

Native macOS network scanner (SwiftUI) built on **nmap**: subnet discovery, security audit and reports.

> ⚠️ Only use it on networks you own or are explicitly authorized to test.

## Requirements

- macOS 14+
- nmap: `brew install nmap` (not bundled with the app because of its NPSL license)
- Xcode (or the Command Line Tools with Swift 6) to build

## Install

```bash
brew install --cask massan71/tap/subnetscout
```

This also installs the `nmap` formula. Alternatively, download the zip from the [releases](https://github.com/massan71/SubnetScout/releases).
The app is not notarized by Apple: the cask removes the quarantine flag, while with the zip you need **Open Anyway** in System Settings › Privacy & Security.

## Build and run

```bash
swift run SubnetScout          # development
scripts/bundle.sh --open       # builds build/SubnetScout.app (universal) and opens it
swift test                     # tests (including a real scan of 127.0.0.1)
```

To work in Xcode: `open Package.swift`.

Icon: `swift scripts/make-icon.swift` regenerates `Resources/AppIcon.icns` (drawn with CoreGraphics).

Release: `scripts/release.sh 0.6.0 release-notes/0.6.0.md` (tests, universal build, verified zip, tag, GitHub release and Homebrew cask update).

If `xcode-select` points to the Command Line Tools, prefix commands with
`DEVELOPER_DIR=/Applications/Xcode.app/Contents/Developer`.

## Privileged helper

When installed, every scan runs through a root daemon (`SubnetScoutHelper`, registered with
`SMAppService`): no password prompts, and no macOS local network limits. **As administrator**
only adds OS detection, UDP and the DHCP probe.

1. Click **Install Helper…** in the sidebar (or in the setup assistant)
2. Approve SubnetScout in *System Settings › General › Login Items & Extensions*

Over XPC the helper only exposes “run profile X on targets Y”. Security measures:
- **The helper builds the nmap arguments** and re-validates profile and targets, so a client cannot make it run arbitrary commands as root.
- **Private networks only**: targets must be private, link-local, CGNAT or loopback addresses. Hostnames are resolved and replaced by the verified IPs.
- **Verified client**: it only accepts connections from the app signed with the same certificate (or, with a Developer ID, the same Team ID).
- **Root-owned nmap only**: it runs nmap only if the binary, libraries, NSE scripts and folders are owned by root and not writable by others (`TrustedNmap`).
  - **Homebrew's nmap does not qualify**, because it belongs to your user: running it as root without a password would give root to any program. In that case the app falls back to asking for your password.
  - To use the helper, also install the **official package from nmap.org**. Since 7.99 its installer puts nmap in `/Applications/nmap.app`, which the admin group can modify, so it is not trusted as is.
  - Click **Copy nmap to Protected Location…**: after your administrator password, the helper copies it to `/Library/Application Support/SubnetScout/nmap` (root:wheel) and checks every file against the installer receipt. Repeat this after updating nmap.
  - MacPorts and older installers that used `/usr/local/bin/nmap` also work.
  - `@rpath`/`@executable_path` libraries are resolved and checked one by one.
- **Isolated environment**: empty environment, cwd `/`, at most 2 concurrent scans. It exits after 30 s of inactivity and launchd restarts it on demand.

Uninstall: use the button in the app, or delete the app. The protected copy of nmap stays:
remove it with `sudo rm -rf "/Library/Application Support/SubnetScout"`.

### Signing, macOS permissions and the helper

- `bundle.sh` signs with the **“SubnetScout Code Signing”** certificate if it is in the keychain, otherwise ad hoc.
  With the certificate, the app and the helper verify each other (`certificate root = H"…"`).
- **Local Network**: macOS can deny the permission to the app even when the switch in Settings is on, for example
  after a signature change or with several copies of the app sharing the same bundle ID. That is why, when the helper
  is active, it reads the ARP table and looks for Bonjour devices and UPnP routers: as a system daemon it is not subject
  to that permission. Without the helper, the Network view warns you if the local network is blocked.
- **Helper approval**: without a Developer ID, macOS ties the approval to the hash of the helper binary.
  When the helper changes, click **Reinstall** and approve it again.
- **Keychain**: the scan history is encrypted with a key stored in the Keychain. Without a Developer ID, macOS ties
  access to the binary hash, so after every update it asks again (“Always Allow”). The app stays usable meanwhile.
- **Install only one copy**: keep the app only in `/Applications`. Two copies with the same bundle ID confuse
  macOS permissions.
- Diagnostics: `/Applications/SubnetScout.app/Contents/MacOS/SubnetScout --diagnose-network`.
- Visual check: `… --qa-snapshots <folder>` saves a screenshot of the main views (using the real history).

## Features

| Area | What it does |
|---|---|
| **Discovery** | Names and models from Bonjour/mDNS (printers, speakers, TVs, smart devices). Detects interface and subnet automatically, ARP/ping sweep, MAC addresses from the ARP table even without root, vendor from nmap's OUI database, randomized MACs, the gateway and the device type |
| **Profiles** | Discovery · Quick (top 100) · Standard + audit (top 1000 + scripts) · Full (65535 TCP + main UDP ports) |
| **Administrator** | OS detection, UDP and DHCP probe; without the helper, the password is requested with the standard macOS dialog |
| **Audit** | ~35 rules: Telnet, anonymous FTP, SMBv1, SMB signing, obsolete or weak TLS, weak DH, expired or self-signed certificates, HTTPS without HSTS, risky HTTP methods, RDP without NLA, VNC without a password, exposed databases, Docker API, SNMP `public`, weak SSH keys… |
| **Network** | Gateway MAC changed or shared by another IP (ARP spoofing), rogue DHCP servers (`broadcast-dhcp-discover`, as administrator), unusual DNS, UPnP routers and **ports open to the Internet** (IGD mapping table), reachable router management |
| **CVE** | Optional and off by default: the CPEs detected by nmap (`-sV`) are looked up in NIST's NVD database. Only product and version are sent, never device data. Responses are cached for 7 days, actively exploited CVEs (CISA KEV) are flagged, optional NVD API key stored in the Keychain |
| **Schedule** | Automatic scans (hourly, every 6 hours, daily, weekly) through the helper, without a password. Notifications only when something changes (new devices, ports, issues, CVEs) and only with counts. Menu bar icon and open at login |
| **Risk** | Score 0–100 per host and per network, grade A–F |
| **History** | Every scan is stored encrypted (AES-256-GCM, key in the Keychain) in `~/Library/Application Support/SubnetScout/Scans`. The diff with the previous scan shows new devices, opened or closed ports and new issues |
| **Known devices** | Devices marked as known no longer show the “NEW” badge |
| **Report** | Self-contained HTML (light and dark, printable to PDF from the browser, strict CSP), CSV per port, full JSON |

## Layout

```
Sources/ScanKit/          engine, no UI (testable, reusable from a CLI)
  ScanProfile.swift       profiles → nmap arguments, target validation
  NmapRunner.swift        Process + XML on stdout, progress, cancellation, password mode
  NmapXMLParser.swift     SAX parser for -oX output
  NetworkInfo.swift       interfaces (getifaddrs), gateway, ARP table, DHCP lease
  AuditEngine.swift       service audit rules → Finding
  NetworkAudit.swift      network rules (ARP spoofing, DHCP, DNS, UPnP)
  CVE.swift               NVD client, cache, CVE findings
  Bonjour.swift           DNS-SD discovery through mDNSResponder
  UPnPInspector.swift     SSDP + read-only IGD port mappings
  TrustedNmap.swift       root-ownership and library checks for nmap
  ScanEngine.swift        orchestration: scan → parse → enrich → audit
  ScanHistoryStore.swift  encrypted history
  ReportGenerator.swift   HTML and CSV
Sources/SubnetScout/      SwiftUI app
Sources/SubnetScoutHelper/  privileged helper (XPC)
Tests/ScanKitTests/       Swift Testing with XML fixtures, fake NVD, real localhost scan
```

## Roadmap

- [x] Privileged helper (`SMAppService` + XPC) with progress and cancellation
- [x] Names and models from Bonjour/mDNS
- [x] CVE correlation from service versions (NVD API, optional)
- [x] Scheduled scans and change notifications
- [x] Menu bar app
- [x] English interface
- [x] App icon
- [ ] Native PDF export (WKWebView + NSPrintOperation)
- [ ] Visual network map
- [ ] IPv6 discovery
- [ ] Default credential check (separate, explicitly enabled)

## License

MIT, see [LICENSE](LICENSE). nmap is distributed separately under its own license (NPSL).
