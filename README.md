# PC Hardening Provisioning Tool

An open-source, self-elevating PowerShell + WinForms GUI for applying Windows
privacy / telemetry / Copilot-AI hardening settings — every option free, no
paywall. Organized under the same category headings as O&O ShutUp10 so it's
easy to cross-reference, but it's an independent implementation: every
registry key was pulled from Microsoft's own Group Policy (ADMX)
documentation, the Policy CSP reference, or Microsoft Learn — not from
ShutUp10's code.

## Screenshots

**Privacy, App Privacy, Security, and the start of Microsoft Edge, with the
Recommended column visible:**
![Privacy, Security, and Microsoft Edge settings, showing the Category, Recommended, Setting, Current State, and Description columns](docs/screenshots/screenshot-privacy-security-edge.png)

**Microsoft Edge (continued), Cortana, Copilot & Windows AI, Location
Services, User Behavior, Windows Update, Windows Explorer, Defender,
Search, Taskbar, Miscellaneous, and Gaming:**
![Remaining categories including Copilot & Windows AI, Windows Update, and Miscellaneous settings](docs/screenshots/screenshot-edge-ai-update-misc.png)

## Status: 119 settings mapped, across all 16 ShutUp10-style categories

Privacy · Activity History and Clipboard · App Privacy · Security ·
Microsoft Edge · Cortana (Personal Assistant) · Copilot & Windows AI ·
Location Services · User Behavior · Windows Update · Windows Explorer ·
Microsoft Defender and Microsoft SpyNet · Search · Taskbar · Miscellaneous ·
Gaming.

Each setting also carries a **Recommended: Yes / Limited / No** rating
(72 Yes, 41 Limited, 6 No) — see "How Recommended is decided" below.

This is **not yet the full ~339 items** ShutUp10 exposes. Every setting here
was included because I could find a documented, sourced registry/policy
value for it — I deliberately left out entries I couldn't verify rather than
guess and risk a wrong key. See **"Not yet mapped"** below for the backlog;
contributions that add a sourced key for any of those are very welcome.

## Files
- `PC-Hardening-Tool.ps1` — the tool (GUI + silent modes).
- `SampleProfile.json` — an example checked/unchecked profile for unattended
  provisioning (kept conservative — see "Items marked NOT recommended" below).
- `LICENSE` — MIT.

## Interactive use
```powershell
.\PC-Hardening-Tool.ps1
```
- Re-launches itself elevated (UAC prompt) automatically if not already admin.
- **Refresh Status** reads the live registry and checks/colors each item
  (green "Hardened" / orange "Default" / gray "Not Set").
- Every setting has a **Recommended** column: **Yes** (green), **Limited**
  (orange), or **No** (red) — see "How Recommended is decided" below.
- **Select Recommended** checks every `Yes`-rated setting in one click — the
  fast path for "lock this workstation down for privacy/AI without breaking
  anything." Nothing rated `Limited` or `No` gets auto-checked; review those
  individually.
- Check/uncheck boxes yourself for anything else, then **Apply Checked**.
- **Revert Checked** restores the Windows default for whatever is checked.
- **Export Profile** saves your current checkbox selection as JSON.
- **Import Profile** loads a JSON profile's selections into the checkboxes
  (review, then click Apply Checked — import does not auto-apply).
- **Filter** box narrows the list live by name/description/category/
  recommendation (e.g. type "no" to see just the flagged-risky items).

## How "Recommended" is decided
- **Yes** — safe to apply broadly for privacy/telemetry/AI lockdown on a
  workstation or staging image; low risk of breaking normal use. This is
  the "harden everything reasonable" tier and is what `SampleProfile.json`
  and **Select Recommended** apply by default.
- **Limited** — real functionality trade-off (e.g. per-app permissions like
  camera/contacts/location that legitimate apps may need, driver/update
  behavior, OneDrive pre-logon sync). Worth reviewing per-deployment rather
  than blanket-applying.
- **No** — included for feature parity, but actively **not** recommended
  by most hardening guidance (disabling SmartScreen, disabling automatic
  Windows Update, disabling inbound RDP, disabling the "no internet access"
  taskbar probe). A few of these intentionally diverge from what ShutUp10
  itself marks "yes" — e.g. disabling RDP is rated `No` here even though
  some tools default to enabling that toggle, because it can strand you
  out of a machine you manage remotely. Read the `Description` before
  checking any `No`-rated item.


## Silent / fleet provisioning use (RMM, imaging, Intune script step, etc.)
```powershell
.\PC-Hardening-Tool.ps1 -Silent -Import .\SampleProfile.json
```
- No UI. Applies every setting listed in the JSON to the value specified
  (`true` = hardened, `false` = Windows default).
- Writes a timestamped log to `%TEMP%\PC-Hardening-Tool_<timestamp>.log`.
- Auto-elevates if needed; if already SYSTEM/admin (typical for RMM script
  steps) it runs immediately with no relaunch.

## Extending it
Every setting is one entry in the `$Settings` array near the top of the
script — `Id`, `Category`, `Name`, `Description`, and one or more `Actions`
(registry path/value/type, on-value, off-value, or a `Service` action for
toggling a service's startup type). Copy an existing block, edit it, done —
it automatically appears in the GUI under its category and works in both
Apply/Revert and silent mode. `Category` strings control grouping and
display order (order of first appearance in the array = order in the GUI).

## Items marked "NOT recommended" / included for parity only
A few ShutUp10-equivalent toggles are things most hardening guides advise
*against* flipping for typical users (they trade real functionality/security
for a marginal privacy gain, or can lock you out of the machine). These are
included so the tool has full coverage, but they're **unchecked by default**
in `SampleProfile.json` and each has a warning in its `Description`:
- Disable SmartScreen Filter (Edge)
- Disable automatic Windows Updates
- Disable remote connections to this computer (RDP) — can cut off your own
  remote access; double-check you have another way in before applying this
  to an unattended/headless machine.
- Disable Network Connectivity Status Indicator active probing

## Not yet mapped (backlog / good first contributions)
These appear in ShutUp10 but I couldn't find a registry/policy key I was
confident was accurate, so they're intentionally left out rather than
guessed:
- App Privacy (newer categories without a confirmed ADMX/CSP mapping):
  passkeys & stored passkey list, Bluetooth devices, human interface
  devices, custom sensors, serial ports, USB devices, Wi-Fi information,
  Wi-Fi Direct, eye tracking, screenshots (with/without borders), music
  libraries, downloads folder, file system, presence sensing
- Security: NFC, wireless display (Miracast/WiDi), mobile broadband
  (cellular/WWAN), Wi-Fi Direct, restrict Bluetooth pairing
- Microsoft Edge: "Edge bar", suggestion of similar sites when a site can't
  be found, site safety services, typosquatting checker, AI-generated
  themes, built-in AI APIs for websites, inline Compose, prompts to make
  Edge default, cloud-based tab services, text prediction in forms, visual
  search, AI-powered history search, "allow user control of local AI
  features" (this one is a positive/opt-in control, different polarity from
  the rest — needs its own UI treatment)
- Copilot & Windows AI: AI actions in File Explorer
- Windows Update: defer feature-update period (numeric, not a toggle),
  automatic app updates through Windows Update
- Microsoft Defender: reporting of malware infection information (distinct
  from SpyNet reporting)
- Mobile Devices: disable connecting the PC to mobile devices / Phone Link
- Legacy (EdgeHTML) Microsoft Edge settings — intentionally omitted; legacy
  Edge is deprecated/removed on all currently supported Windows releases

If you add one of these, please note the source (Microsoft Learn URL, ADMX
file name, or Policy CSP page) in the commit/PR so the next person can
verify it too — that sourcing discipline is the main thing keeping this
tool trustworthy.

## Notes / cautions
- Requires local admin (it self-elevates).
- Some Edge/App-Privacy items are enforced via Group Policy-style registry
  keys (`HKLM\SOFTWARE\Policies\...`); a few may need a sign-out/restart of
  Explorer/Edge to visibly take effect.
- Test on a non-production machine before rolling a profile out to a fleet.
