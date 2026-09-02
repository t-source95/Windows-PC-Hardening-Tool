# PC Hardening Provisioning Tool

A single self-elevating PowerShell script with a WinForms GUI for reviewing and
applying Windows privacy, telemetry, and Copilot/AI settings. Everything it does
is a registry value or a service startup type — the same knobs Group Policy and
the Settings app write to. Nothing gets installed, nothing runs in the
background, and you can read the whole thing before you run it.

## Why this exists

I wanted a way to hand someone a hardening pass without also handing them a
third-party installer. Most of what tools like O&O ShutUp10 do (which is what
got me interested in this in the first place) is documented in Microsoft's own
ADMX files and the Policy CSP reference — it's all reachable with native tooling
if you know where to look. This script is my attempt to make that reachable for
people who don't want to go spelunking through Microsoft Learn: a checklist, a
plain-English description for every toggle, and a note about what you're
trading away.

Practically, I use it two ways:

- **Handing it to junior engineers** as a readable example of how these settings
  are actually stored, so "disable telemetry" stops being a magic button and
  starts being a registry path they can go verify themselves.
- **Handing it to friends and family** who want a cleaner machine but shouldn't
  be downloading random utilities to get one.

The categories mirror ShutUp10's headings so it's easy to cross-reference if
you already know that tool, but every key here came from Microsoft's Group
Policy (ADMX) docs, the Policy CSP reference, or Microsoft Learn.

## Screenshots

**Privacy, App Privacy, Security, and the start of Microsoft Edge, with the
Recommended column visible:**
![Privacy, Security, and Microsoft Edge settings, showing the Category, Recommended, Setting, Current State, and Description columns](docs/screenshots/screenshot-privacy-security-edge.png)

**Microsoft Edge (continued), Cortana, Copilot & Windows AI, Location Services,
User Behavior, Windows Update, Windows Explorer, Defender, Search, Taskbar,
Miscellaneous, and Gaming:**
![Remaining categories including Copilot & Windows AI, Windows Update, and Miscellaneous settings](docs/screenshots/screenshot-edge-ai-update-misc.png)

## What's covered

119 settings across 16 categories:

Privacy · Activity History and Clipboard · App Privacy · Security ·
Microsoft Edge · Cortana (Personal Assistant) · Copilot & Windows AI ·
Location Services · User Behavior · Windows Update · Windows Explorer ·
Microsoft Defender and Microsoft SpyNet · Search · Taskbar · Miscellaneous ·
Gaming

Each one carries a **Recommended** rating — 72 `Yes`, 41 `Limited`, 6 `No`.

This isn't an exhaustive list, and that's on purpose. A setting only gets added
once I've found a documented registry or policy value backing it. Anything I
couldn't source, I left out rather than guessing at a key and quietly breaking
someone's machine. The backlog is further down if you want to help fill it in.

## Files

- `PC-Hardening-Tool.ps1` — the whole tool (GUI and silent mode).
- `SampleProfile.json` — an example profile for unattended provisioning. It's
  deliberately conservative; see the notes below.
- `LICENSE` — MIT.

## Running it interactively

```powershell
.\PC-Hardening-Tool.ps1
```

It re-launches itself elevated (UAC prompt) if it isn't already admin, then
opens the list. What the buttons do:

- **Refresh Status** — reads the live registry and updates each row: green
  `Hardened`, orange `Default`, gray `Not Set`. It also ticks the box for
  anything already hardened, so the checkboxes reflect reality on load.
- **Select Recommended** — checks every `Yes`-rated setting. This is the fast
  path for "clean this machine up without breaking anything." Nothing rated
  `Limited` or `No` gets picked up automatically.
- **Select All / Select None** — exactly what they say.
- **Apply Checked** — writes the hardened value for everything checked, after a
  confirmation prompt.
- **Revert Checked** — puts the Windows default back for everything checked.
- **Export Profile / Import Profile** — save or load your checkbox selection as
  JSON. Importing only sets the checkboxes; you still click Apply yourself.
- **Filter** — type in the box and non-matching rows dim out (they stay in
  place rather than disappearing). Matches on name, description, category, and
  recommendation, so typing `no` is a quick way to spot the flagged items.

## How the Recommended rating works

- **Yes** — safe to apply broadly on a workstation or staging image. Low risk of
  breaking normal use. This is what **Select Recommended** and
  `SampleProfile.json` cover.
- **Limited** — there's a real functionality trade-off. Per-app permissions like
  camera, contacts, and location that legitimate apps need; driver and update
  behavior; OneDrive pre-logon sync. Worth deciding per deployment instead of
  blanket-applying.
- **No** — included so the tool has coverage, but most hardening guidance
  advises against it. Read the description before checking one of these.

## Items rated "No"

These are here for completeness and are unchecked in `SampleProfile.json`:

- **Disable SmartScreen Filter (Edge)** — trades phishing and malware protection
  for a marginal privacy gain.
- **Disable automatic Windows Updates** — leaves the machine unpatched.
- **Disable Windows Updates for other Microsoft products.**
- **Disable remote connections (RDP)** — this one can strand you out of a
  machine you manage remotely. Make sure you have another way in first. Some
  tools default this to on; I rated it `No` here for that reason.
- **Disable Microsoft OneDrive** — fine if you don't use it, disruptive if you do.
- **Disable NCSI active probing** — breaks the accuracy of the "no internet
  access" taskbar indicator.

## Silent / fleet provisioning

```powershell
.\PC-Hardening-Tool.ps1 -Silent -Import .\SampleProfile.json
```

No UI. Every setting listed in the JSON gets applied to the value specified
(`true` = hardened, `false` = Windows default), and a timestamped log lands in
`%TEMP%\PC-Hardening-Tool_<timestamp>.log`. Settings not mentioned in the JSON
are left alone.

Silent mode expects to already be elevated — it errors out rather than throwing
a UAC prompt at an unattended machine, which is the right behavior for an RMM
script step or an Intune run where there's nobody there to click it.

## Extending it

Every setting is one entry in the `$Settings` array near the top of the script:
an `Id`, `Category`, `Name`, `Description`, `Recommended` rating, and one or
more `Actions`. An action is a registry path, value name, type, on-value, and
off-value — or a `Service` action that flips a service's startup type instead.

Copy an existing block, edit it, and you're done. It shows up in the GUI under
its category automatically and works in Apply, Revert, and silent mode with no
other changes. Category strings control grouping and display order; order of
first appearance in the array is the order you'll see in the GUI.

## Backlog — good first contributions

These exist in ShutUp10 but I haven't found a registry or policy key I'm
confident in, so they're not in yet:

- **App Privacy** — passkeys and the stored passkey list, Bluetooth devices,
  human interface devices, custom sensors, serial ports, USB devices, Wi-Fi
  information, Wi-Fi Direct, eye tracking, screenshots (with and without
  borders), music libraries, downloads folder, file system, presence sensing.
- **Security** — NFC, wireless display (Miracast/WiDi), mobile broadband
  (cellular/WWAN), Wi-Fi Direct, restricting Bluetooth pairing.
- **Microsoft Edge** — the Edge bar, similar-site suggestions on failed
  navigation, site safety services, typosquatting checker, AI-generated themes,
  built-in AI APIs for websites, inline Compose, prompts to make Edge default,
  cloud-based tab services, text prediction in forms, visual search, AI-powered
  history search, and "allow user control of local AI features" (that last one
  is an opt-in control with the opposite polarity from everything else here, so
  it needs its own UI treatment).
- **Copilot & Windows AI** — AI actions in File Explorer.
- **Windows Update** — the feature-update deferral period (numeric, not a
  toggle) and automatic app updates through Windows Update.
- **Microsoft Defender** — reporting of malware infection information, which is
  distinct from the SpyNet reporting toggle already included.
- **Mobile Devices** — disabling PC-to-phone connections / Phone Link.
- **Legacy (EdgeHTML) Edge** — intentionally skipped. Legacy Edge is gone from
  every currently supported Windows release.

If you add one, please note the source in the commit or PR — a Microsoft Learn
URL, an ADMX filename, or a Policy CSP page. That sourcing habit is the main
thing that makes this worth trusting over a script full of magic numbers.

## Notes and cautions

- Requires local admin. It self-elevates in GUI mode.
- Some Edge and App Privacy items write Group Policy-style keys under
  `HKLM\SOFTWARE\Policies\...`. A few need a sign-out, or a restart of Explorer
  or Edge, before the change is visible.
- Test a profile on a non-production machine before rolling it out to a fleet.
- Reverting writes the documented Windows default back, which isn't always
  identical to "no value present." If you want a truly untouched key, delete it
  manually.
