# Qingqiuhu Network Workbench

[Chinese (Simplified)](README.md)

> Prebuilt releases are available for download on GitHub: [GitHub Releases](https://github.com/UncleNiu-QingqiuHu/network_diagnosis/releases) or GitCode：[GitCode Releases](https://gitcode.com/ibobcheung/qqhu_network_diagnosis/releases). The executable programs (exe) provided by this warehouse have been compiled and optimized using Nuitka and have been digitally signed.

A **Windows desktop network workbench** built with Python (tkinter + [ttkbootstrap](https://github.com/israel-dryer/ttkbootstrap)): connectivity diagnostics, **security diagnostics (baseline)**, IPv4 subnet utilities, switch **Console/SSH**, database diagnostics, **ARP security monitoring**, **Windows Authenticode signing**, and **SSL certificates (Let's Encrypt / private CA)**. Official site: <https://www.qingqiuhu.net>. Release version is defined by `APP_VERSION` in [`network_diagnosis/version.py`](network_diagnosis/version.py).

## Feature overview

The main window uses a left-hand navigation rail with the following modules:

| Module | Description |
|--------|-------------|
| **Network diagnostics** | Dual output: operator-friendly GUI summary plus a full **Markdown** technical report per run (same underlying model). |
| **Subnet calculator** | IPv4 CIDR / dotted-mask math; refresh local IPv4, gateway, DNS, and public IP hints. |
| **Switch console** | Serial console or **SSH (PTY)**; SSH host keys land under the writable `switch_console/` tree. |
| **Database diagnostics** | **SQLite / MySQL / PostgreSQL / SQL Server / Oracle** connectivity and inventory-style checks, Markdown output; scheduled monitoring snapshots. |
| **ARP security** | Poll `arp -a`, baseline the **default gateway MAC**, and warn on suspicious drift (lightweight LAN-side watch). |
| **Security diagnostics** | Local TCP listeners and read-only Windows Firewall summary; CPU/GPU/memory/user policy and temp cleanup (Windows); with explicit consent—HTTPS TLS/certificates and security headers, DNS comparison, **single-host IPv4 TCP port scan** (Python by default, optional nmap `-sT`). See [`docs/network-security-diagnosis-design.md`](docs/network-security-diagnosis-design.md). Exports under `reports/security_diagnosis/`. |
| **Code signing** | Windows **Authenticode**: `signtool` + PFX to sign/verify exe and dll; self-signed code-signing PFX via **PowerShell / .NET** (requires `powershell.exe`); locate `signtool` from the Windows SDK or PATH. |
| **SSL certificates** | **Let's Encrypt** (DNS-01 via Aliyun / Tencent DNS APIs) and **private CA** (`cryptography`); see in-app **SSL certificates** help and [`docs/ssl_certificate_scheme.md`](docs/ssl_certificate_scheme.md). |
| **Help / About / License** | Built-in help (Markdown-capable body), About, and MIT license text; static tabs are built on **first visit** to shorten cold start. |

**Network diagnostics** probes (summary):

- Local network context (`ipconfig` parsing), DNS, optional ICMP `ping`, multi-port **tcping**, optional **tshark** capture (Wireshark / Npcap installed on the machine).
- Optional **Traceroute**, **PathPing**, **TCP traceroute**; optional **egress probe**, **IPv4 MTU** probe; optional target **HTTP(S)/TLS** probe.
- Throughput: **HTTP download benchmark** or **iperf3** (TCP/UDP, can feed the composite quality assessment); run history index defaults to `reports/_diagnosis_history.json` for same-target comparisons (can be disabled in the UI).
- **Dependency policy** (aligned with `network_diagnosis/paths.py` and the UI **Detect** action): `tcping.exe` is loaded **only** from `ThirdParty/tcping/tcping.exe` (not PATH); `tshark.exe` is resolved under `%ProgramFiles%\Wireshark\` and `%ProgramFiles(x86)%\Wireshark\`; **iperf3** prefers `ThirdParty/iperf3/iperf3.exe`, else PATH; you may ship the official Wireshark **installer** under `ThirdParty/Wireshark/` for guided install from the UI.

**Database diagnostics** notes:

- Non-SQLite engines need a reachable host and database name; **SQL Server** needs a local **ODBC driver** (`pyodbc`); for **Oracle**, use **Service Name** in the “database” field (`oracledb` thin mode).
- Python dependencies for all engines are declared in `pyproject.toml`; install a subset in your venv if you do not need every backend (optional dependency groups are a team policy choice—today the project installs the full set).

## Requirements

- Windows 10/11 (scripts and subprocess flags are tuned for Windows).
- **Python 3.10+** (matches `requires-python` in `pyproject.toml`).
- Place **`tcping.exe`** at `ThirdParty/tcping/tcping.exe` (otherwise TCP port checks degrade and the report notes it).
- Place **`tshark.exe`** under `ThirdParty/Wireshark/` (otherwise capture is unavailable).
- Place **`iperf3.exe`** under `ThirdParty/iperf3/` (otherwise iperf3 bandwidth mode is unavailable).
- Place **`nmap.exe`** under `ThirdParty/Nmap/` (otherwise the port-scan backend is unavailable).

## Screenshots

![](./readmeimgs/PixPin_2026-05-15_15-59-59.png)
![](./readmeimgs/PixPin_2026-05-15_16-01-08.png)
![](./readmeimgs/PixPin_2026-05-15_16-01-27.png)
![](./readmeimgs/PixPin_2026-05-15_16-01-38.png)
![](./readmeimgs/PixPin_2026-05-15_19-11-05.png)

## Install and run

```powershell
cd E:\Workspace\qqhu_network_diagnosis   # use your clone path
python -m venv .venv
.\.venv\Scripts\activate
pip install -e .
```

Start the GUI:

```powershell
python -m network_diagnosis
```

Or the console entry point:

```powershell
network-diagnosis
```

## Packaging

Compile the program into a **PyInstaller / Nuitka** executable package. It is recommended to use **Nuitka**.

## Reports, logs, and data directories

All conventions live in [`network_diagnosis/paths.py`](network_diagnosis/paths.py): **repo root** in development; **directory containing the exe** for PyInstaller / shipped binaries (never write into read-only `_MEIPASS`).

### Runtime logs

- Folder: **`logs/`** (same placement rules as `reports/`).
- Primary file: **`logs/app.log`**, rotated at **local midnight**, dated archives (`TimedRotatingFileHandler`, ~90 files retained by default).
- Code: **`network_diagnosis/runtime_log.py`** (`setup_runtime_logging()` early in GUI `main_gui()`); other modules can use `get_logger(__name__)` on the `qingqiuhu.*` tree.

### Diagnostic artifacts

Each **network diagnostics** run creates:

```text
reports/<short_task_id>_<timestamp>/
```

Markdown report, subprocess stdout/stderr logs, and optional pcap when capture is enabled. Same-target history (unless disabled) is indexed in **`reports/_diagnosis_history.json`**.

**Database diagnostics** and monitoring exports:

```text
reports/db_diagnosis/<task_id>/
```

**Security diagnostics** exports:

```text
reports/security_diagnosis/
```

**Switch console** writable data (e.g. SSH `known_hosts`): **`switch_console/`**.

Directories are created on first use; **`reports/`**, **`logs/`**, **`switch_console/`** are listed in `.gitignore`.

## Third-party assets

| Asset | Path | Notes |
|-------|------|-------|
| tcping | `ThirdParty/tcping/tcping.exe` | Required for full port checks; the app does not rely on PATH for tcping. |
| iperf3 | `ThirdParty/iperf3/iperf3.exe` | Optional; used when iperf3 bandwidth mode is selected; PATH fallback allowed. Recommended in full offline bundles ([docs/packaging.en.md](docs/packaging.en.md)). |
| Wireshark installer | `ThirdParty/Wireshark/*.exe` | Optional; UI can launch the installer when `tshark` is missing. |
| Nmap | `ThirdParty/Nmap/*.exe` (installer) or portable **`ThirdParty/Nmap/`** (`nmap.exe` + DLLs) | Optional; used when security diagnostics enables nmap; resolution order: PATH → default install dirs → `ThirdParty/Nmap/nmap.exe` (`paths.resolve_nmap_exe_path`). Ship the full portable folder when bundling ([docs/packaging.en.md](docs/packaging.en.md)). |
| LICENSE | repo root `LICENSE` | Read by the License tab; include in frozen bundles per [docs/packaging.en.md](docs/packaging.en.md). |

Redistributing third-party binaries must comply with their licenses (see design doc §6).

## Repository layout (excerpt)

```text
network_diagnosis/       # Python package: models, probes, orchestration, GUI, Markdown serialization
docs/                    # Design docs and packaging guides (packaging.en.md, etc.; may be absent in some clones)
readmeimgs/              # Screenshots for README
ThirdParty/              # tcping; optional iperf3 / Wireshark / Nmap; ship with root LICENSE for releases
reports/                 # Default diagnostic output (.gitignore)
logs/                    # app.log, daily rotation (.gitignore)
switch_console/          # SSH writable data (.gitignore; created on first use)
pyproject.toml
CHANGELOG.md
```

## Development

```powershell
.\.venv\Scripts\activate
pip install ruff
python -m ruff check network_diagnosis
```

## License

**MIT** — see [`LICENSE`](LICENSE) in the repository root.
