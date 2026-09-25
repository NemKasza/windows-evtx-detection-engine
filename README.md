
# Windows EVTX Detection Engine

A lightweight Python-based detection engine for analyzing Windows Event Log (EVTX) files and identifying suspicious PowerShell and process execution behavior.

The project was built as a practical cybersecurity portfolio project focused on **Windows telemetry, detection logic, false-positive reduction, and analyst-friendly alerting**.

<img width="1339" height="399" alt="Decetor in use" src="https://github.com/user-attachments/assets/fadbfbfb-b148-4643-a14a-af298515849b" />

---

<img width="908" height="252" alt="Finished detector output" src="https://github.com/user-attachments/assets/535f9d8a-ca46-419d-b68a-fffc8d9c1e3f" />



## Project Goal

The goal is to demonstrate how Windows event telemetry can be transformed into actionable security detections without relying on a full SIEM platform.

The engine:
* Recursively scans EVTX files across target directories.
* Parses Windows Event Log XML structures.
* Extracts relevant event fields.
* Applies detection rules based on behavioral heuristics.
* Generates structured alerts containing the event, rule, severity, reason, and matching indicators.
* Provides a scan summary.

## Architecture

```text
EVTX files
    |
    v
EVTX parser
    |
    v
Normalized event data
    |
    +----------------------+
    |                      |
    v                      v
Event ID 4104          Event ID 1
PowerShell             Process Creation
Script Block           Detection
Detection                  |
    |                      |
    +----------+-----------+
               |
               v
        Detection Result
               |
               v
        Analyst Alert

```

## Detection Rules

### 1. PowerShell Telemetry (Event ID 4104)

Analyzes `ScriptBlockText` for malicious behaviors:

* **Credential Harvesting:** Matches functions like `PromptForCredential`, `GetNetworkCredential`, and `ValidateCredentials`.
* **AMSI & Telemetry Bypass:** Detects memory patching (`amsiUtils`, `AmsiScanBuffer`) and logging tampering (`EtwEventWrite`, `ScriptBlockLogging`).
* **In-Memory Execution:** Flags reflection-based assembly loading (`[Reflection.Assembly]::Load`) and dynamic C# compilation (`Add-Type`).

### 2. Process Creation Telemetry (Sysmon Event ID 1)

Evaluates execution context and command-line arguments:

* **LOLBin & Scripting Execution:** Identifies encoded commands (`-enc`), execution policy bypasses, and suspicious binary calls (`rundll32.exe`, `regsvr32.exe`, `certutil.exe`).
* **System Recovery Tampering:** Flags ransomware indicators like Volume Shadow Copy deletion (`vssadmin delete shadows`, `wmic shadowcopy delete`, `bcdedit`).
* **Suspicious Parent-Child Process:** Identifies shell engines spawned by office applications (`winword.exe`, `excel.exe`) or web services (`w3wp.exe`).

## Example Detection

```text
Rule: Credential Prompt Detection
File: phish_windows_credentials_powershell_scriptblockLog_4104.evtx
Event ID: 4104
Event Record ID: 1123
Timestamp: 2019-09-09 13:35:09.315229+00:00
Severity: HIGH
Reason: Credential harvesting indicator(s) detected (3 matched)
Indicators:
    credential_prompt:promptforcredential
    credential_prompt:getnetworkcredential
    credential_prompt:validatecredentials

```

## Dataset & Attribution

Sample EVTX telemetry files included in `data/samples/` are reproduced from the public [EVTX-ATTACK-SAMPLES](https://github.com/sbousseaden/EVTX-ATTACK-SAMPLES) repository maintained by Samir Bousseaden.

> **Licensing Notice:**
> The upstream repository identifies the project as licensed under the **GNU General Public License (GPL)**. These files are included here solely as sample telemetry for demonstrating and testing the detection engine. See the original repository and its `LICENSE.GPL` file for complete license terms.

## Installation

Clone the repository and create a Python virtual environment:

```bash
git clone https://github.com/NemKasza/windows-evtx-detection-engine.git
cd windows-evtx-detection-engine

python3 -m venv .venv
source .venv/bin/activate  # On Windows: .venv\Scripts\activate

```

Install the required dependencies:

```bash
python3 -m pip install -r requirements.txt

```

## Usage


<img width="708" height="154" alt="helpOutput" src="https://github.com/user-attachments/assets/dbd4504f-fda2-47bf-9b15-53972a01fbae" />


Run the engine against the default sample directory (`data/samples/`):

```bash
python3 main.py

```

Run the engine against a custom directory containing EVTX logs:

```bash
python3 main.py -d /path/to/custom/evtx_logs

```

View CLI flags and command options:

```bash
python3 main.py --help

```

## Running Tests

Execute the unit test suite using `pytest`:

```bash
python3 -m pytest

```

## Project Structure

```text
windows-detection-engine/
├── data/
│   └── samples/                 # Sample EVTX log files for testing & analysis
├── detector/
│   ├── event_inventory.py       # EVTX event ID breakdown & frequency analyzer
│   └── rules.py                 # Behavioral heuristic rules & detection logic
├── legacy_extracting/           # Prototype scripts for single-event extraction
│   ├── extract_1.py
│   └── extract_4104.py
├── tests/
│   └── test_rules.py            # Unit tests for rule verification (pytest)
├── main.py                      # Primary detection engine CLI entry point
├── README.md                    # Project documentation
└── requirements.txt            # Python dependencies (evtx, rich, pytest)

```

## Design Decisions & Limitations

* **Behavioral Combinations:** Rather than alerting on single keywords (e.g., `rundll32.exe`), rules require contextual flags (e.g., DLL execution + memory dump parameters) to minimize noise and false positives.
* **Context-Rich Output:** Alerts detail the rule name, file source, record ID, timestamp, severity, rationale, and specific matched indicators.
* **Scope:** Designed as a lightweight CLI analysis tool. It does not provide real-time streaming ingestion, a SIEM backend, or centralized database storage.

