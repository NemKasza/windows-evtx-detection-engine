# Windows EVTX Detection Engine

A lightweight Python-based detection engine for analyzing Windows Event Log (EVTX) files and identifying suspicious PowerShell and process execution behavior.

The project was built as a practical cybersecurity portfolio project focused on **Windows telemetry, detection logic, false-positive reduction, and analyst-friendly alerting**.

## Project Goal

The goal is to demonstrate how Windows event telemetry can be transformed into actionable security detections without relying on a full SIEM platform.

The engine:

1. Recursively scans EVTX files.
2. Parses Windows Event Log XML.
3. Extracts relevant event fields.
4. Applies detection rules.
5. Generates structured alerts containing the event, rule, severity, reason, and matching indicators.
6. Provides a scan summary.

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

### 1. PowerShell Credential Collection

**Telemetry:** Windows Event ID 4104
**Source:** PowerShell Script Block Logging

The detector searches the `ScriptBlockText` field for a combination of credential-related behaviors:

* `PromptForCredential`
* `GetNetworkCredential`
* `ValidateCredentials`

The rule records which indicators were present and assigns a severity based on the number of related behaviors observed.

The detection is based on the **content of the event**, not the filename of the EVTX sample.

Example behavior:

```powershell
PromptForCredential
GetNetworkCredential
ValidateCredentials
```

This combination produces a high-priority detection because multiple credential-handling behaviors occur within the same script block.

### 2. Suspicious Process Execution

**Telemetry:** Sysmon Event ID 1
**Source:** Process Creation

The process detection looks for combinations of suspicious execution behavior rather than alerting on a process name alone.

Examples include:

* Encoded PowerShell command execution
* PowerShell execution with suspicious command-line options
* `rundll32.exe` executing a DLL
* `rundll32.exe` associated with memory-dump behavior
* Suspicious `regsvr32.exe` or `certutil.exe` usage

The rule was iteratively tuned to reduce noisy detections.

An initial version produced:

```text
71 process events
47 detections
```

After changing the rule to require more meaningful behavioral combinations, the validation run was reduced to:

```text
71 process events
3 detections
```

This tuning process was important because the goal was not simply to maximize the number of alerts, but to make each alert more explainable.

## Example Detection

```text
Rule: Credential Prompt Detection
File: phish_windows_credentials_powershell_scriptblockLog_4104.evtx
Event ID: 4104
Event Record ID: 1123
Timestamp: 2019-09-09 13:35:09.315229+00:00
Severity: HIGH
Reason: Three credential-related indicators found
Indicators:
    PromptForCredential
    GetNetworkCredential
    ValidateCredentials
```

Another example:

```text
Rule: Suspicious Process Detection
Event ID: 1
Image: C:\Windows\System32\rundll32.exe
Command Line:
rundll32 C:\windows\system32\comsvcs.dll, MiniDump ...
Severity: MEDIUM/HIGH
Indicators:
    process:rundll32.exe
    dll_execution
    memory_dump_behavior
```

## Dataset

The project was tested against a collection of Windows EVTX samples containing security-related and Sysmon telemetry.

The analyzed local dataset contained:

```text
EVTX files: 39
Total events: 29,853
Event ID 4104 events: 3
Event ID 1 events: 71
```

The dataset is not included in this repository. Only 3 trial files included. Place the EVTX samples in the local `data/samples/` directory before running the engine.

## Installation

Clone the repository and create a Python virtual environment:

```bash
python3 -m venv .venv
source .venv/bin/activate
```

Install the dependencies:

```bash
python3 -m pip install -r requirements.txt
```

## Running the Detection Engine

Place the EVTX files in:

```text
data/samples/
```

Then run:

```bash
python3 main.py
```

The engine displays detections during the scan and produces a final summary containing:

* files scanned
* total events parsed
* Event ID 4104 events analyzed
* Event ID 1 events analyzed
* total detections

## Running Tests

Run:

```bash
python3 -m pytest
```

The tests validate both detection and non-detection cases, including:

* credential-related PowerShell
* benign PowerShell
* encoded PowerShell execution
* normal PowerShell process creation

## Design Decisions

### Behavioral combinations instead of single keywords

A single keyword is often too broad.

For example:

```text
rundll32.exe
```

by itself does not necessarily provide enough context for an alert.

The process rule therefore looks for additional command-line behavior before generating a detection.

### Alert with context

Each detection includes:

```text
Rule
File
Event ID
Event Record ID
Timestamp
Severity
Reason
Indicators
```

This makes the output more useful to an analyst investigating an event.

### Dataset-driven development

The detection rules were selected based on the telemetry actually available in the dataset rather than assuming that a particular attack technique would be present.

## Limitations

This project is intentionally lightweight.

It does not provide:

* real-time Windows event collection
* a SIEM backend
* centralized log storage
* user authentication
* automated incident response
* machine-learning detection
* production-scale event processing

The rules are also intentionally simple and should be treated as demonstrations of detection logic rather than production-ready security analytics.

## Project Structure

```text
windows-detection-engine/
├── data/
│   └── samples/                 # Sample EVTX log files for testing & analysis
├── detector/
│   ├── event_inventory.py       # EVTX event ID breakdown & frequency analyzer
│   └── rules.py                 # Detection logic & behavioral heuristic rules
├── legacy_extracting/           # Prototype scripts for single-event extraction
│   ├── extract_1.py
│   └── extract_4104.py
├── tests/
│   └── test_rules.py            # Unit tests for rule verification (pytest)
├── main.py                      # Primary detection engine CLI entry point
├── README.md                    # Project documentation
└── requirements.txt            # Python dependencies (evtx, rich, pytest, etc.)
```

## What This Project Demonstrates

This project demonstrates practical experience with:

* Windows Event Logs (EVTX)
* PowerShell Script Block Logging
* Sysmon telemetry
* Python
* XML parsing
* rule-based detection engineering
* behavioral indicators
* alert severity
* false-positive reduction
* unit testing
* Git/GitHub project organization

## Future Improvements

Possible future improvements include:

* additional Windows event detections
* configurable detection rules
* JSON alert output
* command-line arguments for selecting datasets
* additional false-positive testing
* MITRE ATT&CK technique mapping

```
```
