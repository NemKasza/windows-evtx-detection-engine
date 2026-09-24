# Windows EVTX Detection Engine

A lightweight Python-based detection engine for analyzing Windows Event Log (EVTX) files and identifying suspicious PowerShell and process execution behavior.

The project was built as a practical cybersecurity portfolio project focused on **Windows telemetry, detection logic, false-positive reduction, and analyst-friendly alerting**.

## Project Goal

The goal is to demonstrate how Windows event telemetry can be transformed into actionable security detections without relying on a full SIEM platform.

The engine:

1. Recursively scans EVTX files across target directories.
2. Parses Windows Event Log XML structures.
3. Extracts relevant event fields.
4. Applies detection rules based on behavioral heuristics.
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


---

These EVTX samples are reproduced from the public
EVTX-ATTACK-SAMPLES repository:

https://github.com/sbousseaden/EVTX-ATTACK-SAMPLES

Original project: sbousseaden/EVTX-ATTACK-SAMPLES

The upstream repository identifies the project as licensed under the
GNU General Public License. These files are included here solely as
sample telemetry for demonstrating and testing the detection engine.

See the original repository and its LICENSE.GPL file for the complete
license terms.
```
```
