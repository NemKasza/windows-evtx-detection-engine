# noinspection PyPep8Naming
import argparse
import xml.etree.ElementTree as ET
from pathlib import Path
from Evtx.Evtx import Evtx
from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.text import Text as RichText
from rich.progress import (
    Progress,
    SpinnerColumn,
    TextColumn,
    BarColumn,
    TaskProgressColumn,
    TimeRemainingColumn,
    ProgressColumn
)
from detector.rules import (
    detect_credential_prompt,
    detect_amsi_and_logging_bypass,
    detect_in_memory_execution,
    detect_suspicious_process,
    detect_system_recovery_tampering,
    detect_suspicious_parent
)


console = Console(force_terminal=True)
NS = {'ns': 'http://schemas.microsoft.com/win/2004/08/events/event'}


def parse_event_xml(xml_string):
    """Parses EVTX XML into a clean dictionary."""
    try:
        root = ET.fromstring(xml_string)

        event_id_elem = root.find('.//ns:EventID', NS)
        if event_id_elem is None:
            return None

        record_id_elem = root.find('.//ns:EventRecordID', NS)
        time_elem = root.find('.//ns:TimeCreated', NS)

        event_data = {}
        for data in root.findall('.//ns:Data', NS):
            name = data.get('Name')
            if name:
                event_data[name] = data.text or ""

        return {
            "event_id": event_id_elem.text,
            "record_id": record_id_elem.text if record_id_elem is not None else "Unknown",
            "timestamp": time_elem.get('SystemTime') if time_elem is not None else "Unknown",
            "data": event_data
        }
    except ET.ParseError:
        return None


def get_severity_color(severity):
    """Maps severity levels to Rich color tags."""
    colors = {"HIGH": "bold red", "MEDIUM": "bold yellow", "LOW": "bold cyan", "NONE": "bold green"}
    return colors.get(severity.upper(), "white")


# --- CLI Argument Parsing ---
parser = argparse.ArgumentParser(
    description="Scan Windows EVTX logs for suspicious process creation and PowerShell execution."
)
parser.add_argument(
    "-d", "--directory",
    type=Path,
    default=Path("data/samples"),
    help="Path to directory containing .evtx files (default: data/samples)"
)
args = parser.parse_args()

dataset_path: Path = args.directory

# Validate target directory
if not dataset_path.exists() or not dataset_path.is_dir():
    console.print(f"[bold red]Error:[/bold red] Directory '{dataset_path}' does not exist or is not a valid folder.")
    exit(1)

evtx_files = list(dataset_path.rglob("*.evtx"))
stats = {"files": 0, "events": 0, "4104": 0, "process": 0, "detections": 0}

console.print(
    f"[bold blue]Starting Detection Engine on target:[/bold blue] [yellow]{dataset_path.resolve()}[/yellow]\n")

if not evtx_files:
    console.print(f"[bold yellow]No .evtx files found in '{dataset_path.resolve()}'.[/bold yellow]")
else:
    # Explicitly typed column tuple resolves PyCharm inspection warnings
    progress_columns: tuple[ProgressColumn, ...] = (
        SpinnerColumn(),
        TextColumn(text_format="[progress.description]{task.description}"),
        BarColumn(),
        TaskProgressColumn(),
        TimeRemainingColumn(),
    )

    with Progress(
            *progress_columns,
            console=console,
            transient=False
    ) as progress:

        scan_task = progress.add_task("[cyan]Scanning EVTX files...", total=len(evtx_files))

        for file in evtx_files:
            stats["files"] += 1

            try:
                with Evtx(str(file)) as log:
                    for record in log.records():
                        stats["events"] += 1

                        if stats["events"] % 100 == 0:
                            progress.update(
                                scan_task,
                                description=f"[cyan]Scanning [bold]{file.name}[/bold] ([yellow]{stats['events']:,}[/yellow] events parsed)"
                            )

                        event = parse_event_xml(record.xml())
                        if not event:
                            continue

                        result = None
                        rule_name = ""

                        # Analyze PowerShell Script Blocks (Event ID 4104)
                        if event["event_id"] == "4104":
                            stats["4104"] += 1
                            script_text = event["data"].get("ScriptBlockText", "")
                            if script_text:
                                # Rule 1: Credential Prompt
                                result = detect_credential_prompt(script_text)
                                rule_name = "Credential Prompt Detection"

                                # Rule 2: AMSI & Logging Bypass (if Rule 1 clean)
                                if not result.get("detected"):
                                    result = detect_amsi_and_logging_bypass(script_text)
                                    rule_name = "AMSI / Telemetry Bypass"

                                # Rule 3: In-Memory Reflection (if Rules 1 & 2 clean)
                                if not result.get("detected"):
                                    result = detect_in_memory_execution(script_text)
                                    rule_name = "In-Memory Script Execution"

                        # Analyze Process Creations (Event ID 1)
                        elif event["event_id"] == "1":
                            stats["process"] += 1
                            image = event["data"].get("Image", "")
                            cmdline = event["data"].get("CommandLine", "")
                            parent_image = event["data"].get("ParentImage", "")

                            # Rule 1: Suspicious Command Line / LOLBins
                            result = detect_suspicious_process(cmdline, image)
                            rule_name = "Suspicious Process Detection"

                            # Rule 2: Recovery / Shadow Copy Tampering (if Rule 1 clean)
                            if not result.get("detected"):
                                result = detect_system_recovery_tampering(cmdline, image)
                                rule_name = "System Recovery Tampering"

                            # Rule 3: Suspicious Parent-Child Process (if Rules 1 & 2 clean)
                            if not result.get("detected") and parent_image:
                                result = detect_suspicious_parent(parent_image, image)
                                rule_name = "Suspicious Parent-Child Process"

                        # Print Formatted Detections
                        if result and result.get("detected"):
                            stats["detections"] += 1
                            color = get_severity_color(result["severity"])

                            alert_text = RichText()
                            alert_text.append("File: ", style="bold")
                            alert_text.append(f"{file}\n")
                            alert_text.append("Event Record ID: ", style="bold")
                            alert_text.append(f"{event['record_id']}  |  ")
                            alert_text.append("Timestamp: ", style="bold")
                            alert_text.append(f"{event['timestamp']}\n")

                            if event["event_id"] == "1":
                                alert_text.append("Image: ", style="bold")
                                alert_text.append(f"{event['data'].get('Image', '')}\n")
                                alert_text.append("Command Line: ", style="bold")
                                alert_text.append(f"{event['data'].get('CommandLine', '')}\n")

                            alert_text.append("\nReason: ", style="bold")
                            alert_text.append(f"{result['reason']}\n")
                            alert_text.append("Indicators: ", style="bold")
                            alert_text.append(f"{', '.join(result['indicators'])}")

                            panel = Panel(
                                alert_text,
                                title=f"[{color}]DETECTION: {rule_name} (Severity: {result['severity']})[/{color}]",
                                border_style=color.split()[-1]
                            )
                            progress.console.print(panel)
                            progress.console.print()

            except Exception as error:
                progress.console.print(f"[bold red]ERROR processing {file}:[/bold red] {error}")

            progress.advance(scan_task)

# Summary Output Table
table = Table(title="Detection Engine Summary", show_header=True, header_style="bold magenta")
table.add_column("Metric", style="cyan", no_wrap=True)
table.add_column("Count", justify="right", style="green")

table.add_row("Files Scanned", str(stats['files']))
table.add_row("Total Events Parsed", f"{stats['events']:,}")
table.add_row("Event ID 4104 Analyzed", f"{stats['4104']:,}")
table.add_row("Event ID 1 Analyzed", f"{stats['process']:,}")
table.add_row("Total Detections", str(stats['detections']),
              style="bold red" if stats['detections'] > 0 else "bold green")

console.print("\n")
console.print(table)