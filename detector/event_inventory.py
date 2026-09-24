import xml.etree.ElementTree as ET
from Evtx.Evtx import Evtx
from pathlib import Path
from collections import Counter
from rich.console import Console
from rich.table import Table

console = Console()
dataset_path = Path("../data/samples")
NS = {'ns': 'http://schemas.microsoft.com/win/2004/08/events/event'}

event_id_counts = Counter()
files_scanned = 0
total_events = 0

with console.status("[bold blue]Scanning EVTX files for Event IDs...", spinner="dots"):
    for file in dataset_path.rglob("*.evtx"):
        files_scanned += 1
        try:
            with Evtx(str(file)) as log:
                for record in log.records():
                    total_events += 1
                    try:
                        root = ET.fromstring(record.xml())
                        event_id = root.find('.//ns:EventID', NS)
                        if event_id is not None and event_id.text:
                            event_id_counts[event_id.text] += 1
                    except ET.ParseError:
                        continue

        except Exception as error:
            console.print(f"[bold red]ERROR processing {file}:[/bold red] {error}")

# Build the Output Table
table = Table(title="Event ID Inventory", show_header=True, header_style="bold magenta")
table.add_column("Event ID", style="cyan", justify="center")
table.add_column("Occurrences", style="green", justify="right")
table.add_column("Percentage of Total", style="yellow", justify="right")

for event_id, count in event_id_counts.most_common():
    percentage = (count / total_events) * 100 if total_events > 0 else 0
    table.add_row(
        str(event_id),
        f"{count:,}",
        f"{percentage:.2f}%"
    )

console.print("\n")
console.print(table)
console.print(f"[dim]Total Files Scanned: {files_scanned} | Total Events Parsed: {total_events:,}[/dim]\n")