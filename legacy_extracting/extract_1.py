from Evtx.Evtx import Evtx
from detector.rules import detect_suspicious_process
from pathlib import Path
import re


dataset_path = Path("../data/samples")

evtx_files = dataset_path.rglob("*.evtx")

total_files = 0
total_process_events = 0
total_detections = 0


for file in evtx_files:
    total_files += 1

    try:
        with Evtx(file) as log:
            for record in log.records():
                xml = record.xml()

                event_id = re.search(
                    r"<EventID[^>]*>(\d+)</EventID>",
                    xml
                )

                if not event_id or event_id.group(1) != "1":
                    continue

                total_process_events += 1

                event_record_id = re.search(
                    r"<EventRecordID>(\d+)</EventRecordID>",
                    xml
                )

                timestamp = re.search(
                    r'<TimeCreated SystemTime="([^"]+)"',
                    xml
                )

                image = re.search(
                    r'<Data Name="Image">(.*?)</Data>',
                    xml,
                    re.DOTALL
                )

                command_line = re.search(
                    r'<Data Name="CommandLine">(.*?)</Data>',
                    xml,
                    re.DOTALL
                )

                image_text = image.group(1) if image else ""
                command_line_text = command_line.group(1) if command_line else ""

                result = detect_suspicious_process(
                    command_line_text,
                    image_text
                )

                if result["detected"]:
                    total_detections += 1

                    print("\nDETECTION")
                    print("File:", file)
                    print(
                        "Event Record ID:",
                        event_record_id.group(1)
                        if event_record_id
                        else "Unknown"
                    )
                    print(
                        "Timestamp:",
                        timestamp.group(1)
                        if timestamp
                        else "Unknown"
                    )
                    print("Image:", image_text)
                    print("Command Line:", command_line_text)
                    print("Severity:", result["severity"])
                    print("Reason:", result["reason"])
                    print("Indicators:", result["indicators"])
                    print("-" * 80)

    except Exception as error:
        print("ERROR:", file)
        print(error)


print("\n" + "=" * 60)
print("PROCESS CREATION SCAN COMPLETE")
print("=" * 60)
print("Files scanned:", total_files)
print("Event ID 1 events:", total_process_events)
print("Detections:", total_detections)