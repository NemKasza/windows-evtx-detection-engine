from Evtx.Evtx import Evtx
from detector.rules import detect_credential_prompt
from pathlib import Path
import re


dataset_path = Path("../data/samples")

evtx_files = dataset_path.rglob("*.evtx")

total_files = 0
total_detections = 0
total_4104_events = 0


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

                if not event_id or event_id.group(1) != "4104":
                    continue
                total_4104_events += 1
                event_record_id = re.search(
                    r"<EventRecordID>(\d+)</EventRecordID>",
                    xml
                )

                timestamp = re.search(
                    r'<TimeCreated SystemTime="([^"]+)"',
                    xml
                )

                script = re.search(
                    r'<Data Name="ScriptBlockText">(.*?)</Data>',
                    xml,
                    re.DOTALL
                )

                if not script:
                    continue

                script_text = script.group(1)

                result = detect_credential_prompt(script_text)

                if result["detected"]:
                    total_detections += 1

                    print("\nDETECTION:")
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
                    print("Severity:", result["severity"])
                    print("Reason:", result["reason"])
                    print("Indicators:", result["indicators"])
                    print("-" * 80)

    except Exception as error:
        print("ERROR:", file)
        print(error)


print("\nSCAN COMPLETE")
print("Files scanned:", total_files)
print("4104 events:", total_4104_events)
print("Detections:", total_detections)