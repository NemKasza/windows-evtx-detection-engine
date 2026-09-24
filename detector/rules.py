def detect_credential_prompt(script):
    indicators = [
        "PromptForCredential",
        "GetNetworkCredential",
        "ValidateCredentials"
    ]

    indicator_names = [ind for ind in indicators if ind in script]
    indicator_count = len(indicator_names)

    if indicator_count == 0:
        severity, reason = "NONE", "No credential-related indicators found"
    elif indicator_count == 1:
        severity, reason = "LOW", "One credential-related indicator found"
    elif indicator_count == 2:
        severity, reason = "MEDIUM", "Two credential-related indicators found"
    else:
        severity, reason = "HIGH", "Three credential-related indicators found"

    return {
        "detected": indicator_count > 0,
        "severity": severity,
        "reason": reason,
        "indicator_count": indicator_count,
        "indicators": indicator_names
    }


def detect_suspicious_process(command_line, image):
    indicators = []
    command_line_lower = (command_line or "").lower()
    image_lower = (image or "").lower()

    scripting_processes = ["powershell.exe", "pwsh.exe", "wscript.exe", "cscript.exe", "mshta.exe"]
    lolbin_processes = ["rundll32.exe", "regsvr32.exe", "certutil.exe"]

    encoded_commands = ["-enc", "-encodedcommand", "frombase64string"]
    powershell_execution = ["downloadstring", "invoke-expression", "iex", "executionpolicy bypass", "-nop",
                            "-noprofile"]
    certutil_behavior = ["-decode", "urlcache", "http://", "https://"]
    suspicious_paths = ["\\temp\\", "\\appdata\\", "\\downloads\\", "\\users\\public\\"]

    # Scripting processes with flags
    for process in scripting_processes:
        if process in image_lower:
            for command in encoded_commands + powershell_execution:
                if command in command_line_lower:
                    indicators.append(f"process:{process}")
                    indicators.append(f"command:{command}")

    # LOLBins behavior
    for process in lolbin_processes:
        if process in image_lower:
            if process == "rundll32.exe":
                if ".dll," in command_line_lower:
                    indicators.append("process:rundll32.exe")
                    indicators.append("dll_execution")
                if any(x in command_line_lower for x in ["comsvcs.dll", "minidump", "dump"]):
                    indicators.append("memory_dump_behavior")

            elif process == "regsvr32.exe":
                if "http://" in command_line_lower or "https://" in command_line_lower:
                    indicators.append("process:regsvr32.exe")
                    indicators.append("remote_execution")

            elif process == "certutil.exe":
                for command in certutil_behavior:
                    if command in command_line_lower:
                        indicators.append("process:certutil.exe")
                        indicators.append(f"command:{command}")

    # Suspicious path behavior
    if any(p in image_lower for p in scripting_processes + lolbin_processes):
        for path in suspicious_paths:
            if path in command_line_lower or path in image_lower:
                indicators.append(f"path:{path}")

    indicators = list(dict.fromkeys(indicators))

    if not indicators:
        return {"detected": False, "severity": "NONE", "reason": "No suspicious process behavior detected",
                "indicators": []}

    severity = "HIGH" if "memory_dump_behavior" in indicators or len(indicators) >= 3 else "MEDIUM"

    return {
        "detected": True,
        "severity": severity,
        "reason": "Suspicious process behavior detected" if len(
            indicators) < 3 else "Multiple suspicious process behaviors detected",
        "indicators": indicators
    }