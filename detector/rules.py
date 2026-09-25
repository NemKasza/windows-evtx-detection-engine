def detect_credential_prompt(script):
    script_lower = (script or "").lower()

    targets = [
        "promptforcredential",
        "getnetworkcredential",
        "validatecredentials"
    ]

    indicators = [f"credential_prompt:{target}" for target in targets if target in script_lower]
    indicator_count = len(indicators)

    if indicator_count == 0:
        return {
            "detected": False,
            "severity": "NONE",
            "reason": "No credential-related indicators found",
            "indicators": []
        }

    severity = "HIGH" if indicator_count >= 3 else ("MEDIUM" if indicator_count == 2 else "LOW")

    return {
        "detected": True,
        "severity": severity,
        "reason": f"Credential harvesting indicator(s) detected ({indicator_count} matched)",
        "indicators": indicators
    }


def detect_amsi_and_logging_bypass(script):
    script_lower = (script or "").lower()
    indicators = []

    amsi_patterns = ["amsiutils", "amsiinitfailed", "amsicontext", "amsiscanbuffer"]
    memory_patch_patterns = ["getfield('amsiinitfailed'", "system.management.automation.amsi", "marshal::copy"]
    etw_patterns = ["etweventwrite", "scriptblocklogging"]

    for pattern in amsi_patterns + memory_patch_patterns:
        if pattern in script_lower:
            indicators.append(f"amsi_bypass:{pattern}")

    for pattern in etw_patterns:
        if pattern in script_lower:
            indicators.append(f"logging_tampering:{pattern}")

    indicators = list(dict.fromkeys(indicators))

    if not indicators:
        return {"detected": False, "severity": "NONE", "reason": "No AMSI or logging bypass indicators found", "indicators": []}

    return {
        "detected": True,
        "severity": "HIGH",
        "reason": "AMSI or Security Telemetry Bypass Attempt Detected",
        "indicators": indicators
    }


def detect_in_memory_execution(script):
    script_lower = (script or "").lower()
    indicators = []

    reflection_triggers = [
        "[reflection.assembly]::load",
        "[system.reflection.assembly]::load",
        "add-type -typedefinition",
        "virtualalloc",
        "createthread"
    ]

    for trigger in reflection_triggers:
        if trigger in script_lower:
            indicators.append(f"in_memory_execution:{trigger}")

    if not indicators:
        return {"detected": False, "severity": "NONE", "reason": "No in-memory execution indicators found", "indicators": []}

    return {
        "detected": True,
        "severity": "HIGH",
        "reason": "In-memory .NET assembly loading or shellcode allocation detected",
        "indicators": indicators
    }


def detect_suspicious_process(command_line, image):
    indicators = []
    command_line_lower = (command_line or "").lower()
    image_lower = (image or "").lower()

    scripting_processes = ["powershell.exe", "pwsh.exe", "wscript.exe", "cscript.exe", "mshta.exe"]
    lolbin_processes = ["rundll32.exe", "regsvr32.exe", "certutil.exe"]

    encoded_commands = ["-enc", "-encodedcommand", "frombase64string"]
    powershell_execution = ["downloadstring", "invoke-expression", "iex", "executionpolicy bypass", "-nop", "-noprofile"]
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
        return {"detected": False, "severity": "NONE", "reason": "No suspicious process behavior detected", "indicators": []}

    severity = "HIGH" if "memory_dump_behavior" in indicators or len(indicators) >= 3 else "MEDIUM"

    return {
        "detected": True,
        "severity": severity,
        "reason": "Suspicious process behavior detected" if len(indicators) < 3 else "Multiple suspicious process behaviors detected",
        "indicators": indicators
    }


def detect_system_recovery_tampering(command_line, image):
    cmd_lower = (command_line or "").lower()
    indicators = []

    if "vssadmin" in cmd_lower and "delete" in cmd_lower and "shadows" in cmd_lower:
        indicators.append("vssadmin_shadow_deletion")

    if "wmic" in cmd_lower and "shadowcopy" in cmd_lower and "delete" in cmd_lower:
        indicators.append("wmic_shadow_deletion")

    if "bcdedit" in cmd_lower and ("bootstatuspolicy" in cmd_lower or "recoveryenabled" in cmd_lower):
        indicators.append("bcdedit_recovery_disabled")

    if "wbadmin" in cmd_lower and "delete" in cmd_lower:
        indicators.append("wbadmin_backup_deletion")

    if not indicators:
        return {"detected": False, "severity": "NONE", "reason": "No recovery tampering detected", "indicators": []}

    return {
        "detected": True,
        "severity": "HIGH",
        "reason": "System backup or Volume Shadow Copy deletion detected (Ransomware behavior)",
        "indicators": indicators
    }


def detect_suspicious_parent(parent_image, child_image):
    parent_lower = (parent_image or "").lower()
    child_lower = (child_image or "").lower()

    suspicious_parents = [
        "winword.exe", "excel.exe", "powerpnt.exe", "outlook.exe",
        "w3wp.exe", "httpd.exe", "nginx.exe",
        "sqlserver.exe", "mysqld.exe"
    ]

    dangerous_children = [
        "cmd.exe", "powershell.exe", "pwsh.exe",
        "wscript.exe", "cscript.exe", "mshta.exe", "certutil.exe"
    ]

    indicators = []

    for parent in suspicious_parents:
        if parent in parent_lower:
            for child in dangerous_children:
                if child in child_lower:
                    indicators.append(f"parent:{parent}")
                    indicators.append(f"child_spawned:{child}")

    if not indicators:
        return {"detected": False, "severity": "NONE", "reason": "No suspicious parent-child process relationship detected", "indicators": []}

    return {
        "detected": True,
        "severity": "HIGH",
        "reason": f"Suspicious parent process '{parent_image}' spawned shell engine '{child_image}'",
        "indicators": indicators
    }