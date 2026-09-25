from detector.rules import (
    detect_credential_prompt,
    detect_amsi_and_logging_bypass,
    detect_in_memory_execution,
    detect_suspicious_process,
    detect_system_recovery_tampering,
    detect_suspicious_parent
)


# --- Event ID 4104 Tests ---

def test_credential_detection():
    script = """
    PromptForCredential
    GetNetworkCredential
    ValidateCredentials
    """

    result = detect_credential_prompt(script)

    assert result["detected"] is True
    assert result["severity"] == "HIGH"
    assert len(result["indicators"]) == 3


def test_credential_partial_matches():
    script_one = "PromptForCredential"
    script_two = "PromptForCredential GetNetworkCredential"

    res_low = detect_credential_prompt(script_one)
    res_med = detect_credential_prompt(script_two)

    assert res_low["detected"] is True
    assert res_low["severity"] == "LOW"
    assert "credential_prompt:promptforcredential" in res_low["indicators"]

    assert res_med["detected"] is True
    assert res_med["severity"] == "MEDIUM"


def test_amsi_bypass_detection():
    script = "sYsTeM.mAnAgEmEnT.aUtOmAtIoN.aMsIUtils.GetField('amsiInitFailed')"
    result = detect_amsi_and_logging_bypass(script)

    assert result["detected"] is True
    assert result["severity"] == "HIGH"
    assert any("amsi_bypass" in ind for ind in result["indicators"])


def test_in_memory_execution_detection():
    script = "[Reflection.Assembly]::Load([System.Convert]::FromBase64String('...'))"
    result = detect_in_memory_execution(script)

    assert result["detected"] is True
    assert result["severity"] == "HIGH"
    assert "in_memory_execution:[reflection.assembly]::load" in result["indicators"]


# --- Event ID 1 Tests ---

def test_suspicious_process_detection():
    cmd = "powershell.exe -nop -enc AAAA..."
    image = "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe"

    result = detect_suspicious_process(cmd, image)

    assert result["detected"] is True
    assert "process:powershell.exe" in result["indicators"]


def test_recovery_tampering_detection():
    cmd = "vssadmin.exe Delete Shadows /All /Quiet"
    image = "C:\\Windows\\System32\\vssadmin.exe"

    result = detect_system_recovery_tampering(cmd, image)

    assert result["detected"] is True
    assert result["severity"] == "HIGH"
    assert "vssadmin_shadow_deletion" in result["indicators"]


def test_suspicious_parent_detection():
    parent = "C:\\Program Files\\Microsoft Office\\Office16\\WINWORD.EXE"
    child = "C:\\Windows\\System32\\cmd.exe"

    result = detect_suspicious_parent(parent, child)

    assert result["detected"] is True
    assert result["severity"] == "HIGH"
    assert "parent:winword.exe" in result["indicators"]
    assert "child_spawned:cmd.exe" in result["indicators"]


# --- Benign Telemetry Tests ---

def test_benign_script():
    script = "Write-Output 'Hello World'"

    res_cred = detect_credential_prompt(script)
    res_amsi = detect_amsi_and_logging_bypass(script)
    res_mem = detect_in_memory_execution(script)

    assert res_cred["detected"] is False
    assert res_amsi["detected"] is False
    assert res_mem["detected"] is False


def test_benign_process():
    cmd = "C:\\Windows\\System32\\notepad.exe C:\\Users\\user\\document.txt"
    image = "C:\\Windows\\System32\\notepad.exe"

    result = detect_suspicious_process(cmd, image)

    assert result["detected"] is False