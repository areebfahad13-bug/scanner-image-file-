/*
    Sample YARA Rules for EDR System
    These are basic example rules - add your own custom rules here
*/

rule suspicious_high_entropy {
    meta:
        description = "Detects files with suspiciously high entropy"
        author = "EDR-System"
        date = "2025-11-24"
        severity = "medium"
    
    condition:
        filesize > 10KB and
        filesize < 10MB and
        math.entropy(0, filesize) > 7.5
}

rule embedded_executable {
    meta:
        description = "Detects embedded PE files"
        author = "EDR-System"
        severity = "high"
    
    strings:
        $mz = "MZ"
        $pe = "PE\x00\x00"
    
    condition:
        $mz at 0 or
        ($mz and $pe)
}

rule suspicious_file_extension_mismatch {
    meta:
        description = "Detects files with mismatched extension and content"
        author = "EDR-System"
        severity = "medium"
    
    strings:
        $pdf_magic = "%PDF"
        $exe_magic = { 4D 5A }
        $zip_magic = { 50 4B 03 04 }
    
    condition:
        (filename matches /\.txt$/i and ($pdf_magic at 0 or $exe_magic at 0)) or
        (filename matches /\.jpg$/i and $exe_magic at 0) or
        (filename matches /\.doc$/i and $zip_magic at 0)
}

rule packed_executable {
    meta:
        description = "Detects potentially packed executables"
        author = "EDR-System"
        severity = "high"
    
    strings:
        $upx1 = "UPX0"
        $upx2 = "UPX1"
        $aspack = "aPLib"
        $petite = "Petite"
        $mew = "MEW"
    
    condition:
        uint16(0) == 0x5A4D and
        ($upx1 or $upx2 or $aspack or $petite or $mew)
}

rule suspicious_script_patterns {
    meta:
        description = "Detects suspicious script patterns"
        author = "EDR-System"
        severity = "medium"
    
    strings:
        $cmd1 = "powershell.exe" nocase
        $cmd2 = "cmd.exe /c" nocase
        $cmd3 = "wget" nocase
        $cmd4 = "curl" nocase
        $obfuscation1 = "fromCharCode"
        $obfuscation2 = "eval("
        $obfuscation3 = "base64"
        $registry = "HKEY_CURRENT_USER\\Software\\Microsoft\\Windows\\CurrentVersion\\Run" nocase
    
    condition:
        2 of ($cmd*) or
        2 of ($obfuscation*) or
        ($cmd1 and $registry)
}

rule ransomware_indicators {
    meta:
        description = "Detects common ransomware behavior indicators"
        author = "EDR-System"
        severity = "critical"
    
    strings:
        $encrypt1 = "CryptEncrypt" nocase
        $encrypt2 = "AES" nocase
        $encrypt3 = "RSA" nocase
        $file1 = ".encrypted"
        $file2 = ".locked"
        $file3 = "README"
        $ransom1 = "bitcoin" nocase
        $ransom2 = "decrypt" nocase
        $ransom3 = "ransom" nocase
    
    condition:
        2 of ($encrypt*) and
        (1 of ($file*) or 2 of ($ransom*))
}

rule network_activity_indicators {
    meta:
        description = "Detects network communication patterns"
        author = "EDR-System"
        severity = "medium"
    
    strings:
        $http1 = "http://" nocase
        $http2 = "https://" nocase
        $socket1 = "socket"
        $socket2 = "connect"
        $ip_pattern = /\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}:\d{1,5}/
    
    condition:
        ($http1 or $http2) and
        ($socket1 or $socket2) and
        $ip_pattern
}
