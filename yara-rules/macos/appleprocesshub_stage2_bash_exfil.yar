rule AppleProcessHub_BashStage2_Exfil {
    meta:
        description = "Detects stage 2 MacOS bash exfiltration tools using system profiling, sensitive file staging, exfil, and cleanup"
        author = "Abstract Security ASTRO - Justin Borland"
        date = "2025-06-19"
        malware_family = "AppleProcessHub"
        file_type = "Stage 2 exfil"
        threat_type = "macOS infostealer"
        confidence = "high"
        sample = "639e824e329c429a53d0e64f3a4f254131443a669da93a59a755fb7171d49745"
        reference = "https://www.virustotal.com/gui/file/639e824e329c429a53d0e64f3a4f254131443a669da93a59a755fb7171d49745"

    strings:
        // System profiling
        $uname = /uname\s+-[armnsp]/ ascii

        // Data staging commands
        $zip = /zip\s+-r/ ascii

        // Copy commands
        $cp_0 = /cp\s+-r/ ascii
        $cp_1 = "cp " ascii

        // Cleanup commands
        $rm_0 = /rm\s+-rf/ ascii
        $rm_1 = "rm " ascii

        // Exfil
        $web_0 = "curl" ascii
        $web_1 = "wget" ascii

        // Stolen file targets
        $hist_0 = ".bash_history" ascii
        $hist_1 = ".zsh_history" ascii
        $hist_2 = ".gitconfig" ascii
        $hist_3 = "/.ssh" ascii
        $hist_4 = "Login.keychain-db" ascii

        // Hardware serial profiling
        $hardware_0 = /ioreg\s+-l/ ascii
        $hardware_1 = "IOPlatformSerialNumber" ascii

    condition:
        filesize < 25KB and
        $zip and
        #uname > 3 and
        1 of ($web_*) and
        1 of ($rm_*) and
        1 of ($cp_*) and
        3 of ($hist_*) and
        1 of ($hardware_*)
}

