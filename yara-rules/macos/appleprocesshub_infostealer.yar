rule AppleProcessHub_Structural {
    meta:
        description = "Detects AppleProcessHub/ProcessHub macOS stealer binary"
        author = "Abstract Security ASTRO - Justin Borland"
        date = "2025-06-19"
        malware_family = "AppleProcessHub"
        file_type = "Mach-O 64-bit"
        threat_type = "macOS stealer"
        confidence = "high"
        sample = "3f86c4cc956a6df5ddfad5d03334ece07e78351dec3ca62390f203f82675e00f"
        reference = "https://www.virustotal.com/gui/file/3f86c4cc956a6df5ddfad5d03334ece07e78351dec3ca62390f203f82675e00f"

    strings:
        // Crypto routines
        $func_aes = "aesd:" ascii
        $func_des_decrypt = "des12Decry:" ascii
        $func_des_encrypt = "des12Encry:" ascii

        // HTTP communication and Obj-C use
        $sel_data_task = "dataTaskWithRequest:completionHandler:" ascii
        $sel_session_cfg = "sessionWithConfiguration:" ascii
        $sel_http_header = "setValue:forHTTPHeaderField:" ascii
        $sel_http_method = "setHTTPMethod:" ascii
        $sel_string_fmt = "stringWithFormat:" ascii

        // System info / task execution
        $objc_task = "NSTask" ascii
        $objc_defaults = "NSUserDefaults" ascii
        $objc_platform = "IOPlatformSerialNumber" ascii
        
        // Shell reference
        $cmd_sh = "/bin/sh" ascii

    condition:
        // Mach-O 64-bit binary
        uint32(0) == 0xfeedfacf and
        filesize < 100KB and

        // Core indicators: crypto + HTTP logic + task/systeminfo + ObjC patterns
        all of ($func_*) and
        all of ($sel_*) and
        all of ($objc_*) and
        $cmd_sh
}

