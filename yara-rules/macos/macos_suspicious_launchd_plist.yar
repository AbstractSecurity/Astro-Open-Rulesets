rule Suspicious_macOS_Launchd_Plist
{
  meta:
    description = "Detects suspicious macOS LaunchAgent/LaunchDaemon plist files with signs of persistence or execution"
    author = "Abstract Security ASTRO - Justin Borland"
    date = "2025-06-24"

  strings:
    // plist identification
    $plist_tag = "<plist version=" ascii
    $bplist = "bplist00"

    // Persistence keys
    $persistence_runatload = "RunAtLoad" ascii
    $persistence_keepalive = "KeepAlive" ascii
    $persistence_startinterval = "StartInterval" ascii
    $persistence_startcalendarinterval = "StartCalendarInterval" ascii
    $persistence_watchpaths = "WatchPaths" ascii
    $persistence_queuedirectories = "QueueDirectories" ascii
    $persistence_sockets = "Sockets" ascii
    $persistence_programargs = "ProgramArguments" ascii
    $persistence_program = "Program" ascii

    // Suspicious command keywords
    $suspicious_cmd_networksetup1 = "networksetup -setwebproxy" ascii
    $suspicious_cmd_networksetup2 = "networksetup -setsecurewebproxy" ascii
    $suspicious_cmd_curl = "curl" ascii
    $suspicious_cmd_wget = "wget" ascii
    $suspicious_cmd_osascript = "osascript" ascii
    $suspicious_cmd_base64 = "base64" ascii
    $suspicious_cmd_eval = "eval" ascii
    $suspicious_cmd_python = "python" ascii
    $suspicious_cmd_launchctl = "launchctl" ascii
    $suspicious_cmd_bash = "bash" ascii
    $suspicious_cmd_sh = "sh" ascii
    $suspicious_cmd_zsh = "zsh" ascii

    // Suspicious file paths
    $suspicious_path_dot_hidden = "/Library/.cache/" ascii
    $suspicious_path_tmp = "/private/tmp/" ascii
    $suspicious_path_shared = "/Users/Shared/" ascii
    $suspicious_path_var_tmp = "/var/tmp/" ascii
    $suspicious_path_dev_null = "/dev/null" ascii

  condition:
    // Must be a plist (XML or binary)
    ($plist_tag or $bplist) and

    // Must have any persistence key
    any of ($persistence_*) and

    // Must have suspicious command or suspicious path indicator
    (
      any of ($suspicious_cmd_*) or
      any of ($suspicious_path_*)
    )
}
