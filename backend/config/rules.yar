rule SuspiciousReverseShell {
    meta:
        description = "Detects possible reverse shell execution patterns"
    strings:
        $net_socket1 = "net.Socket" ascii
        $net_socket2 = "net.socket" ascii
        $socket_connect1 = "socket.connect" ascii
        $socket_connect2 = "socket.Connect" ascii
        $socket_socket = "socket.socket" ascii
        $exec1 = "exec" ascii
        $exec2 = "Exec" ascii
        $subprocess1 = "subprocess" ascii
        $subprocess2 = "Subprocess" ascii
        $pty = "pty" ascii
    condition:
        ($net_socket1 or $net_socket2 or $socket_socket) and ($exec1 or $exec2 or $subprocess1 or $subprocess2 or $pty or $socket_connect1 or $socket_connect2)
}

rule EnvironmentExfiltration {
    meta:
        description = "Detects environment harvesting with outbound networking"
    strings:
        $env_js = "process.env" ascii
        $env_py = "os.environ" ascii
        $http_req1 = "http.request" ascii
        $http_req2 = "http.Request" ascii
        $http_get1 = "http.get" ascii
        $http_get2 = "http.Get" ascii
        $fetch1 = "fetch(" ascii
        $fetch2 = "Fetch(" ascii
        $axios1 = "axios" ascii
        $axios2 = "Axios" ascii
        $requests = "requests.post" ascii
        $urllib = "urllib.request" ascii
    condition:
        ($env_js or $env_py) and ($http_req1 or $http_req2 or $http_get1 or $http_get2 or $fetch1 or $fetch2 or $axios1 or $axios2 or $requests or $urllib)
}

rule ObfuscatedPayload {
    meta:
        description = "Detects obfuscated dynamic code execution chains"
    strings:
        $eval1 = "eval" ascii
        $eval2 = "Eval" ascii
        $exec1 = "exec" ascii
        $exec2 = "Exec" ascii
        $char_code = "String.fromCharCode" ascii
        $base64_1 = "base64" ascii
        $base64_2 = "Base64" ascii
        $rot13_1 = "rot13" ascii
        $rot13_2 = "Rot13" ascii
    condition:
        ($eval1 or $eval2 or $exec1 or $exec2) and ($char_code or $base64_1 or $base64_2 or $rot13_1 or $rot13_2)
}

rule DiscordExfiltration {
    meta:
        description = "Detects exfiltration via Discord Webhooks"
    strings:
        $discord_api1 = "discord.com/api/webhooks" ascii
        $discord_api2 = "discordapp.com/api/webhooks" ascii
        $webhook_token = /webhooks\/[0-9]{17,19}\/[a-zA-Z0-9_\-]+/ ascii
    condition:
        $discord_api1 or $discord_api2 or $webhook_token
}

rule TelegramExfiltration {
    meta:
        description = "Detects exfiltration via Telegram Bot API"
    strings:
        $telegram_api = "api.telegram.org/bot" ascii
        $bot_token = /bot[0-9]{8,12}:[a-zA-Z0-9_\-]{35,40}/ ascii
    condition:
        $telegram_api or $bot_token
}

rule CredentialPathTheft {
    meta:
        description = "Detects access/references to sensitive credential storage paths"
    strings:
        $aws1 = ".aws/credentials" ascii
        $aws2 = ".aws\\credentials" ascii
        $ssh = ".ssh/id_rsa" ascii
        $passwd = "etc/passwd" ascii
        $git = ".git-credentials" ascii
        $chrome_cookies = "cookies.sqlite" ascii
        $chrome_login = "Login Data" ascii
        $chrome_state = "Local State" ascii
    condition:
        any of them
}

rule MaliciousInstallerDownloader {
    meta:
        description = "Detects download-and-execute installer patterns"
    strings:
        $curl = "curl" ascii
        $wget = "wget" ascii
        $powershell1 = "powershell" ascii
        $powershell2 = "Powershell" ascii
        $powershell3 = "PowerShell" ascii
        $chmod = "chmod" ascii
        $exec = "exec" ascii
        $spawn = "spawn" ascii
        $system = "system" ascii
        $temp1 = "temp" ascii
        $temp2 = "Temp" ascii
        $temp3 = "TEMP" ascii
        $appdata1 = "appdata" ascii
        $appdata2 = "AppData" ascii
        $appdata3 = "APPDATA" ascii
        $tmp = "tmp" ascii
    condition:
        ($curl or $wget or $powershell1 or $powershell2 or $powershell3) and ($chmod or $exec or $spawn or $system) and ($temp1 or $temp2 or $temp3 or $appdata1 or $appdata2 or $appdata3 or $tmp)
}

rule SandboxEvasionDetected {
    meta:
        description = "Detects code attempting to identify sandbox, virtual machines, or CI environments"
    strings:
        $ci_env1 = "process.env.CI" ascii
        $ci_env2 = "process.env.GITHUB_ACTIONS" ascii
        $ci_env3 = "process.env.TRAVIS" ascii
        $ci_env4 = "os.environ.get('CI')" ascii
        $ci_env5 = "os.environ.get(\"CI\")" ascii
        $vm_vbox1 = "virtualbox" ascii
        $vm_vbox2 = "VirtualBox" ascii
        $vm_vmware1 = "vmware" ascii
        $vm_vmware2 = "VMware" ascii
        $vm_vboxguest = "vboxguest" ascii
        $vm_vboxservice = "VBoxService" ascii
        $vm_qemu = "qemu" ascii
        $vm_xen = "xen" ascii
    condition:
        any of them
}

