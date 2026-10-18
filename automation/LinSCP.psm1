#Requires -Version 7.0
# PowerShell 7 (pwsh) on Linux is the supported host. Windows PowerShell 5.1
# is a Windows-only shell and does not run on this platform.
<#
.SYNOPSIS
    PowerShell module for LinSCP - Linux secure file transfer client.

.DESCRIPTION
    Provides cmdlets for automating LinSCP from PowerShell on Linux.
    The module wraps the linscp command-line client, providing
    structured PowerShell objects for session management, file transfer,
    directory listing and synchronization.

    This is a compatibility shim for the WinSCP .NET assembly API,
    implemented through the LinSCP CLI with -server mode for persistent
    sessions.

.EXAMPLE
    $session = Open-LScpSession -Url "sftp://user@host:22/path"
    Get-LScpItem -Session $session -RemotePath "/data/file.txt" -LocalPath "/tmp/file.txt"
    Close-LScpSession -Session $session
#>

$Script:LinScpBin = $null
$Script:Sessions = @{}

function Find-LinScpBinary {
    <#
    .SYNOPSIS
        Locates the linscp binary on PATH.
    #>
    if ($Script:LinScpBin) { return $Script:LinScpBin }
    $candidates = @(
        "linscp",
        "/usr/bin/linscp",
        "/usr/local/bin/linscp",
        (Join-Path $env:HOME ".local/bin/linscp")
    )
    foreach ($c in $candidates) {
        if (Get-Command $c -ErrorAction SilentlyContinue) {
            $Script:LinScpBin = (Get-Command $c).Source
            return $Script:LinScpBin
        }
        if (Test-Path $c) {
            $Script:LinScpBin = $c
            return $Script:LinScpBin
        }
    }
    throw "linscp binary not found. Install LinSCP or add it to PATH."
}

function ConvertTo-LScpArgument {
    <#
    .SYNOPSIS
        Escapes a value for the LinSCP command splitter.

    .DESCRIPTION
        The splitter follows the rules of a POSIX shell: a word in double
        quotes keeps its blanks, and a backslash inside those quotes is
        literal unless it stands in front of a double quote or of another
        backslash. A backslash is therefore doubled and a double quote is
        escaped, and the whole value is wrapped in double quotes.
    #>
    param([string]$Value)
    if ($null -eq $Value) { return '""' }
    if ($Value -match "[\x00-\x1F\x7F]") {
        throw "Value contains a control character and cannot be safely quoted."
    }
    if ($Value -notmatch '[ \t\"'';\\]') { return $Value }
    $escaped = $Value -replace '\\', '\\' -replace '"', '\"'
    return '"' + $escaped + '"'
}

function Invoke-LinScp {
    <#
    .SYNOPSIS
        Runs a linscp command and returns structured output.
    #>
    param(
        [string[]]$Arguments,
        [switch]$CaptureOutput
    )
    $bin = Find-LinScpBinary
    $psi = New-Object System.Diagnostics.ProcessStartInfo
    $psi.FileName = $bin
    # Use ArgumentList when available (pwsh 7+ on .NET Core) to avoid shell
    # interpolation; fall back to manual quoting for older hosts.
    if ($psi.PSObject.Properties.Match('ArgumentList').Count -gt 0) {
        $psi.ArgumentList.Clear()
        foreach ($a in $Arguments) { $psi.ArgumentList.Add($a) }
    } else {
        $psi.Arguments = ($Arguments | ForEach-Object { ConvertTo-LScpArgument $_ }) -join " "
    }
    $psi.RedirectStandardOutput = $true
    $psi.RedirectStandardError = $true
    $psi.UseShellExecute = $false
    $psi.CreateNoWindow = $true
    $proc = [System.Diagnostics.Process]::Start($psi)
    $stdout = $proc.StandardOutput.ReadToEnd()
    $stderr = $proc.StandardError.ReadToEnd()
    $proc.WaitForExit()
    [PSCustomObject]@{
        ExitCode = $proc.ExitCode
        Stdout   = $stdout
        Stderr   = $stderr
    }
}

function Open-LScpSession {
    <#
    .SYNOPSIS
        Opens a persistent LinSCP session.
    .PARAMETER Url
        The session URL (sftp://user@host:port/path).
    .PARAMETER Password
        Password for authentication.
    .PARAMETER HostKey
        Expected host key fingerprint.
    .PARAMETER PrivateKey
        Path to the private key file.
    .OUTPUTS
        A session object for use with other cmdlets.
    #>
    param(
        [Parameter(Mandatory=$true)]
        [string]$Url,
        [string]$Password,
        [string]$HostKey,
        [string]$PrivateKey
    )
    $bin = Find-LinScpBinary
    $proc = New-Object System.Diagnostics.Process
    $proc.StartInfo.FileName = $bin
    $proc.StartInfo.Arguments = "-server"
    $proc.StartInfo.RedirectStandardInput = $true
    $proc.StartInfo.RedirectStandardOutput = $true
    $proc.StartInfo.RedirectStandardError = $true
    $proc.StartInfo.UseShellExecute = $false
    $proc.StartInfo.CreateNoWindow = $true
    $proc.Start() | Out-Null

    # Wait for the ready banner.
    $ready = $proc.StandardOutput.ReadLine()
    if ($ready -notmatch "^LSCP-SERVER") {
        $proc.Kill()
        throw "LinSCP server did not start correctly."
    }

    $session = [PSCustomObject]@{
        Process = $proc
        Url     = $Url
        Stdin   = $proc.StandardInput
        Stdout  = $proc.StandardOutput
    }

    # Build the open command with proper quoting so a URL or password
    # holding spaces, semicolons or quotes does not become a second
    # command when the server splits on ';' and quotes.
    $openCmd = "open $(ConvertTo-LScpArgument $Url)"
    if ($Password) { $openCmd += " -password=$(ConvertTo-LScpArgument $Password)" }
    if ($HostKey)  { $openCmd += " -hostkey=$(ConvertTo-LScpArgument $HostKey)" }
    if ($PrivateKey) { $openCmd += " -privatekey=$(ConvertTo-LScpArgument $PrivateKey)" }

    $session.Stdin.WriteLine($openCmd)
    $session.Stdin.Flush()
    $result = $session.Stdout.ReadLine()
    if ($result -match "LSCP-RESULT 1") {
        $session.Process.Kill()
        throw "Failed to open session: $result"
    }

    $sessionId = [guid]::NewGuid().ToString()
    $Script:Sessions[$sessionId] = $session
    $session | Add-Member -NotePropertyName "Id" -NotePropertyValue $sessionId
    return $session
}

function Close-LScpSession {
    <#
    .SYNOPSIS
        Closes a LinSCP session.
    #>
    param(
        [Parameter(Mandatory=$true)]
        [PSCustomObject]$Session
    )
    try {
        $Session.Stdin.WriteLine("close")
        $Session.Stdin.Flush()
        $Session.Stdout.ReadLine() | Out-Null
        $Session.Stdin.WriteLine("exit")
        $Session.Stdin.Flush()
        $Session.Process.WaitForExit(5000) | Out-Null
    } catch {
        try { $Session.Process.Kill() } catch {}
    }
    if ($Session.Id -and $Script:Sessions.ContainsKey($Session.Id)) {
        $Script:Sessions.Remove($Session.Id)
    }
}

function Get-LScpItem {
    <#
    .SYNOPSIS
        Downloads a file from the remote server.
    #>
    param(
        [Parameter(Mandatory=$true)]
        [PSCustomObject]$Session,
        [Parameter(Mandatory=$true)]
        [string]$RemotePath,
        [Parameter(Mandatory=$true)]
        [string]$LocalPath,
        [switch]$PreserveTime
    )
    $cmd = "get $(ConvertTo-LScpArgument $RemotePath) $(ConvertTo-LScpArgument $LocalPath)"
    if ($PreserveTime) { $cmd += " -preservetime" }
    $Session.Stdin.WriteLine($cmd)
    $Session.Stdin.Flush()
    $result = $Session.Stdout.ReadLine()
    $Session.Stdout.ReadLine() | Out-Null
    return [PSCustomObject]@{
        Success = $result -notmatch "LSCP-RESULT 1"
        Output  = $result
    }
}

function Send-LScpItem {
    <#
    .SYNOPSIS
        Uploads a file to the remote server.
    #>
    param(
        [Parameter(Mandatory=$true)]
        [PSCustomObject]$Session,
        [Parameter(Mandatory=$true)]
        [string]$LocalPath,
        [Parameter(Mandatory=$true)]
        [string]$RemotePath,
        [switch]$PreserveTime
    )
    $cmd = "put $(ConvertTo-LScpArgument $LocalPath) $(ConvertTo-LScpArgument $RemotePath)"
    if ($PreserveTime) { $cmd += " -preservetime" }
    $Session.Stdin.WriteLine($cmd)
    $Session.Stdin.Flush()
    $result = $Session.Stdout.ReadLine()
    $Session.Stdout.ReadLine() | Out-Null
    return [PSCustomObject]@{
        Success = $result -notmatch "LSCP-RESULT 1"
        Output  = $result
    }
}

function Get-LScpDirectory {
    <#
    .SYNOPSIS
        Lists a remote directory.
    #>
    param(
        [Parameter(Mandatory=$true)]
        [PSCustomObject]$Session,
        [string]$RemotePath
    )
    $cmd = "ls"
    if ($RemotePath) { $cmd += " $(ConvertTo-LScpArgument $RemotePath)" }
    $Session.Stdin.WriteLine($cmd)
    $Session.Stdin.Flush()
    $lines = @()
    while ($true) {
        $line = $Session.Stdout.ReadLine()
        if ($line -match "^LSCP-RESULT") { break }
        $lines += $line
    }
    return $lines
}

function Sync-LScpDirectory {
    <#
    .SYNOPSIS
        Synchronizes directories.
    #>
    param(
        [Parameter(Mandatory=$true)]
        [PSCustomObject]$Session,
        [Parameter(Mandatory=$true)]
        [string]$Direction,
        [string]$LocalDir,
        [string]$RemoteDir,
        [switch]$Delete,
        [switch]$Preview
    )
    if ($Direction -notin @('local','remote','both')) {
        throw "Direction must be local, remote or both."
    }
    $cmd = "synchronize $Direction"
    if ($LocalDir) { $cmd += " $(ConvertTo-LScpArgument $LocalDir)" }
    if ($RemoteDir) { $cmd += " $(ConvertTo-LScpArgument $RemoteDir)" }
    if ($Delete) { $cmd += " -delete" }
    if ($Preview) { $cmd += " -preview" }
    $Session.Stdin.WriteLine($cmd)
    $Session.Stdin.Flush()
    $lines = @()
    while ($true) {
        $line = $Session.Stdout.ReadLine()
        if ($line -match "^LSCP-RESULT") { break }
        $lines += $line
    }
    return [PSCustomObject]@{
        Success = $lines[-1] -notmatch "LSCP-RESULT 1"
        Lines   = $lines
    }
}

Export-ModuleMember -Function @(
    "Find-LinScpBinary",
    "Invoke-LinScp",
    "Open-LScpSession",
    "Close-LScpSession",
    "Get-LScpItem",
    "Send-LScpItem",
    "Get-LScpDirectory",
    "Sync-LScpDirectory"
)