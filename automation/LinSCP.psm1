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

    The -server protocol is one command per line on the client's stdin.
    The client answers with any number of output lines on stdout, then
    exactly one 'LSCP-RESULT <code>' line; its diagnostics go to stderr.
    Every cmdlet here therefore reads stdout up to the marker line and
    drains stderr while it waits, instead of assuming how many lines a
    command prints: 'open' prints a 'Connecting to...' line before its
    marker, a failed 'get' prints nothing but the marker, and a reader
    that expected a fixed number of lines fell out of step with the
    server on the first command that printed a different number.

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
        Locates the linscp binary on PATH, or in the usual install locations.
    #>
    if ($Script:LinScpBin) { return $Script:LinScpBin }
    $homeDir = if ($env:HOME) { $env:HOME } else { [Environment]::GetFolderPath('UserProfile') }
    $candidates = @(
        "linscp",
        "/usr/bin/linscp",
        "/usr/local/bin/linscp"
    )
    if ($homeDir) {
        $candidates += (Join-Path $homeDir ".local/bin/linscp")
    }
    # PREFIX/share/linscp/automation/LinSCP.psm1 -> PREFIX/bin/linscp,
    # whatever prefix 'make install' or 'cmake --install' used.
    $candidates += (Join-Path $PSScriptRoot "../../../bin/linscp")
    foreach ($c in $candidates) {
        $command = Get-Command $c -CommandType Application -ErrorAction SilentlyContinue
        if ($command) {
            $Script:LinScpBin = $command.Source
            return $Script:LinScpBin
        }
        if ((Test-Path -LiteralPath $c -PathType Leaf)) {
            $Script:LinScpBin = (Resolve-Path -LiteralPath $c).Path
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

        A control character cannot be quoted at all: the server reads one
        command per line, so a value holding a newline would be a second
        command. Such a value is refused.
    #>
    param([string]$Value)
    if ($null -eq $Value -or $Value -eq '') { return '""' }
    if ($Value -match "[\x00-\x1F\x7F]") {
        throw "Value contains a control character and cannot be safely quoted."
    }
    if ($Value -notmatch '[ \t\"'';\\]') { return $Value }
    $escaped = $Value -replace '\\', '\\' -replace '"', '\"'
    return '"' + $escaped + '"'
}

function New-LScpProcessStartInfo {
    param([string[]]$Arguments)
    $psi = New-Object System.Diagnostics.ProcessStartInfo
    $psi.FileName = Find-LinScpBinary
    foreach ($a in $Arguments) { $psi.ArgumentList.Add($a) }
    $psi.RedirectStandardInput = $true
    $psi.RedirectStandardOutput = $true
    $psi.RedirectStandardError = $true
    $psi.UseShellExecute = $false
    $psi.CreateNoWindow = $true
    # The listing parser below reads the client's status lines, which are
    # translated; the objects this module returns are the same in every
    # locale, so the client it drives speaks English to it.
    $psi.Environment["LINSCP_LANGUAGE"] = "en"
    return $psi
}

function Invoke-LinScp {
    <#
    .SYNOPSIS
        Runs a linscp command line to completion and returns its output.
    .PARAMETER Arguments
        The command-line arguments, one per element; they are passed to the
        process as they are, with no shell in between.
    .OUTPUTS
        An object with ExitCode, Stdout and Stderr.
    #>
    param(
        [string[]]$Arguments,
        [switch]$CaptureOutput
    )
    $psi = New-LScpProcessStartInfo -Arguments $Arguments
    $psi.RedirectStandardInput = $false
    $proc = [System.Diagnostics.Process]::Start($psi)
    # Both pipes are read at once: reading one to its end while the other
    # fills its buffer stops the client, which then never ends either.
    $stderrTask = $proc.StandardError.ReadToEndAsync()
    $stdout = $proc.StandardOutput.ReadToEnd()
    $stderr = $stderrTask.GetAwaiter().GetResult()
    $proc.WaitForExit()
    [PSCustomObject]@{
        ExitCode = $proc.ExitCode
        Stdout   = $stdout
        Stderr   = $stderr
    }
}

function Read-LScpResponse {
    <#
    .SYNOPSIS
        Reads the server's answer to one command: every stdout line up to
        the 'LSCP-RESULT <code>' marker, and whatever reached stderr
        meanwhile.
    #>
    param(
        [Parameter(Mandatory=$true)]
        [PSCustomObject]$Session,
        [int]$TimeoutSeconds = 0
    )
    $lines = New-Object System.Collections.Generic.List[string]
    $errors = New-Object System.Collections.Generic.List[string]
    $deadline = if ($TimeoutSeconds -gt 0) { [DateTime]::UtcNow.AddSeconds($TimeoutSeconds) } else { [DateTime]::MaxValue }
    while ($true) {
        if ($null -eq $Session.StdoutTask) {
            $Session.StdoutTask = $Session.Stdout.ReadLineAsync()
        }
        if ($null -eq $Session.StderrTask -and -not $Session.StderrClosed) {
            $Session.StderrTask = $Session.Stderr.ReadLineAsync()
        }
        $tasks = New-Object System.Collections.Generic.List[System.Threading.Tasks.Task]
        $tasks.Add($Session.StdoutTask)
        if ($null -ne $Session.StderrTask) { $tasks.Add($Session.StderrTask) }
        $waitMs = -1
        if ($TimeoutSeconds -gt 0) {
            $remaining = ($deadline - [DateTime]::UtcNow).TotalMilliseconds
            if ($remaining -le 0) {
                Stop-LScpProcess -Session $Session
                throw "The LinSCP command did not answer within $TimeoutSeconds seconds; the session was closed."
            }
            $waitMs = [int][Math]::Ceiling($remaining)
        }
        $index = [System.Threading.Tasks.Task]::WaitAny($tasks.ToArray(), $waitMs)
        if ($index -lt 0) { continue }
        if ($tasks[$index] -eq $Session.StderrTask) {
            $line = $Session.StderrTask.GetAwaiter().GetResult()
            $Session.StderrTask = $null
            if ($null -eq $line) { $Session.StderrClosed = $true } else { $errors.Add($line) }
            continue
        }
        $line = $Session.StdoutTask.GetAwaiter().GetResult()
        $Session.StdoutTask = $null
        if ($null -eq $line) {
            # The server is gone. Whatever stderr still holds says why. A
            # read that is still outstanding is finished first: a second
            # read on the same stream while one is pending is an error.
            if ($null -ne $Session.StderrTask) {
                $pending = $Session.StderrTask.GetAwaiter().GetResult()
                $Session.StderrTask = $null
                if ($null -eq $pending) { $Session.StderrClosed = $true } else { $errors.Add($pending) }
            }
            if (-not $Session.StderrClosed) {
                $rest = $Session.Stderr.ReadToEnd()
                if ($rest) { $errors.AddRange([string[]]($rest -split "`n" | Where-Object { $_ })) }
                $Session.StderrClosed = $true
            }
            $detail = ($errors -join "`n").Trim()
            if (-not $detail) { $detail = "The LinSCP server process ended unexpectedly." }
            throw $detail
        }
        if ($line -match '^LSCP-RESULT (\d+)') {
            # Read the code before anything else runs: a -match anywhere in
            # between would replace $Matches with its own result.
            $code = [int]$Matches[1]
            # The marker won the race with stderr: a diagnostic line that
            # arrived just after it would otherwise be lost, leaving a
            # failure with nothing saying why. Collect what already
            # finished, without waiting for what did not.
            if ($null -ne $Session.StderrTask -and $Session.StderrTask.IsCompleted) {
                $trailing = $Session.StderrTask.GetAwaiter().GetResult()
                $Session.StderrTask = $null
                if ($null -eq $trailing) { $Session.StderrClosed = $true }
                elseif ($trailing) { $errors.Add($trailing) }
            }
            return [PSCustomObject]@{
                Code   = $code
                Output = $lines.ToArray()
                Errors = $errors.ToArray()
            }
        }
        $lines.Add($line)
    }
}

function Send-LScpCommand {
    <#
    .SYNOPSIS
        Sends one command line to the server of a session and returns its
        answer: Code (0 on success), Output (stdout lines) and Errors
        (stderr lines).
    .DESCRIPTION
        The values of a command are quoted by the cmdlets that build them;
        a caller of this function quotes its own with ConvertTo-LScpArgument.
        A command holding a newline is two commands and is refused.
    #>
    param(
        [Parameter(Mandatory=$true)]
        [PSCustomObject]$Session,
        [Parameter(Mandatory=$true)]
        [string]$Command,
        [int]$TimeoutSeconds = 0
    )
    if ($Command -match "[\r\n]") {
        throw "A LinSCP command must be a single line."
    }
    if ($null -eq $Session.Process -or $Session.Process.HasExited) {
        throw "The LinSCP session is not open."
    }
    $Session.Stdin.WriteLine($Command)
    $Session.Stdin.Flush()
    return Read-LScpResponse -Session $Session -TimeoutSeconds $TimeoutSeconds
}

function Stop-LScpProcess {
    param([PSCustomObject]$Session)
    try {
        if ($null -ne $Session.Process -and -not $Session.Process.HasExited) {
            $Session.Process.Kill()
            [void]$Session.Process.WaitForExit(2000)
        }
    } catch {}
    # The streams are disposed to release the pipes; the Process object is
    # not, because a caller checks whether the session ended by asking it
    # for HasExited, and a disposed Process answers that with an error that
    # PowerShell turns into $null.
    foreach ($stream in @($Session.Stdin, $Session.Stdout, $Session.Stderr)) {
        try { if ($null -ne $stream) { $stream.Dispose() } } catch {}
    }
    if ($Session.Id -and $Script:Sessions.ContainsKey($Session.Id)) {
        $Script:Sessions.Remove($Session.Id)
    }
}

function Format-LScpFailure {
    param([PSCustomObject]$Response, [string]$Default)
    $text = (@($Response.Errors) + @($Response.Output) | Where-Object { $_ }) -join "`n"
    if (-not $text.Trim()) { $text = $Default }
    return $text.Trim()
}

function Open-LScpSession {
    <#
    .SYNOPSIS
        Opens a persistent LinSCP session.
    .PARAMETER Url
        The session URL (sftp://user@host:port/path) or the name of a
        stored session.
    .PARAMETER Password
        Password for authentication. It is written to the client's stdin,
        never to its command line, so it does not appear in the process
        list; prefer -SecurePassword where the script has a SecureString.
    .PARAMETER SecurePassword
        The password as a SecureString.
    .PARAMETER HostKey
        Expected host key fingerprint ('*' accepts any key, for one
        connection only). Without it, the client verifies the key against
        its cache and refuses an unknown one, reporting the fingerprint.
    .PARAMETER PrivateKey
        Path to the private key file.
    .PARAMETER TimeoutSeconds
        How long to wait for the connection; 0 waits for the client's
        own timeout.
    .OUTPUTS
        A session object for use with other cmdlets.
    #>
    param(
        [Parameter(Mandatory=$true)]
        [string]$Url,
        [string]$Password,
        [securestring]$SecurePassword,
        [string]$HostKey,
        [string]$PrivateKey,
        [int]$TimeoutSeconds = 0
    )
    if ($SecurePassword) {
        $Password = [System.Net.NetworkCredential]::new('', $SecurePassword).Password
    }
    $psi = New-LScpProcessStartInfo -Arguments @("-server")
    $proc = [System.Diagnostics.Process]::Start($psi)

    $session = [PSCustomObject]@{
        Id           = [guid]::NewGuid().ToString()
        Url          = $Url
        Process      = $proc
        Stdin        = $proc.StandardInput
        Stdout       = $proc.StandardOutput
        Stderr       = $proc.StandardError
        StdoutTask   = $null
        StderrTask   = $null
        StderrClosed = $false
    }

    # Wait for the ready banner.
    $ready = $session.Stdout.ReadLine()
    if ($null -eq $ready -or $ready -notmatch "^LSCP-SERVER") {
        $detail = ""
        try { $detail = $session.Stderr.ReadToEnd().Trim() } catch {}
        Stop-LScpProcess -Session $session
        if ($detail) { throw "LinSCP server did not start correctly: $detail" }
        throw "LinSCP server did not start correctly."
    }

    # Build the open command with proper quoting so a URL or password
    # holding spaces, semicolons or quotes does not become a second
    # command when the server splits on quotes.
    $openCmd = "open $(ConvertTo-LScpArgument $Url)"
    if ($Password) { $openCmd += " -password=$(ConvertTo-LScpArgument $Password)" }
    if ($HostKey)  { $openCmd += " -hostkey=$(ConvertTo-LScpArgument $HostKey)" }
    if ($PrivateKey) { $openCmd += " -privatekey=$(ConvertTo-LScpArgument $PrivateKey)" }

    try {
        $response = Send-LScpCommand -Session $session -Command $openCmd -TimeoutSeconds $TimeoutSeconds
    } catch {
        Stop-LScpProcess -Session $session
        throw "Failed to open session: $($_.Exception.Message)"
    }
    if ($response.Code -ne 0) {
        Stop-LScpProcess -Session $session
        throw "Failed to open session: $(Format-LScpFailure $response 'the client refused the connection')"
    }
    # Confirmations cannot be answered through this pipe: an overwrite
    # the client would ask about is done, as in the graphical client.
    Send-LScpCommand -Session $session -Command "option confirm off" | Out-Null

    $Script:Sessions[$session.Id] = $session
    return $session
}

function Close-LScpSession {
    <#
    .SYNOPSIS
        Closes a LinSCP session and ends its server process.
    #>
    param(
        [Parameter(Mandatory=$true)]
        [PSCustomObject]$Session
    )
    try {
        if ($null -ne $Session.Process -and -not $Session.Process.HasExited) {
            Send-LScpCommand -Session $Session -Command "close" -TimeoutSeconds 30 | Out-Null
            # The server answers 'exit' with its marker before it goes:
            # read the answer so the pipes are drained, then wait for
            # the process itself. A dead server answers nothing, which
            # is already closed enough.
            try {
                Send-LScpCommand -Session $Session -Command "exit" -TimeoutSeconds 30 | Out-Null
            } catch {}
            if (-not $Session.Process.WaitForExit(5000)) {
                $Session.Process.Kill()
            }
        }
    } catch {
        try { $Session.Process.Kill() } catch {}
    } finally {
        Stop-LScpProcess -Session $Session
    }
}

function Get-LScpItem {
    <#
    .SYNOPSIS
        Downloads a file from the remote server.
    .OUTPUTS
        An object with Success, Output (the client's stdout lines) and
        Error (the diagnostic, when it failed).
    #>
    param(
        [Parameter(Mandatory=$true)]
        [PSCustomObject]$Session,
        [Parameter(Mandatory=$true)]
        [string]$RemotePath,
        [Parameter(Mandatory=$true)]
        [string]$LocalPath,
        [switch]$PreserveTime,
        [int]$TimeoutSeconds = 0
    )
    $cmd = "get"
    if ($PreserveTime) { $cmd += " -preservetime" }
    $cmd += " $(ConvertTo-LScpArgument $RemotePath) $(ConvertTo-LScpArgument $LocalPath)"
    $response = Send-LScpCommand -Session $Session -Command $cmd -TimeoutSeconds $TimeoutSeconds
    return [PSCustomObject]@{
        Success = ($response.Code -eq 0)
        Output  = $response.Output
        Error   = if ($response.Code -eq 0) { "" } else { Format-LScpFailure $response 'The download failed.' }
    }
}

function Send-LScpItem {
    <#
    .SYNOPSIS
        Uploads a file to the remote server.
    .OUTPUTS
        An object with Success, Output (the client's stdout lines) and
        Error (the diagnostic, when it failed).
    #>
    param(
        [Parameter(Mandatory=$true)]
        [PSCustomObject]$Session,
        [Parameter(Mandatory=$true)]
        [string]$LocalPath,
        [Parameter(Mandatory=$true)]
        [string]$RemotePath,
        [switch]$PreserveTime,
        [int]$TimeoutSeconds = 0
    )
    $cmd = "put"
    if ($PreserveTime) { $cmd += " -preservetime" }
    $cmd += " $(ConvertTo-LScpArgument $LocalPath) $(ConvertTo-LScpArgument $RemotePath)"
    $response = Send-LScpCommand -Session $Session -Command $cmd -TimeoutSeconds $TimeoutSeconds
    return [PSCustomObject]@{
        Success = ($response.Code -eq 0)
        Output  = $response.Output
        Error   = if ($response.Code -eq 0) { "" } else { Format-LScpFailure $response 'The upload failed.' }
    }
}

# A listing line in long format starts with a mode string: the file type,
# nine permission characters and perhaps an ACL or attribute marker. That,
# not its position, is what tells an entry from the status lines around
# it ('Reading directory /x...' and '3 entries').
$Script:ListingMode = '^[-a-zA-Z?][-rwxsStTlL]{9}[+@.]?$'

function ConvertFrom-LScpListing {
    <#
    .SYNOPSIS
        Turns the lines of 'ls' into objects, one per entry.
    #>
    param(
        [string[]]$Lines,
        [string]$Directory = ""
    )
    $entries = @()
    foreach ($line in $Lines) {
        $raw = $line -replace '[\r\n]+$', ''
        if (-not $raw.Trim()) { continue }
        if ($raw -notmatch '^\s*(\S+)\s+(\S+)\s+(\S+)\s+(\S+)\s+(\S+)\s+(\S+)\s+(\S+)\s+(\S+)\s(.*)$') {
            continue
        }
        # Every field has to be read before the mode is checked: a
        # -match/-notmatch that succeeds replaces $Matches with its own
        # result, so checking the mode first left the owner, the size and
        # the name empty and every entry came back without a name.
        $perms = $Matches[1]
        $owner = $Matches[3]
        $group = $Matches[4]
        $sizeText = $Matches[5]
        $modified = "$($Matches[6]) $($Matches[7]) $($Matches[8])"
        $name = $Matches[9]
        if ($perms -notmatch $Script:ListingMode) { continue }
        $target = ""
        $isLink = $perms.StartsWith("l")
        if ($isLink) {
            $arrow = $name.IndexOf(" -> ")
            if ($arrow -ge 0) {
                $target = $name.Substring($arrow + 4)
                $name = $name.Substring(0, $arrow)
            }
        }
        if ($name -eq "." -or $name -eq "..") { continue }
        $size = 0L
        [void][long]::TryParse($sizeText, [ref]$size)
        $fullName = if ($Directory) { $Directory.TrimEnd('/') + '/' + $name } else { $name }
        $entries += [PSCustomObject]@{
            Name        = $name
            FullName    = $fullName
            IsDirectory = $perms.StartsWith("d")
            IsLink      = $isLink
            LinkTarget  = $target
            Length      = $size
            Permissions = $perms
            Owner       = $owner
            Group       = $group
            Modified    = $modified
        }
    }
    return $entries
}

function Get-LScpDirectory {
    <#
    .SYNOPSIS
        Lists a remote directory.
    .OUTPUTS
        One object per entry: Name, FullName, IsDirectory, IsLink,
        LinkTarget, Length, Permissions, Owner, Group and Modified.
        A directory that cannot be read is a terminating error.
    #>
    param(
        [Parameter(Mandatory=$true)]
        [PSCustomObject]$Session,
        [string]$RemotePath,
        [int]$TimeoutSeconds = 0
    )
    $cmd = "ls -la"
    if ($RemotePath) { $cmd += " $(ConvertTo-LScpArgument $RemotePath)" }
    $response = Send-LScpCommand -Session $Session -Command $cmd -TimeoutSeconds $TimeoutSeconds
    if ($response.Code -ne 0) {
        throw (Format-LScpFailure $response 'The directory could not be listed.')
    }
    $directory = $RemotePath
    foreach ($line in $response.Output) {
        if ($line -match '^Reading directory (.*)\.\.\.$') { $directory = $Matches[1]; break }
    }
    return ConvertFrom-LScpListing -Lines $response.Output -Directory $directory
}

function Sync-LScpDirectory {
    <#
    .SYNOPSIS
        Synchronizes directories.
    .PARAMETER Direction
        'local' updates the local directory, 'remote' the remote one,
        'both' each from the other.
    .OUTPUTS
        An object with Success, Lines (the client's output) and Error.
    #>
    param(
        [Parameter(Mandatory=$true)]
        [PSCustomObject]$Session,
        [Parameter(Mandatory=$true)]
        [string]$Direction,
        [string]$LocalDir,
        [string]$RemoteDir,
        [switch]$Delete,
        [switch]$Preview,
        [int]$TimeoutSeconds = 0
    )
    if ($Direction -notin @('local','remote','both')) {
        throw "Direction must be local, remote or both."
    }
    if ($RemoteDir -and -not $LocalDir) {
        # The client reads the first directory as the local one, so a
        # remote directory on its own would have been taken for it.
        throw "A remote directory needs the local directory beside it."
    }
    $cmd = "synchronize $Direction"
    if ($LocalDir) { $cmd += " $(ConvertTo-LScpArgument $LocalDir)" }
    if ($RemoteDir) { $cmd += " $(ConvertTo-LScpArgument $RemoteDir)" }
    if ($Delete) { $cmd += " -delete" }
    if ($Preview) { $cmd += " -preview" }
    $response = Send-LScpCommand -Session $Session -Command $cmd -TimeoutSeconds $TimeoutSeconds
    return [PSCustomObject]@{
        Success = ($response.Code -eq 0)
        Lines   = $response.Output
        Error   = if ($response.Code -eq 0) { "" } else { Format-LScpFailure $response 'The synchronization failed.' }
    }
}

Export-ModuleMember -Function @(
    "Find-LinScpBinary",
    "ConvertTo-LScpArgument",
    "ConvertFrom-LScpListing",
    "Invoke-LinScp",
    "Send-LScpCommand",
    "Open-LScpSession",
    "Close-LScpSession",
    "Get-LScpItem",
    "Send-LScpItem",
    "Get-LScpDirectory",
    "Sync-LScpDirectory"
)
