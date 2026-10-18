# Pester tests for the LinSCP PowerShell module (automation/LinSCP.psm1).
#
# Run through automation/test_psmodule.py, which starts the throwaway
# WebDAV endpoint, points PATH at the linscp binary under test and sets
# the LSCP_TEST_* variables below. Without pwsh the harness skips the
# live cases loudly instead of passing quietly.
#
# What is covered here is the acceptance list of the automation
# capability: a session opened and closed, an upload and a download of
# exact bytes, a listing as pipeline objects, a terminating error, a
# cancelled transfer, and a password that appears neither in the
# process list nor in the output. The quoting and listing parsers get
# their own server-free cases, including the hostile names.
BeforeAll {
    Import-Module (Join-Path $PSScriptRoot 'LinSCP.psm1') -Force
    $script:BinDir = Split-Path $env:LSCP_TEST_BINARY -Parent
    $env:PATH = $script:BinDir + [System.IO.Path]::PathSeparator + $env:PATH
    $script:BaseUrl = $env:LSCP_TEST_URL_BASE
    $script:User = $env:LSCP_TEST_USER
    $script:Password = $env:LSCP_TEST_PASSWORD
    $script:Root = $env:LSCP_TEST_ROOT
}

Describe 'Quoting for the client command splitter' {
    It 'leaves a plain word alone' {
        ConvertTo-LScpArgument 'plain' | Should -Be 'plain'
    }

    It 'quotes blanks, quotes, semicolons and backslashes' {
        ConvertTo-LScpArgument 'with space' | Should -Be '"with space"'
        ConvertTo-LScpArgument 'semi;colon' | Should -Be '"semi;colon"'
        ConvertTo-LScpArgument 'quote"name' | Should -Be '"quote\"name"'
        ConvertTo-LScpArgument 'a\b' | Should -Be '"a\\b"'
    }

    It 'refuses a control character rather than quoting it' {
        { ConvertTo-LScpArgument "a`nrm -r /" } | Should -Throw
        { ConvertTo-LScpArgument "tab`there" } | Should -Throw
    }
}

Describe 'Listing parser' {
    It 'turns long lines into objects and skips status lines' {
        $lines = @(
            'Reading directory /data...',
            '-rw-r--r-- 1 owner group 22 Oct 13 07:07 keep.txt',
            'drwxr-xr-x 1 owner group 60 Oct 13 07:08 testdir',
            '3 entries'
        )
        $entries = ConvertFrom-LScpListing -Lines $lines -Directory '/data'
        $entries.Count | Should -Be 2
        $entries[0].Name | Should -Be 'keep.txt'
        $entries[0].FullName | Should -Be '/data/keep.txt'
        $entries[0].Length | Should -Be 22
        $entries[0].IsDirectory | Should -Be $false
        $entries[1].IsDirectory | Should -Be $true
    }

    It 'reads link targets and skips dot entries' {
        $lines = @(
            'lrwxrwxrwx 1 o g 7 Oct 13 07:07 link -> target',
            '-rw-r--r-- 1 o g 1 Oct 13 07:07 .',
            '-rw-r--r-- 1 o g 1 Oct 13 07:07 ..'
        )
        $entries = ConvertFrom-LScpListing -Lines $lines
        $entries.Count | Should -Be 1
        $entries[0].IsLink | Should -Be $true
        $entries[0].LinkTarget | Should -Be 'target'
    }
}

Describe 'Session lifetime' {
    It 'opens and closes a session' {
        $session = Open-LScpSession -Url "$script:BaseUrl" `
            -Password $script:Password -HostKey '*'
        try {
            $session.Id | Should -Not -BeNullOrEmpty
            $session.Process.HasExited | Should -Be $false
        } finally {
            Close-LScpSession -Session $session
        }
        $session.Process.HasExited | Should -Be $true
    }

    It 'refuses a wrong password with a terminating error' {
        { Open-LScpSession -Url "$script:BaseUrl" `
                -Password 'not-the-password' -HostKey '*' } | Should -Throw
    }
}

Describe 'Transfers carry exact bytes' {
    BeforeAll {
        $script:Payload = [byte[]](0..255 + 0..255)
        $script:LocalSrc = Join-Path $script:Root 'ps-upload.bin'
        [System.IO.File]::WriteAllBytes($script:LocalSrc, $script:Payload)
        $script:LocalDst = Join-Path $script:Root 'ps-download.bin'
    }

    It 'uploads and downloads byte-exact content' {
        $session = Open-LScpSession -Url "$script:BaseUrl" `
            -Password $script:Password -HostKey '*'
        try {
            $up = Send-LScpItem -Session $session -LocalPath $script:LocalSrc `
                -RemotePath '/ps-roundtrip.bin'
            $up.Success | Should -Be $true
            if (Test-Path $script:LocalDst) { Remove-Item $script:LocalDst -Force }
            $down = Get-LScpItem -Session $session -RemotePath '/ps-roundtrip.bin' `
                -LocalPath $script:LocalDst
            $down.Success | Should -Be $true
            $back = [System.IO.File]::ReadAllBytes($script:LocalDst)
            [System.Convert]::ToBase64String($back) | Should -Be `
                ([System.Convert]::ToBase64String($script:Payload))
        } finally {
            Close-LScpSession -Session $session
        }
    }

    It 'reports a missing file without throwing' {
        $session = Open-LScpSession -Url "$script:BaseUrl" `
            -Password $script:Password -HostKey '*'
        try {
            $result = Get-LScpItem -Session $session -RemotePath '/no-such-ps-file' `
                -LocalPath (Join-Path $script:Root 'ps-missing.bin')
            $result.Success | Should -Be $false
            $result.Error | Should -Not -BeNullOrEmpty
        } finally {
            Close-LScpSession -Session $session
        }
    }
}

Describe 'Directory listing as pipeline objects' {
    It 'lists entries with names, sizes and kinds' {
        $session = Open-LScpSession -Url "$script:BaseUrl" `
            -Password $script:Password -HostKey '*'
        try {
            $entries = Get-LScpDirectory -Session $session -RemotePath '/'
            ($entries | Where-Object { $_.Name -eq 'ps-roundtrip.bin' }).Count | Should -Be 1
            $file = $entries | Where-Object { $_.Name -eq 'ps-roundtrip.bin' } | Select-Object -First 1
            $file.Length | Should -Be 512
            $file.IsDirectory | Should -Be $false
            $file.FullName | Should -Be '/ps-roundtrip.bin'
        } finally {
            Close-LScpSession -Session $session
        }
    }

    It 'is a terminating error when the directory cannot be read' {
        $session = Open-LScpSession -Url "$script:BaseUrl" `
            -Password $script:Password -HostKey '*'
        try {
            { Get-LScpDirectory -Session $session -RemotePath '/no-such-ps-dir' } | Should -Throw
        } finally {
            Close-LScpSession -Session $session
        }
    }
}

Describe 'Cancellation' {
    It 'abandons a connection that never answers' {
        # 192.0.2.0/24 is TEST-NET-1: routed nowhere, so the client waits
        # for its own timeout while this cmdlet stops waiting first.
        { Open-LScpSession -Url 'dav://nobody@192.0.2.1/' `
                -Password 'x' -HostKey '*' -TimeoutSeconds 3 } | Should -Throw '*did not answer*'
    }
}

Describe 'Secret handling' {
    It 'keeps the password out of the process list and the output' {
        $session = Open-LScpSession -Url "$script:BaseUrl" `
            -Password $script:Password -HostKey '*'
        try {
            $pattern = [regex]::Escape($script:Password)
            $session.Url | Should -Not -Match $pattern
            ($session | Out-String) | Should -Not -Match $pattern
            $entries = Get-LScpDirectory -Session $session -RemotePath '/'
            ($entries | Out-String) | Should -Not -Match $pattern
            $ps = & ps -ef | Out-String
            $ps | Should -Not -Match $pattern
        } finally {
            Close-LScpSession -Session $session
        }
    }
}
