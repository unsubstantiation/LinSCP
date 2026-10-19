# Runs the Pester suite and writes NUnit results, on Pester 4 or 5.
#
# automation/test_psmodule.py invokes this script instead of building an
# Invoke-Pester command line, because the two Pester generations take
# different parameters: Pester 4 takes -OutputFormat/-OutputFile, Pester 5
# takes a configuration object and rejects the legacy switches. The
# version that is installed decides which shape is used, so neither
# generation can silently run zero tests and still look green: the
# python harness reads the NUnit counts and refuses a run with none.
#
# Exit code: 0 when every test passed, 1 when any failed or Pester did
# not run at all.
[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)][string]$TestPath,
    [Parameter(Mandatory = $true)][string]$ResultsPath
)

$ErrorActionPreference = 'Stop'

$pester = Get-Module -ListAvailable Pester |
    Sort-Object Version -Descending | Select-Object -First 1
if ($null -eq $pester) {
    Write-Error 'Pester is not installed; the live PowerShell tests cannot run.'
    exit 1
}
Import-Module Pester -RequiredVersion $pester.Version

if ($pester.Version.Major -ge 5) {
    $configuration = New-PesterConfiguration
    $configuration.Run.Path = $TestPath
    $configuration.Run.PassThru = $true
    $configuration.Output.Verbosity = 'Detailed'
    $configuration.TestResult.Enabled = $true
    $configuration.TestResult.OutputPath = $ResultsPath
    $configuration.TestResult.OutputFormat = 'NUnitXml'
    $result = Invoke-Pester -Configuration $configuration
} else {
    $result = Invoke-Pester -Path $TestPath -OutputFormat NUnitXml `
        -OutputFile $ResultsPath -PassThru
}

if ($null -eq $result -or ($result.TotalCount -eq 0 -and $result.TestCount -eq 0)) {
    Write-Error 'Pester ran no tests.'
    exit 1
}
if ($result.FailedCount -gt 0) {
    exit 1
}
exit 0
