#Requires -Module Pester
<#
.SYNOPSIS
    Pester tests for the Import-RoutePlan function in scripts/windows/run-scan.ps1.

.DESCRIPTION
    Covers: no-op when proxy already set, missing plan, loading from env file,
    blank/comment line skipping, -RunDoctor triggering route-doctor when plan is
    missing or stale, -RunDoctor skipping when plan is fresh.

.NOTES
    Run from the repo root:
        Invoke-Pester tests/pester/Import-RoutePlan.Tests.ps1 -Output Detailed
#>

BeforeAll {
    # Load only function definitions from run-scan.ps1 using the PowerShell AST
    # so the main script body (docker calls, scan pipeline, mandatory $Target param)
    # is never executed.
    $scriptPath = Join-Path $PSScriptRoot '..\..\scripts\windows\run-scan.ps1'
    $parseErrors = $null
    $tokens = $null
    $ast = [System.Management.Automation.Language.Parser]::ParseFile(
        $scriptPath, [ref]$tokens, [ref]$parseErrors
    )
    if ($parseErrors) {
        throw "Parse errors in run-scan.ps1: $($parseErrors -join '; ')"
    }
    $funcDefs = $ast.FindAll(
        { param($node) $node -is [System.Management.Automation.Language.FunctionDefinitionAst] },
        $false
    )
    foreach ($func in $funcDefs) {
        Invoke-Expression $func.Extent.Text
    }
}

Describe 'Import-RoutePlan' {
    BeforeEach {
        # Isolate each test: clear proxy vars that the function reads/sets.
        Remove-Item Env:HTTP_PROXY  -ErrorAction SilentlyContinue
        Remove-Item Env:ALL_PROXY   -ErrorAction SilentlyContinue
        Remove-Item Env:HTTPS_PROXY -ErrorAction SilentlyContinue
    }

    AfterEach {
        Remove-Item Env:HTTP_PROXY  -ErrorAction SilentlyContinue
        Remove-Item Env:ALL_PROXY   -ErrorAction SilentlyContinue
        Remove-Item Env:HTTPS_PROXY -ErrorAction SilentlyContinue
    }

    Context 'No-op when proxy already configured' {
        It 'skips loading when HTTP_PROXY is already set' {
            $env:HTTP_PROXY = 'http://existing:8080'
            # Call without a planFile present so we can verify no side effects
            Push-Location (Join-Path $TestDrive 'noproxy')
            New-Item -ItemType Directory -Force -Path (Join-Path $TestDrive 'noproxy') | Out-Null
            { Import-RoutePlan } | Should -Not -Throw
            Pop-Location
            # Value must remain unchanged (function returned early)
            $env:HTTP_PROXY | Should -Be 'http://existing:8080'
        }

        It 'skips loading when ALL_PROXY is already set' {
            $env:ALL_PROXY = 'socks5h://existing:1080'
            Push-Location (Join-Path $TestDrive 'noproxy2')
            New-Item -ItemType Directory -Force -Path (Join-Path $TestDrive 'noproxy2') | Out-Null
            { Import-RoutePlan } | Should -Not -Throw
            Pop-Location
            $env:ALL_PROXY | Should -Be 'socks5h://existing:1080'
        }
    }

    Context 'Missing route-plan.env' {
        It 'proceeds without error when route-plan.env does not exist' {
            $dir = Join-Path $TestDrive 'nofile'
            New-Item -ItemType Directory -Force -Path $dir | Out-Null
            Push-Location $dir
            { Import-RoutePlan } | Should -Not -Throw
            Pop-Location
            # No proxy vars should have been set
            $env:HTTP_PROXY | Should -BeNullOrEmpty
            $env:ALL_PROXY  | Should -BeNullOrEmpty
        }
    }

    Context 'Loading from route-plan.env' {
        BeforeEach {
            $dir = Join-Path $TestDrive 'withplan'
            New-Item -ItemType Directory -Force -Path $dir | Out-Null
            $artifactsDir = Join-Path $dir 'artifacts'
            New-Item -ItemType Directory -Force -Path $artifactsDir | Out-Null
            $script:planFile = Join-Path $artifactsDir 'route-plan.env'
            $script:workDir  = $dir
        }

        It 'loads HTTP_PROXY from plan file' {
            Set-Content $script:planFile 'HTTP_PROXY=http://proxy.corp:3128'
            Push-Location $script:workDir
            Import-RoutePlan
            Pop-Location
            $env:HTTP_PROXY | Should -Be 'http://proxy.corp:3128'
        }

        It 'loads ALL_PROXY from plan file' {
            Set-Content $script:planFile 'ALL_PROXY=socks5h://socks.corp:1080'
            Push-Location $script:workDir
            Import-RoutePlan
            Pop-Location
            $env:ALL_PROXY | Should -Be 'socks5h://socks.corp:1080'
        }

        It 'loads multiple vars and ignores blank lines and comments' {
            @(
                '# this is a comment',
                '',
                'HTTP_PROXY=http://proxy.corp:3128',
                '  ',
                'ALL_PROXY=socks5h://socks.corp:1080',
                '# another comment'
            ) | Set-Content $script:planFile
            Push-Location $script:workDir
            Import-RoutePlan
            Pop-Location
            $env:HTTP_PROXY | Should -Be 'http://proxy.corp:3128'
            $env:ALL_PROXY  | Should -Be 'socks5h://socks.corp:1080'
        }

        It 'handles values containing = signs (splits on first = only)' {
            Set-Content $script:planFile 'HTTP_PROXY=http://user:pass=special@proxy:3128'
            Push-Location $script:workDir
            Import-RoutePlan
            Pop-Location
            $env:HTTP_PROXY | Should -Be 'http://user:pass=special@proxy:3128'
        }
    }

    Context '-RunDoctor behaviour' {
        BeforeEach {
            $dir = Join-Path $TestDrive ('doctor-' + [System.Guid]::NewGuid().ToString('N').Substring(0,6))
            New-Item -ItemType Directory -Force -Path $dir | Out-Null
            $artifactsDir = Join-Path $dir 'artifacts'
            New-Item -ItemType Directory -Force -Path $artifactsDir | Out-Null
            $script:workDir      = $dir
            $script:artifactsDir = $artifactsDir
        }

        It 'runs route-doctor when -RunDoctor and plan file is missing' {
            # No plan file → needDoctor = true
            $script:dockerArgs = [System.Collections.Generic.List[string]]::new()
            Mock docker {
                $script:dockerArgs.Add(($args -join ' '))
            }

            Push-Location $script:workDir
            Import-RoutePlan -RunDoctor -MaxAgeMinutes 30
            Pop-Location

            # At least one docker call should mention route-doctor
            ($script:dockerArgs | Where-Object { $_ -match 'route-doctor' }).Count |
                Should -BeGreaterThan 0
        }

        It 'skips route-doctor when -RunDoctor but plan is fresh' {
            # Create a fresh plan (just now)
            $planFile = Join-Path $script:artifactsDir 'route-plan.env'
            Set-Content $planFile 'HTTP_PROXY=http://fresh:3128'

            $script:dockerCalled = $false
            Mock docker { $script:dockerCalled = $true }

            Push-Location $script:workDir
            Import-RoutePlan -RunDoctor -MaxAgeMinutes 30
            Pop-Location

            $script:dockerCalled | Should -BeFalse
            $env:HTTP_PROXY | Should -Be 'http://fresh:3128'
        }

        It 'runs route-doctor when -RunDoctor and plan is stale' {
            $planFile = Join-Path $script:artifactsDir 'route-plan.env'
            Set-Content $planFile 'HTTP_PROXY=http://stale:3128'
            # Back-date to 2 hours ago
            (Get-Item $planFile).LastWriteTime = (Get-Date).AddHours(-2)

            $script:dockerCalled = $false
            Mock docker { $script:dockerCalled = $true }

            Push-Location $script:workDir
            Import-RoutePlan -RunDoctor -MaxAgeMinutes 30
            Pop-Location

            $script:dockerCalled | Should -BeTrue
        }

        It 'does not run route-doctor without -RunDoctor even if plan is missing' {
            # No plan file, but -RunDoctor not passed
            $script:dockerCalled = $false
            Mock docker { $script:dockerCalled = $true }

            Push-Location $script:workDir
            Import-RoutePlan   # no -RunDoctor
            Pop-Location

            $script:dockerCalled | Should -BeFalse
        }
    }
}
