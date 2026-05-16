@{
    # PSScriptAnalyzer settings for scripts/windows/*.ps1.
    # CI invokes:  Invoke-ScriptAnalyzer -Path ./scripts/windows -Recurse -Settings ./PSScriptAnalyzerSettings.psd1
    #
    # Locally:     pwsh -c "Invoke-ScriptAnalyzer -Path ./scripts/windows -Recurse -Settings ./PSScriptAnalyzerSettings.psd1"

    Severity     = @('Error', 'Warning')

    # Rules we explicitly opt into.  Default list plus a few hygiene rules.
    IncludeRules = @(
        'PSAvoidUsingCmdletAliases',
        'PSAvoidUsingPositionalParameters',
        'PSReservedCmdletChar',
        'PSReservedParams',
        'PSUseDeclaredVarsMoreThanAssignments',
        'PSAvoidGlobalVars',
        'PSAvoidDefaultValueSwitchParameter',
        'PSPossibleIncorrectComparisonWithNull',
        'PSUseConsistentIndentation',
        'PSUseConsistentWhitespace',
        'PSAlignAssignmentStatement'
    )

    ExcludeRules = @(
        # Write-Host is intentional: these scripts emit human progress logs
        # to the console, NOT structured pipeline output.
        'PSAvoidUsingWriteHost',
        # We accept positional Add-MpPreference / Set-MpPreference calls.
        'PSAvoidUsingPlainTextForPassword'
    )

    Rules = @{
        PSUseConsistentIndentation = @{
            Enable          = $true
            IndentationSize = 2
            Kind            = 'space'
        }
        PSUseConsistentWhitespace = @{
            Enable          = $true
            CheckOpenBrace  = $true
            CheckOpenParen  = $true
            CheckOperator   = $true
            CheckSeparator  = $true
        }
    }
}
