# Quick-CTF-Test.ps1 - Run this to quickly test all applications
# This script runs the comprehensive testing and gives immediate results

Write-Host "=== CTF APPLICATION TESTING - QUICK START ===" -ForegroundColor Cyan
Write-Host ""

# Ensure Results directory exists
if (-not (Test-Path "Results")) {
    New-Item -ItemType Directory -Path "Results" -Force | Out-Null
}

Write-Host "Loading and executing application tests..." -ForegroundColor Blue

# Run the main testing script
try {
    . .\Test-AllApplications-CTF.ps1
    Write-Host "[SUCCESS] Base testing script loaded successfully" -ForegroundColor Green
    
    Write-Host ""
    Write-Host "Starting application testing..." -ForegroundColor Yellow
    
    # Execute the testing
    $results = Start-CTFApplicationTesting
    
    Write-Host ""
    Write-Host "=== QUICK SUMMARY FOR CTF ===" -ForegroundColor Cyan
    
    # Analyze which app has the most access
    $bestApp = $results.Applications | Sort-Object { $_.Summary.TotalSuccessfulCalls } -Descending | Select-Object -First 1
    
    Write-Host ""
    Write-Host "BEST APPLICATION FOR CTF: $($bestApp.Name)" -ForegroundColor Green
    Write-Host "  App ID: $($bestApp.AppId)" -ForegroundColor White
    Write-Host "  Total Accessible Endpoints: $($bestApp.Summary.TotalSuccessfulCalls)" -ForegroundColor White
    Write-Host "  Graph Token: $($bestApp.Summary.GraphTokenSuccess)" -ForegroundColor White
    Write-Host "  ARM Token: $($bestApp.Summary.ARMTokenSuccess)" -ForegroundColor White
    
    Write-Host ""
    Write-Host "ACCESSIBLE GRAPH ENDPOINTS:" -ForegroundColor Yellow
    $successfulGraph = $bestApp.GraphResults.Tests | Where-Object { $_.Success }
    foreach ($test in $successfulGraph) {
        Write-Host "  [SUCCESS] $($test.Name) - $($test.DataCount) items" -ForegroundColor Green
    }
    
    Write-Host ""
    Write-Host "ACCESSIBLE ARM ENDPOINTS:" -ForegroundColor Yellow
    $successfulARM = $bestApp.ARMResults.Tests | Where-Object { $_.Success }
    foreach ($test in $successfulARM) {
        Write-Host "  [SUCCESS] $($test.Name) - $($test.DataCount) items" -ForegroundColor Green
    }
    
    # Check for high-value access
    Write-Host ""
    Write-Host "HIGH-VALUE ACCESS DETECTED:" -ForegroundColor Red
    
    foreach ($app in $results.Applications) {
        if ($app.GraphResults) {
            $highValue = $app.GraphResults.Tests | Where-Object { 
                $_.Success -and ($_.Name -in @("Applications", "ServicePrincipals", "OAuth2PermissionGrants", "AppRoleAssignments")) 
            }
            if ($highValue) {
                Write-Host "  [WARNING] $($app.Name): $($highValue.Name -join ', ')" -ForegroundColor Red
            }
        }
    }
    
    # Generate tokens for manual use
    Write-Host ""
    Write-Host "=== TOKEN GENERATION FOR MANUAL USE ===" -ForegroundColor Magenta
    
    foreach ($app in $results.Applications) {
        if ($app.Tokens.Graph.Success -or $app.Tokens.ARM.Success) {
            Write-Host ""
            Write-Host "Application: $($app.Name)" -ForegroundColor Yellow
            
            if ($app.Tokens.Graph.Success) {
                Write-Host "  Graph Token (copy for manual use):" -ForegroundColor Green
                Write-Host "  `$graphToken = `"$($app.Tokens.Graph.Token)`"" -ForegroundColor Gray
            }
            
            if ($app.Tokens.ARM.Success) {
                Write-Host "  ARM Token (copy for manual use):" -ForegroundColor Green  
                Write-Host "  `$armToken = `"$($app.Tokens.ARM.Token)`"" -ForegroundColor Gray
            }
        }
    }
    
    Write-Host ""
    Write-Host "=== NEXT STEPS FOR CTF ===" -ForegroundColor Yellow
    Write-Host "1. Use the tokens above in your existing Enum-AzureARM script:" -ForegroundColor White
    Write-Host "   .\Enum-AzureARM.ps1 -AccessTokenARM `$armToken -AccessTokenGraph `$graphToken -AccountId 'servicepricipal'" -ForegroundColor Cyan
    Write-Host ""
    Write-Host "2. Focus on applications with high-value access (Applications, ServicePrincipals)" -ForegroundColor White
    Write-Host ""
    Write-Host "3. Check storage account 'examplestorage' for blueprint files" -ForegroundColor White
    Write-Host ""
    Write-Host "4. Examine Key Vault 'examplekeyvault' for additional credentials" -ForegroundColor White
    Write-Host ""
    Write-Host "5. Look for Azure Blueprints and blueprint assignments" -ForegroundColor White
    Write-Host ""
    Write-Host "6. Look for privilege escalation through application modifications" -ForegroundColor White
    
    # Check for blueprint-specific findings
    Write-Host ""
    Write-Host "=== BLUEPRINT-SPECIFIC ANALYSIS ===" -ForegroundColor Magenta
    
    foreach ($app in $results.Applications) {
        if ($app.BlueprintResults) {
            Write-Host ""
            Write-Host "Blueprint findings for $($app.Name):" -ForegroundColor Yellow
            
            if ($app.BlueprintResults.Blueprints -and $app.BlueprintResults.Blueprints.Count -gt 0) {
                Write-Host "  [SUCCESS] Found $($app.BlueprintResults.Blueprints.Count) Azure Blueprints" -ForegroundColor Green
                foreach ($blueprint in $app.BlueprintResults.Blueprints) {
                    Write-Host "    - $($blueprint.name): $($blueprint.status)" -ForegroundColor White
                }
            }
            
            if ($app.BlueprintResults.Assignments -and $app.BlueprintResults.Assignments.Count -gt 0) {
                Write-Host "  [SUCCESS] Found $($app.BlueprintResults.Assignments.Count) Blueprint Assignments" -ForegroundColor Green
                foreach ($assignment in $app.BlueprintResults.Assignments) {
                    Write-Host "    - Assignment: $($assignment.name)" -ForegroundColor White
                }
            }
            
            if ($app.BlueprintResults.StorageFiles -and $app.BlueprintResults.StorageFiles.Count -gt 0) {
                Write-Host "  [SUCCESS] Found $($app.BlueprintResults.StorageFiles.Count) Blueprint Files in Storage" -ForegroundColor Green
                foreach ($file in $app.BlueprintResults.StorageFiles) {
                    Write-Host "    - Downloaded: $($file.LocalPath)" -ForegroundColor Cyan
                }
            }
        }
    }
    
    # Store in global variable for easy access
    $Global:CTFQuickResults = $results
    Write-Host ""
    Write-Host "[SUCCESS] Results stored in `$Global:CTFQuickResults for further analysis" -ForegroundColor Green
    
} catch {
    Write-Error "Failed to execute testing: $($_.Exception.Message)"
    Write-Error $_.ScriptStackTrace
}