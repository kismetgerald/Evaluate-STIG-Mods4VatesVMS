#!/usr/bin/env pwsh
# Script to move WebSRG-specific documentation to XO_v5.x_WebSRG subfolder
# Created: February 9, 2026

$sourceDir = "d:\Dropbox\IT Docs\Scripts\VatesVMS-Evaluate-STIG\v1.2507.6_Mod4VatesVMS_OpenCode\.Mods_by_Kismet\Docs"
$destDir = "d:\Dropbox\IT Docs\Scripts\VatesVMS-Evaluate-STIG\v1.2507.6_Mod4VatesVMS_OpenCode\.Mods_by_Kismet\Docs\XO_v5.x_WebSRG"

Write-Host "=" * 80 -ForegroundColor Cyan
Write-Host "WebSRG Documentation Organization Script" -ForegroundColor Cyan
Write-Host "=" * 80 -ForegroundColor Cyan
Write-Host ""
Write-Host "Moving WebSRG-specific documentation files..." -ForegroundColor Yellow
Write-Host "Source: $sourceDir" -ForegroundColor Gray
Write-Host "Destination: $destDir" -ForegroundColor Gray
Write-Host ""

# Define WebSRG-specific files to move
$websrgFiles = @(
    # Session summaries (Sessions 16-34 are all WebSRG-related)
    "SESSION_16_SUMMARY.md",
    "SESSION_17_SUMMARY.md",
    "SESSION_18_IMPLEMENTATION_SUMMARY.md",
    "SESSION_18_SUMMARY.md",
    "SESSION_18_TEST100_RESULTS.md",
    "SESSION_18_TEST99_RESULTS.md",
    "SESSION_19_SUMMARY.md",
    "SESSION_20_SUMMARY.md",
    "SESSION_21_PHASE1_COMPLETE.md",
    "SESSION_21_PHASE1_TARGETED.md",
    "SESSION_21_QA_ANALYSIS.md",
    "SESSION_21_SUMMARY.md",
    "SESSION_22_SUMMARY.md",
    "SESSION_23_SUMMARY.md",
    "SESSION_24_SUMMARY.md",
    "SESSION_25_BATCH1_SUMMARY.md",
    "SESSION_25_BATCH2_SUMMARY.md",
    "SESSION_25_SUMMARY.md",
    "SESSION_26_SUMMARY.md",
    "SESSION_27_SUMMARY.md",
    "SESSION_28_FINAL_VERIFICATION.md",
    "SESSION_28_IMPLEMENTATION_DETAILS.md",
    "SESSION_28_PHASE1_IMPLEMENTATION.md",
    "SESSION_28_SUMMARY.md",
    "SESSION_29_ANSWER_FILE_ENTRIES.xml",
    "SESSION_29_MD5_HASHES.csv",
    "SESSION_29_SUMMARY.md",
    "SESSION_30_ANSWER_FILE_INTEGRATION.md",
    "SESSION_30_COMPLETION.md",
    "SESSION_30_SUMMARY.md",
    "SESSION_30_V206427_IMPLEMENTATION.md",
    "SESSION_31_COMPLETION.md",
    "SESSION_31_IMPLEMENTATION_PLAN.md",
    "SESSION_31_PHASE1_IMPLEMENTATION_SUMMARY.md",
    "SESSION_31_PHASE1_TESTING_GUIDE.md",
    "SESSION_31_SUMMARY.md",
    "SESSION_32_BATCH1_ANSWER_FILE_COMPLETE.md",
    "SESSION_32_BATCH1_ANSWER_FILE_XML_FIX.md",
    "SESSION_32_BATCH1_COMPLETE.md",
    "SESSION_32_BATCH1_COMPLETE_VALIDATED.md",
    "SESSION_32_BATCH1_COMPLETION_STATUS.md",
    "SESSION_32_BATCH1_IMPLEMENTATION.md",
    "SESSION_32_BATCH1_IMPLEMENTATION_SUMMARY.md",
    "SESSION_32_BATCH1_IMPLEMENTATIONS.md",
    "SESSION_32_BATCH1_INTEGRATION_SUMMARY.md",
    "SESSION_32_BATCH2_COMPLETE.md",
    "SESSION_32_BATCH2_TEST113C_READY.md",
    "SESSION_32_BATCH2_TEST113D_READY.md",
    "SESSION_32_BATCH3B_COMPLETE.md",
    "SESSION_32_IMPLEMENTATION_PLAN.md",
    "SESSION_32_SUMMARY.md",
    "SESSION_33_SUMMARY.md",
    "SESSION_34_SUMMARY.md",
    "SESSION_34_V264347_PERFORMANCE_FIX.md",

    # Individual function implementation docs
    "V206367_ANSWER_FILE_FIX.md",
    "V206367_API_INTEGRATION.md",
    "V206367_FIXES_NEEDED.md",
    "V206386_IMPLEMENTATION_SUMMARY.md",
    "V206396_IMPLEMENTATION_SUMMARY.md",
    "V206397_IMPLEMENTATION_SUMMARY.md",
    "V206428_IMPLEMENTATION_SUMMARY.md",
    "V-206430_IMPLEMENTATION_COMPLETE.md",
    "V206432_IMPLEMENTATION_SUMMARY.md",
    "V206432-INTEGRATION-INSTRUCTIONS.md",
    "V206433_IMPLEMENTATION_SUMMARY.md",
    "V206443_IMPLEMENTATION_SUMMARY.md",
    "V264340_IMPLEMENTATION_SUMMARY.md",
    "V264343-implementation.txt",
    "V264344-IMPLEMENTATION-SUMMARY.md",
    "V264356_IMPLEMENTATION_SUMMARY.md",

    # WebSRG-specific planning and analysis
    "WEBSRG_REMAINING_53_ANALYSIS.md",
    "WEBSRG_REMAINING_53_TITLES.txt",
    "WEBSRG_REMAINING_QUICK_REFERENCE.md",

    # WebSRG implementation guides and trackers
    "XO_WebSRG_CAT1_CheckContent.md",
    "XO_WebSRG_HelperFunctions.ps1",
    "XO_WebSRG_IMPLEMENTATION_GUIDE_CAT_II.md",
    "XO_WebSRG_IMPLEMENTATION_TRACKER_CAT_I.md",
    "XO_WebSRG_IMPLEMENTATION_TRACKER_CAT_II.md",

    # Session 32 batch 1 answer file
    "answer_file_entries_session32_batch1.xml",

    # Batch 3b research (WebSRG-related)
    "batch3b_research.md"
)

$movedCount = 0
$skipCount = 0
$errorCount = 0

foreach ($file in $websrgFiles) {
    $sourcePath = Join-Path $sourceDir $file
    $destPath = Join-Path $destDir $file

    if (-not (Test-Path $sourcePath)) {
        Write-Host "  [SKIP] $file - File not found" -ForegroundColor Yellow
        $skipCount++
        continue
    }

    try {
        Move-Item -Path $sourcePath -Destination $destPath -Force
        Write-Host "  [MOVED] $file" -ForegroundColor Green
        $movedCount++
    }
    catch {
        Write-Host "  [ERROR] $file - $($_.Exception.Message)" -ForegroundColor Red
        $errorCount++
    }
}

Write-Host ""
Write-Host "=" * 80 -ForegroundColor Cyan
Write-Host "Move Summary" -ForegroundColor Cyan
Write-Host "=" * 80 -ForegroundColor Cyan
Write-Host "  Total files processed: $($websrgFiles.Count)" -ForegroundColor White
Write-Host "  Files moved: $movedCount" -ForegroundColor Green
Write-Host "  Files skipped (not found): $skipCount" -ForegroundColor Yellow
Write-Host "  Errors: $errorCount" -ForegroundColor $(if ($errorCount -gt 0) { "Red" } else { "Green" })
Write-Host ""

if ($movedCount -gt 0) {
    Write-Host "WebSRG documentation successfully organized!" -ForegroundColor Green
    Write-Host "All WebSRG-specific files are now in:" -ForegroundColor Cyan
    Write-Host "  $destDir" -ForegroundColor Gray
}

Write-Host ""
Write-Host "FILES KEPT IN MAIN DOCS (Project-wide scope):" -ForegroundColor Cyan
Write-Host "  - CLAUDE.md (project instructions)" -ForegroundColor Gray
Write-Host "  - STATUS.md (overall project status)" -ForegroundColor Gray
Write-Host "  - PROJECT_SUMMARY.md (overall summary)" -ForegroundColor Gray
Write-Host "  - MODIFICATIONS.md (all upstream changes)" -ForegroundColor Gray
Write-Host "  - VATES_COMPLIANCE_BLOCKERS.md (all modules)" -ForegroundColor Gray
Write-Host "  - XCP-ng_* files (different module)" -ForegroundColor Gray
Write-Host "  - XO_ASD_* files (different module)" -ForegroundColor Gray
Write-Host "  - XO_MODULES_* files (multi-module planning)" -ForegroundColor Gray
Write-Host "  - All other non-WebSRG specific files" -ForegroundColor Gray
