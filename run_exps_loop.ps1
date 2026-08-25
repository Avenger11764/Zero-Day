# Headless loop for deep/detection-work — runs until stopped.
# Usage:  .\run_exps_loop.ps1            # full files, 4 seeds
#         .\run_exps_loop.ps1 -Smoke     # quick smoke (limit 150k, seed 0) for verification
param([switch]$Smoke)

$ErrorActionPreference = "Stop"
$ROOT = $PSScriptRoot
Set-Location $ROOT
# Ensure venv? Assume current python has torch+pyg
$PYTHON = "python"

# Determinism flags (gotcha #24)
$env:CUBLAS_WORKSPACE_CONFIG = ":4096:8"

function Run-Step {
    param([string]$Name, [string]$Cmd)
    Write-Host "`n$('='*70)`n$Name`n$('='*70)" -ForegroundColor Cyan
    Write-Host $Cmd -ForegroundColor DarkGray
    $ts = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    "$ts | $Name | $Cmd" | Out-File -Append -FilePath "experiments\loop.log"
    Invoke-Expression $Cmd
    if ($LASTEXITCODE -ne 0) {
        Write-Host "FAILED ($LASTEXITCODE): $Name" -ForegroundColor Red
        "$ts | FAILED $Name $LASTEXITCODE" | Out-File -Append -FilePath "experiments\loop.log"
    } else {
        Write-Host "DONE: $Name" -ForegroundColor Green
    }
}

# Clean log start
"Loop started $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss') Smoke=$Smoke Device=$((& $PYTHON -c 'import torch; print(torch.cuda.get_device_name(0) if torch.cuda.is_available() else \"cpu\")')) Torch=$((& $PYTHON -c 'import torch; print(torch.__version__)'))" | Out-File -Append -FilePath "experiments\loop.log"

if ($Smoke) {
    # Quick verification — one seed, limited rows, 60s — reproduces gap before fixes
    Run-Step "SMOKE Exp1 ensemble (T5, v1, plain→log baseline)" "$PYTHON detection\exp_gnn_fused_ensemble.py --limit 150000 --window 60 --seq-len 5 --feature-set v1 --epochs 40 --epochs-fused 40 --seeds 0 --out experiments\exp1_smoke.json"
    Run-Step "SMOKE Exp2 stages (plain→log→v2→T3→2stage)" "$PYTHON detection\exp_fused_improve.py --limit 150000 --window 60 --epochs 40 --seeds 0 --out experiments\exp2_smoke.json"
    Write-Host "`nSmoke done. Check experiments/exp1_smoke.md and exp2_smoke.md" -ForegroundColor Yellow
    exit 0
}

# Full run — 4 seeds, full files, staged improvements first, then ensemble sweeps
while ($true) {
    $iter = (Get-Date -Format "yyyyMMdd-HHmmss")

    # Exp2 staged first (fixes fused alone)
    Run-Step "Exp2 staged fixes 60s (4 seeds, full)" "$PYTHON detection\exp_fused_improve.py --window 60 --epochs 80 --seeds 0 1 2 3 --out experiments\exp2_60s_80ep.json"
    Run-Step "Exp2 staged fixes 300s (4 seeds, full)" "$PYTHON detection\exp_fused_improve.py --window 300 --epochs 80 --seeds 0 1 2 3 --out experiments\exp2_300s_80ep.json"

    # Exp1 ensemble on best fused config (log+v2+T3)
    Run-Step "Exp1 ensemble 60s T3 v2 (4 seeds)" "$PYTHON detection\exp_gnn_fused_ensemble.py --window 60 --seq-len 3 --feature-set v2 --epochs 80 --epochs-fused 80 --seeds 0 1 2 3 --out experiments\exp1_60s_T3_v2.json"
    Run-Step "Exp1 ensemble 300s T3 v2 (4 seeds)" "$PYTHON detection\exp_gnn_fused_ensemble.py --window 300 --seq-len 3 --feature-set v2 --epochs 80 --epochs-fused 80 --seeds 0 1 2 3 --out experiments\exp1_300s_T3_v2.json"
    # Also log+v1 baseline for ablation
    Run-Step "Exp1 ensemble 60s T5 v1 (control, 4 seeds)" "$PYTHON detection\exp_gnn_fused_ensemble.py --window 60 --seq-len 5 --feature-set v1 --epochs 80 --epochs-fused 80 --seeds 0 1 2 3 --out experiments\exp1_60s_T5_v1.json"

    Write-Host "`nLoop iteration $iter complete. Sleeping 5s before next round (or Ctrl+C to stop). Next iter will re-run with same seeds (deterministic check) or you can edit to grid-search hyperparams." -ForegroundColor Magenta
    Start-Sleep -Seconds 5
    # Break after one full round unless user wants continuous
    # For 24/7 operation, comment out the break and let it loop; it will re-train deterministically (bands measurable)
    break
}

Write-Host "`nLoop finished. Tabular scorecards: experiments/exp1_*.md , experiments/exp2_*.md , experiments/loop.log" -ForegroundColor Green
