@echo off
title One-Shield Test: Model Failover
echo ========================================================
echo [TEST CASE 4] MODEL FAILOVER SIMULATION
echo ========================================================
echo This will rename 'model.onnx' to 'model.onnx.bak'.
echo.
echo STEPS:
echo 1. Close One-Shield (if running).
echo 2. Run this script.
echo 3. Start One-Shield.
echo.
echo EXPECTED RESULT:
echo  - Console/Log: "ONNX model not found - using fallback"
echo  - UI: Warning status (Yellow)
echo  - Logic: Still detects anomalies (using Heuristics)
echo ========================================================
pause

cd ..\core-service\models

if exist "model.onnx" (
    ren "model.onnx" "model.onnx.bak"
    echo [SUCCESS] Model renamed to model.onnx.bak
    echo NOW: Restart One-Shield to test fallback.
) else (
    echo [ERROR] model.onnx not found! (Already renamed?)
)
pause
