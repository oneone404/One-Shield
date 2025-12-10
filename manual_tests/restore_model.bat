@echo off
title One-Shield: Restore Model
echo Restoring model.onnx...
cd ..\core-service\models

if exist "model.onnx.bak" (
    ren "model.onnx.bak" "model.onnx"
    echo [SUCCESS] Model restored.
) else (
    echo [INFO] model.onnx.bak not found.
)
pause
