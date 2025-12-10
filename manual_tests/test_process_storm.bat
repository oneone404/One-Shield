@echo off
title One-Shield Test: Process Storm
echo ========================================================
echo [TEST CASE 2] PROCESS STORM SIMULATION
echo ========================================================
echo This will spawn 30 notepad.exe processes rapidly.
echo EXPECTED RESULT:
echo  - ThreatClass: Malicious/Suspicious
echo  - Incident: "Rapid Process Forking" or similar
echo  - Explain: High 'process_churn_rate', 'new_process_rate'
echo ========================================================
pause
echo Launching attack...
for /L %%i in (1,1,30) do (
    start /min notepad.exe
)
echo.
echo Attack launched! Check Dashboard.
echo.
pause
echo Cleaning up (Killing notepads)...
taskkill /IM notepad.exe /F
echo Done.
