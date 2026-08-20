@echo off
rem Harmless Demonstration of Windows Persistence (Registry / Task Simulation)
echo Simulating persistence setup for demonstration...
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Run" /v "DemoTask" /t REG_SZ /d "cmd.exe /c echo Safe" /f
schtasks /create /tn "DemoUpdater" /tr "cmd.exe /c echo Safe" /sc daily /st 09:00 /f
