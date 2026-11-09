@echo off
cd /d "%~dp0"
set /p NEWPW=Type a new admin password (8+ characters): 
node server.js --set-password "%NEWPW%"
pause
