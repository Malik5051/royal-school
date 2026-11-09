@echo off
title Royal International Schools - Server
cd /d "%~dp0"
where node >nul 2>nul
if errorlevel 1 (
  echo Node.js is not installed. Download it from https://nodejs.org and try again.
  pause
  exit /b 1
)
start "" http://localhost:3000/admin
node server.js
pause
