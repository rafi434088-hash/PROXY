@echo off
rem Launch the server-run watchdog hidden (no console window). It keeps
rem running in the background and only writes to watchdog.log when it
rem finds no active run. Double-click this file to start it.
cd /d "%~dp0"
start "" /min pythonw watchdog.py
