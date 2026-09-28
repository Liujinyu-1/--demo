@echo off
chcp 65001 >nul
cd /d "%~dp0"
python probability_simulation.py --participants 128 --runs 12800 --winners 1 --output output
pause
