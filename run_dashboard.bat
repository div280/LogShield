@echo off
title LogShield SIEM Dashboard
echo ========================================================
echo   Starting LogShield Real-Time Forensic Dashboard...
echo ========================================================
echo.
python -m streamlit run dashboard/app.py
pause

