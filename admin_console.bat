@echo off
title LogShield Admin Console
cd /d "%~dp0"
"D:\Yashu_lp\Software\Softwares_d\Anaconda\envs\logshield\python.exe" admin_cmd.py %*
if "%1"=="" pause

