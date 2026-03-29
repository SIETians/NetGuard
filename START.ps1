#!/usr/bin/env pwsh

# NetGuard Quick Start Script

Write-Host "`n" -ForegroundColor Cyan
Write-Host "==========================================" -ForegroundColor Cyan
Write-Host "     NetGuard - Network Intelligence       " -ForegroundColor Cyan
Write-Host "==========================================" -ForegroundColor Cyan
Write-Host "`n"

# Activate virtual environment
Write-Host "[1/3] Activating virtual environment..." -ForegroundColor Green
& ".\netguard_env\Scripts\Activate.ps1"

# Run migrations
Write-Host "[2/3] Syncing database..." -ForegroundColor Green
python manage.py migrate

# Start server
Write-Host "`n[3/3] Starting development server...`n" -ForegroundColor Green
Write-Host "==========================================" -ForegroundColor Cyan
Write-Host "   Server running at: http://localhost:8000" -ForegroundColor Cyan
Write-Host "   Login page: http://localhost:8000/login/" -ForegroundColor Cyan
Write-Host "==========================================" -ForegroundColor Cyan
Write-Host "`n"

python manage.py runserver 8000

Read-Host "Press Enter to exit"
