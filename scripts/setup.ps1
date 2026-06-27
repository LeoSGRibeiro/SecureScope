# SecureScope - Quick Setup (Windows/PowerShell)
Set-StrictMode -Version Latest

Write-Host "======================================"
Write-Host "  SecureScope - Security Platform"
Write-Host "  AUTHORIZED USE ONLY"
Write-Host "======================================"
Write-Host ""
Write-Host "WARNING: This tool is for authorized security testing ONLY."
Write-Host "Ensure you have written permission before scanning any target."
Write-Host ""

# Generate secret key
$secretKey = [System.Convert]::ToBase64String([System.Security.Cryptography.RandomNumberGenerator]::GetBytes(64))
"SECRET_KEY=$secretKey`nDEBUG=false" | Out-File -FilePath ".env" -Encoding utf8
Write-Host "Generated .env with SECRET_KEY"
Write-Host ""

Write-Host "Building Docker images..."
docker-compose build --no-cache

Write-Host "Starting core services..."
docker-compose up -d db redis

Write-Host "Waiting for database (10s)..."
Start-Sleep 10

Write-Host "Running migrations..."
docker-compose run --rm migrations

Write-Host "Starting all services..."
docker-compose up -d

Write-Host ""
Write-Host "======================================"
Write-Host "  SecureScope is running!"
Write-Host ""
Write-Host "  Frontend:  http://localhost:3000"
Write-Host "  API Docs:  http://localhost:8000/api/docs"
Write-Host "  Flower:    http://localhost:5555"
Write-Host "======================================"