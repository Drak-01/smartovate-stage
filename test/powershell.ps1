<#
.SYNOPSIS
    Script de simulation multi-événements de sécurité Windows (SecurityEvent)
    Contexte : Projet SIEM Smartovate Ltd - Tests de règles d'analyse
#>

Write-Host "=== Début de la simulation des événements de sécurité Windows ===" -ForegroundColor Cyan

# 1. Simulation d'échecs de connexion multiples (Event ID 4625 - Brute Force)
Write-Host "[*] Génération d'échecs de connexion (Event ID 4625)..." -ForegroundColor Yellow
for ($i = 1; $i -le 6; $i++) {
    $badUser = "AdminTest_$i"
    net use "\\127.0.0.1\IPC$" "MauvaisMotDePasse" /user:$badUser 2>&1 | Out-Null
    Start-Sleep -Seconds 1
}

# 2. Simulation de tentative de création de compte utilisateur local (Event ID 4720)
Write-Host "[*] Simulation de création de compte (Event ID 4720)..." -ForegroundColor Yellow
$tempUser = "HackerTestUser"
net user $tempUser P@ssword123! /add 2>&1 | Out-Null
Start-Sleep -Seconds 1

# 3. Simulation de tentative d'ajout d'un utilisateur à un groupe sensible (Event ID 4728 / 4732)
Write-Host "[*] Simulation d'ajout de groupe (Event ID 4732 - Administrateurs)..." -ForegroundColor Yellow
net localgroup "Administrateurs" $tempUser /add 2>&1 | Out-Null
Start-Sleep -Seconds 1

# 4. Nettoyage immédiat du compte de test pour garder la machine propre
Write-Host "[*] Nettoyage du compte de test..." -ForegroundColor Yellow
net user $tempUser /delete 2>&1 | Out-Null

Write-Host "=== Simulation multi-événements terminée avec succès ! ===" -ForegroundColor Green
Write-Host "Rappel : Laissez un court délai d'ingestion (généralement 5 à 15 minutes) pour voir remonter ces événements dans Sentinel." -ForegroundColor Gray