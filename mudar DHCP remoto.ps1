# Script para modificar configurações DHCP em computadores remotos
# REQUER PRIVILÉGIOS DE ADMINISTRADOR E ACESSO À REDE CORPORATIVA

param(
    [string]$RemoteIP
)

# Verifica se está executando como administrador
$currentPrincipal = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
if (-not $currentPrincipal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Write-Host "ERRO: Este script requer privilégios de administrador!" -ForegroundColor Red
    Write-Host "Execute o PowerShell como Administrador e tente novamente." -ForegroundColor Yellow
    pause
    exit
}

function Show-Header {
    Clear-Host
    Write-Host "================================================================" -ForegroundColor Cyan
    Write-Host "          GERENCIADOR DHCP REMOTO - REDE CORPORATIVA" -ForegroundColor Cyan
    Write-Host "               MODIFICACAO DE CONFIGURACOES" -ForegroundColor Cyan
    Write-Host "================================================================" -ForegroundColor Cyan
    Write-Host ""
}

function Get-ComputerNameFromIP {
    param([string]$IPAddress)
    
    Write-Host "Resolvendo nome do computador para o IP: $IPAddress" -ForegroundColor Yellow
    
    try {
        $result = [System.Net.Dns]::GetHostByAddress($IPAddress)
        $computerName = $result.HostName
        Write-Host "Nome do computador encontrado: $computerName" -ForegroundColor Green
        return $computerName
    }
    catch {
        Write-Host "Nao foi possivel resolver o nome do computador para o IP: $IPAddress" -ForegroundColor Red
        Write-Host "Erro: $($_.Exception.Message)" -ForegroundColor Red
        return $null
    }
}

function Test-RemoteConnection {
    param([string]$ComputerName)
    
    Write-Host "Testando conectividade com: $ComputerName" -ForegroundColor Yellow
    
    # Testa se o computador está online
    if (Test-Connection -ComputerName $ComputerName -Count 2 -Quiet) {
        Write-Host "Computador responde ao ping" -ForegroundColor Green
        return $true
    } else {
        Write-Host "Computador nao responde ao ping" -ForegroundColor Red
        return $false
    }
}

function Get-RemoteDHCPConfig {
    param([string]$ComputerName)
    
    Write-Host "Obtendo configuracoes DHCP atuais do computador remoto..." -ForegroundColor Yellow
    
    try {
        # Obtém configurações de rede via WMI remoto
        $networkAdapters = Get-WmiObject -Class Win32_NetworkAdapterConfiguration -ComputerName $ComputerName -Filter "IPEnabled=True"
        
        Write-Host "CONFIGURACOES DHCP ATUAIS:" -ForegroundColor Cyan
        foreach ($adapter in $networkAdapters) {
            Write-Host "Adaptador: $($adapter.Description)" -ForegroundColor White
            Write-Host "  DHCP Habilitado: $($adapter.DHCPEnabled)" -ForegroundColor White
            Write-Host "  IP Address: $($adapter.IPAddress -join ', ')" -ForegroundColor White
            Write-Host "  Servidor DHCP: $($adapter.DHCPServer)" -ForegroundColor White
            Write-Host "  Gateway Padrao: $($adapter.DefaultIPGateway -join ', ')" -ForegroundColor White
            Write-Host "  DNS: $($adapter.DNSServerSearchOrder -join ', ')" -ForegroundColor White
            Write-Host ""
        }
        
        return $networkAdapters
    }
    catch {
        Write-Host "Erro ao obter configuracoes DHCP: $($_.Exception.Message)" -ForegroundColor Red
        return $null
    }
}

function Set-RemoteDHCP {
    param([string]$ComputerName, [string]$AdapterIndex)
    
    Write-Host "Modificando configuracoes DHCP no computador remoto..." -ForegroundColor Yellow
    
    try {
        # Habilita DHCP no adaptador remoto
        $adapter = Get-WmiObject -Class Win32_NetworkAdapterConfiguration -ComputerName $ComputerName -Filter "Index=$AdapterIndex"
        
        if ($adapter) {
            $result = $adapter.EnableDHCP()
            
            if ($result.ReturnValue -eq 0) {
                Write-Host "DHCP habilitado com sucesso no adaptador $AdapterIndex" -ForegroundColor Green
                
                # Libera e renova o IP
                $releaseResult = $adapter.ReleaseDHCPLease()
                $renewResult = $adapter.RenewDHCPLease()
                
                Write-Host "Concessao DHCP liberada e renovada" -ForegroundColor Green
                return $true
            } else {
                Write-Host "Falha ao habilitar DHCP. Codigo de retorno: $($result.ReturnValue)" -ForegroundColor Red
                return $false
            }
        } else {
            Write-Host "Adaptador nao encontrado" -ForegroundColor Red
            return $false
        }
    }
    catch {
        Write-Host "Erro ao modificar DHCP: $($_.Exception.Message)" -ForegroundColor Red
        return $false
    }
}

function Set-RemoteStaticIP {
    param([string]$ComputerName, [string]$AdapterIndex, [string]$IPAddress, [string]$SubnetMask, [string]$Gateway, [string[]]$DNS)
    
    Write-Host "Configurando IP estatico no computador remoto..." -ForegroundColor Yellow
    
    try {
        $adapter = Get-WmiObject -Class Win32_NetworkAdapterConfiguration -ComputerName $ComputerName -Filter "Index=$AdapterIndex"
        
        if ($adapter) {
            # Define IP estatico
            $result = $adapter.EnableStatic($IPAddress, $SubnetMask)
            
            if ($result.ReturnValue -eq 0) {
                Write-Host "IP estatico configurado com sucesso" -ForegroundColor Green
                
                # Define gateway se especificado
                if ($Gateway) {
                    $gatewayResult = $adapter.SetGateways($Gateway)
                    if ($gatewayResult.ReturnValue -eq 0) {
                        Write-Host "Gateway configurado com sucesso" -ForegroundColor Green
                    }
                }
                
                # Define DNS se especificado
                if ($DNS) {
                    $dnsResult = $adapter.SetDNSServerSearchOrder($DNS)
                    if ($dnsResult.ReturnValue -eq 0) {
                        Write-Host "DNS configurado com sucesso" -ForegroundColor Green
                    }
                }
                
                return $true
            } else {
                Write-Host "Falha ao configurar IP estatico. Codigo: $($result.ReturnValue)" -ForegroundColor Red
                return $false
            }
        }
    }
    catch {
        Write-Host "Erro ao configurar IP estatico: $($_.Exception.Message)" -ForegroundColor Red
        return $false
    }
}

function Show-DHCPOptions {
    Write-Host "OPCOES DE CONFIGURACAO DHCP:" -ForegroundColor Cyan
    Write-Host "1. Habilitar DHCP automatico" -ForegroundColor White
    Write-Host "2. Configurar IP estatico" -ForegroundColor White
    Write-Host "3. Apenas ver configuracoes atuais" -ForegroundColor White
    Write-Host "4. Sair" -ForegroundColor White
    Write-Host ""
}

# MAIN EXECUTION
Show-Header

if (-not $RemoteIP) {
    $RemoteIP = Read-Host "Digite o IP do computador remoto"
}

# Valida formato do IP
if (-not ($RemoteIP -match "^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$")) {
    Write-Host "IP invalido. Use o formato: 192.168.1.100" -ForegroundColor Red
    pause
    exit
}

Write-Host "INICIANDO PROCESSO PARA O IP: $RemoteIP" -ForegroundColor Yellow
Write-Host ""

# Obtém nome do computador
$computerName = Get-ComputerNameFromIP -IPAddress $RemoteIP

if (-not $computerName) {
    Write-Host "Nao foi possivel continuar sem o nome do computador." -ForegroundColor Red
    pause
    exit
}

# Testa conectividade
$isOnline = Test-RemoteConnection -ComputerName $computerName

if (-not $isOnline) {
    Write-Host "Computador parece estar offline ou inacessivel." -ForegroundColor Red
    $continue = Read-Host "Deseja continuar mesmo assim? (S/N)"
    if ($continue -ne "S" -and $continue -ne "s") {
        exit
    }
}

# Obtém configurações atuais
$adapters = Get-RemoteDHCPConfig -ComputerName $computerName

if (-not $adapters) {
    Write-Host "Nao foi possivel obter as configuracoes de rede." -ForegroundColor Red
    pause
    exit
}

# Menu de opções
do {
    Show-Header
    Write-Host "Computador: $computerName ($RemoteIP)" -ForegroundColor Cyan
    Write-Host "Status: $(if ($isOnline) {'Online'} else {'Offline'})" -ForegroundColor $(if ($isOnline) {'Green'} else {'Red'})
    Write-Host ""
    
    Show-DHCPOptions
    $choice = Read-Host "Digite sua opcao (1-4)"
    
    switch ($choice) {
        "1" {
            Write-Host "HABILITANDO DHCP AUTOMATICO" -ForegroundColor Yellow
            $adapterIndex = Read-Host "Digite o indice do adaptador (veja na lista acima)"
            
            $result = Set-RemoteDHCP -ComputerName $computerName -AdapterIndex $adapterIndex
            
            if ($result) {
                Write-Host "DHCP habilitado com sucesso no computador remoto" -ForegroundColor Green
                
                # Verifica se ainda está online
                Write-Host "Verificando conectividade apos a alteracao..." -ForegroundColor Yellow
                if (Test-RemoteConnection -ComputerName $computerName) {
                    Write-Host "Computador ainda esta online e respondendo" -ForegroundColor Green
                } else {
                    Write-Host "Computador pode ter perdido conectividade" -ForegroundColor Red
                }
            } else {
                Write-Host "Falha ao habilitar DHCP" -ForegroundColor Red
            }
            pause
        }
        "2" {
            Write-Host "CONFIGURANDO IP ESTATICO" -ForegroundColor Yellow
            $adapterIndex = Read-Host "Digite o indice do adaptador"
            $staticIP = Read-Host "Digite o IP estatico"
            $subnetMask = Read-Host "Digite a mascara de rede (ex: 255.255.255.0)"
            $gateway = Read-Host "Digite o gateway (opcional)"
            $dnsInput = Read-Host "Digite os servidores DNS separados por virgula (opcional)"
            
            $dnsServers = @()
            if ($dnsInput) {
                $dnsServers = $dnsInput -split ','
            }
            
            $result = Set-RemoteStaticIP -ComputerName $computerName -AdapterIndex $adapterIndex -IPAddress $staticIP -SubnetMask $subnetMask -Gateway $gateway -DNS $dnsServers
            
            if ($result) {
                Write-Host "IP estatico configurado com sucesso" -ForegroundColor Green
                
                Write-Host "Verificando conectividade apos a alteracao..." -ForegroundColor Yellow
                if (Test-RemoteConnection -ComputerName $computerName) {
                    Write-Host "Computador ainda esta online e respondendo" -ForegroundColor Green
                } else {
                    Write-Host "Computador pode ter perdido conectividade" -ForegroundColor Red
                }
            } else {
                Write-Host "Falha ao configurar IP estatico" -ForegroundColor Red
            }
            pause
        }
        "3" {
            Get-RemoteDHCPConfig -ComputerName $computerName
            pause
        }
        "4" {
            Write-Host "Saindo do script..." -ForegroundColor Green
            exit
        }
        default {
            Write-Host "Opcao invalida" -ForegroundColor Red
            pause
        }
    }
} while ($true)