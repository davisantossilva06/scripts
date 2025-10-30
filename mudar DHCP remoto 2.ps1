# Script completo para gerenciamento remoto de DHCP e informacoes de rede
# REQUER PRIVILÉGIOS DE ADMINISTRADOR

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

# Variaveis globais para historico de operacoes
$global:OperationHistory = @()
$global:OriginalConfigs = @{}
$global:CurrentRemoteComputer = ""

function Show-Header {
    Clear-Host
    Write-Host "==================================================================================" -ForegroundColor Cyan
    Write-Host "                   GERENCIADOR AVANCADO DHCP REMOTO - REDE CORPORATIVA" -ForegroundColor Cyan
    Write-Host "==================================================================================" -ForegroundColor Cyan
    Write-Host ""
}

function Add-OperationHistory {
    param([string]$Operation, [string]$Status, [string]$Details)
    
    $historyEntry = @{
        Timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
        Computer = $global:CurrentRemoteComputer
        Operation = $Operation
        Status = $Status
        Details = $Details
    }
    
    $global:OperationHistory += $historyEntry
    Write-Host "Historico atualizado: $Operation - $Status" -ForegroundColor Gray
}

function Get-ComputerNameFromIP {
    param([string]$IPAddress)
    
    Write-Host "Resolvendo nome do computador para o IP: $IPAddress" -ForegroundColor Yellow
    
    try {
        $result = [System.Net.Dns]::GetHostByAddress($IPAddress)
        $computerName = $result.HostName
        Write-Host "Nome do computador encontrado: $computerName" -ForegroundColor Green
        Add-OperationHistory -Operation "Resolucao DNS" -Status "Sucesso" -Details "IP: $IPAddress -> Nome: $computerName"
        return $computerName
    }
    catch {
        Write-Host "Nao foi possivel resolver o nome do computador para o IP: $IPAddress" -ForegroundColor Red
        Write-Host "Erro detalhado: $($_.Exception.Message)" -ForegroundColor Red
        Add-OperationHistory -Operation "Resolucao DNS" -Status "Falha" -Details "IP: $IPAddress - Erro: $($_.Exception.Message)"
        return $null
    }
}

function Test-AdvancedRemoteConnection {
    param([string]$ComputerName)
    
    Write-Host "Testando conectividade avancada com: $ComputerName" -ForegroundColor Yellow
    
    $connectionTest = @{
        ComputerName = $ComputerName
        Ping = $false
        WMI = $false
        RPC = $false
        PSRemoting = $false
        ResponseTime = $null
    }
    
    # Teste de Ping
    try {
        $pingResult = Test-Connection -ComputerName $ComputerName -Count 4 -Quiet
        $connectionTest.Ping = $pingResult
        $responseTime = (Test-Connection -ComputerName $ComputerName -Count 1).ResponseTime
        $connectionTest.ResponseTime = $responseTime
        Write-Host "Ping: $($pingResult) - Tempo de resposta: $responseTime ms" -ForegroundColor $(if($pingResult){"Green"}else{"Red"})
    } catch {
        Write-Host "Ping: Falhou" -ForegroundColor Red
    }
    
    # Teste WMI
    try {
        $wmiTest = Get-WmiObject -Class Win32_ComputerSystem -ComputerName $ComputerName -ErrorAction Stop
        $connectionTest.WMI = $true
        Write-Host "WMI: Conectividade estabelecida" -ForegroundColor Green
    } catch {
        Write-Host "WMI: Falhou - $($_.Exception.Message)" -ForegroundColor Red
    }
    
    # Teste RPC
    try {
        $rpcTest = Get-WmiObject -Class Win32_Process -ComputerName $ComputerName -Filter "Name='svchost.exe'" -ErrorAction Stop | Select-Object -First 1
        $connectionTest.RPC = $true
        Write-Host "RPC: Conectividade estabelecida" -ForegroundColor Green
    } catch {
        Write-Host "RPC: Falhou" -ForegroundColor Red
    }
    
    # Teste PowerShell Remoting
    try {
        $psTest = Invoke-Command -ComputerName $ComputerName -ScriptBlock { $env:COMPUTERNAME } -ErrorAction Stop
        $connectionTest.PSRemoting = $true
        Write-Host "PSRemoting: Conectividade estabelecida" -ForegroundColor Green
    } catch {
        Write-Host "PSRemoting: Falhou - $($_.Exception.Message)" -ForegroundColor Red
    }
    
    Add-OperationHistory -Operation "Teste Conectividade" -Status "Completo" -Details "Computador: $ComputerName - Ping: $($connectionTest.Ping) - WMI: $($connectionTest.WMI)"
    return $connectionTest
}

function Get-ComprehensiveSystemInfo {
    param([string]$ComputerName)
    
    Write-Host "Coletando informacoes completas do sistema..." -ForegroundColor Yellow
    
    try {
        # Informacoes basicas do sistema
        $computerSystem = Get-WmiObject -Class Win32_ComputerSystem -ComputerName $ComputerName
        $operatingSystem = Get-WmiObject -Class Win32_OperatingSystem -ComputerName $ComputerName
        $bios = Get-WmiObject -Class Win32_BIOS -ComputerName $ComputerName
        $processor = Get-WmiObject -Class Win32_Processor -ComputerName $ComputerName | Select-Object -First 1
        
        Write-Host "INFORMACOES DO SISTEMA:" -ForegroundColor Cyan
        Write-Host "  Nome: $($computerSystem.Name)" -ForegroundColor White
        Write-Host "  Fabricante: $($computerSystem.Manufacturer)" -ForegroundColor White
        Write-Host "  Modelo: $($computerSystem.Model)" -ForegroundColor White
        Write-Host "  Processador: $($processor.Name)" -ForegroundColor White
        Write-Host "  Memoria RAM: $([math]::Round($computerSystem.TotalPhysicalMemory/1GB, 2)) GB" -ForegroundColor White
        Write-Host "  BIOS: $($bios.Manufacturer) $($bios.SMBIOSBIOSVersion)" -ForegroundColor White
        Write-Host "  Sistema Operacional: $($operatingSystem.Caption)" -ForegroundColor White
        Write-Host "  Versao: $($operatingSystem.Version)" -ForegroundColor White
        Write-Host "  Ultima Reinicializacao: $([Management.ManagementDateTimeConverter]::ToDateTime($operatingSystem.LastBootUpTime))" -ForegroundColor White
        
        return $true
    }
    catch {
        Write-Host "Erro ao coletar informacoes do sistema: $($_.Exception.Message)" -ForegroundColor Red
        return $false
    }
}

function Get-DetailedNetworkInfo {
    param([string]$ComputerName)
    
    Write-Host "Coletando informacoes detalhadas de rede..." -ForegroundColor Yellow
    
    try {
        $networkAdapters = Get-WmiObject -Class Win32_NetworkAdapterConfiguration -ComputerName $ComputerName -Filter "IPEnabled=True"
        
        Write-Host "CONFIGURACOES DE REDE DETALHADAS:" -ForegroundColor Cyan
        foreach ($adapter in $networkAdapters) {
            Write-Host "Adaptador: $($adapter.Description)" -ForegroundColor Magenta
            Write-Host "  Indice: $($adapter.Index)" -ForegroundColor White
            Write-Host "  DHCP Habilitado: $($adapter.DHCPEnabled)" -ForegroundColor $(if($adapter.DHCPEnabled){"Green"}else{"Yellow"})
            Write-Host "  Endereco MAC: $($adapter.MACAddress)" -ForegroundColor White
            Write-Host "  IP(s): $($adapter.IPAddress -join ', ')" -ForegroundColor White
            Write-Host "  Mascara(s): $($adapter.IPSubnet -join ', ')" -ForegroundColor White
            Write-Host "  Gateway(s): $($adapter.DefaultIPGateway -join ', ')" -ForegroundColor White
            Write-Host "  Servidor(es) DNS: $($adapter.DNSServerSearchOrder -join ', ')" -ForegroundColor White
            Write-Host "  Servidor DHCP: $($adapter.DHCPServer)" -ForegroundColor White
            Write-Host "  Concessao DHCP: $($adapter.DHCPLeaseObtained) - $($adapter.DHCPLeaseExpires)" -ForegroundColor White
            Write-Host ""
            
            # Salva configuracao original para reversao
            if (-not $global:OriginalConfigs.ContainsKey($adapter.Index)) {
                $global:OriginalConfigs[$adapter.Index] = @{
                    DHCPEnabled = $adapter.DHCPEnabled
                    IPAddress = $adapter.IPAddress
                    IPSubnet = $adapter.IPSubnet
                    DefaultIPGateway = $adapter.DefaultIPGateway
                    DNSServerSearchOrder = $adapter.DNSServerSearchOrder
                }
            }
        }
        
        # Informacoes de roteamento
        Write-Host "TABELA DE ROTEAMENTO:" -ForegroundColor Cyan
        try {
            $routes = Invoke-Command -ComputerName $ComputerName -ScriptBlock { route print } -ErrorAction SilentlyContinue
            if ($routes) {
                $routes | Select-String -Pattern "^\s*\d" | ForEach-Object { Write-Host "  $($_.ToString().Trim())" -ForegroundColor White }
            }
        } catch {
            Write-Host "  Nao foi possivel obter tabela de roteamento" -ForegroundColor Red
        }
        
        Add-OperationHistory -Operation "Coleta Informacoes Rede" -Status "Sucesso" -Details "Computador: $ComputerName - Adaptadores: $($networkAdapters.Count)"
        return $networkAdapters
    }
    catch {
        Write-Host "Erro ao coletar informacoes de rede: $($_.Exception.Message)" -ForegroundColor Red
        Add-OperationHistory -Operation "Coleta Informacoes Rede" -Status "Falha" -Details "Computador: $ComputerName - Erro: $($_.Exception.Message)"
        return $null
    }
}

function Set-RemoteDHCP {
    param([string]$ComputerName, [string]$AdapterIndex)
    
    Write-Host "Habilitando DHCP no adaptador $AdapterIndex..." -ForegroundColor Yellow
    
    try {
        $adapter = Get-WmiObject -Class Win32_NetworkAdapterConfiguration -ComputerName $ComputerName -Filter "Index=$AdapterIndex"
        
        if ($adapter) {
            $result = $adapter.EnableDHCP()
            
            if ($result.ReturnValue -eq 0) {
                Write-Host "DHCP habilitado com sucesso" -ForegroundColor Green
                
                # Libera e renova concessao DHCP
                $releaseResult = $adapter.ReleaseDHCPLease()
                $renewResult = $adapter.RenewDHCPLease()
                
                Write-Host "Concessao DHCP liberada e renovada" -ForegroundColor Green
                
                Add-OperationHistory -Operation "Habilitar DHCP" -Status "Sucesso" -Details "Computador: $ComputerName - Adaptador: $AdapterIndex"
                return $true
            } else {
                Write-Host "Falha ao habilitar DHCP. Codigo: $($result.ReturnValue)" -ForegroundColor Red
                Add-OperationHistory -Operation "Habilitar DHCP" -Status "Falha" -Details "Computador: $ComputerName - Adaptador: $AdapterIndex - Codigo: $($result.ReturnValue)"
                return $false
            }
        }
    }
    catch {
        Write-Host "Erro ao habilitar DHCP: $($_.Exception.Message)" -ForegroundColor Red
        Add-OperationHistory -Operation "Habilitar DHCP" -Status "Falha" -Details "Computador: $ComputerName - Adaptador: $AdapterIndex - Erro: $($_.Exception.Message)"
        return $false
    }
}

function Set-RemoteStaticIP {
    param([string]$ComputerName, [string]$AdapterIndex, [string]$IPAddress, [string]$SubnetMask, [string]$Gateway, [string[]]$DNS)
    
    Write-Host "Configurando IP estatico $IPAddress..." -ForegroundColor Yellow
    
    try {
        $adapter = Get-WmiObject -Class Win32_NetworkAdapterConfiguration -ComputerName $ComputerName -Filter "Index=$AdapterIndex"
        
        if ($adapter) {
            # Define IP estatico
            $result = $adapter.EnableStatic($IPAddress, $SubnetMask)
            
            if ($result.ReturnValue -eq 0) {
                Write-Host "IP estatico configurado com sucesso" -ForegroundColor Green
                
                # Define gateway
                if ($Gateway) {
                    $gatewayResult = $adapter.SetGateways($Gateway)
                    if ($gatewayResult.ReturnValue -eq 0) {
                        Write-Host "Gateway configurado: $Gateway" -ForegroundColor Green
                    }
                }
                
                # Define DNS
                if ($DNS) {
                    $dnsResult = $adapter.SetDNSServerSearchOrder($DNS)
                    if ($dnsResult.ReturnValue -eq 0) {
                        Write-Host "DNS configurado: $($DNS -join ', ')" -ForegroundColor Green
                    }
                }
                
                Add-OperationHistory -Operation "Configurar IP Estatico" -Status "Sucesso" -Details "Computador: $ComputerName - Adaptador: $AdapterIndex - IP: $IPAddress"
                return $true
            } else {
                Write-Host "Falha ao configurar IP estatico. Codigo: $($result.ReturnValue)" -ForegroundColor Red
                Add-OperationHistory -Operation "Configurar IP Estatico" -Status "Falha" -Details "Computador: $ComputerName - Adaptador: $AdapterIndex - IP: $IPAddress - Codigo: $($result.ReturnValue)"
                return $false
            }
        }
    }
    catch {
        Write-Host "Erro ao configurar IP estatico: $($_.Exception.Message)" -ForegroundColor Red
        Add-OperationHistory -Operation "Configurar IP Estatico" -Status "Falha" -Details "Computador: $ComputerName - Adaptador: $AdapterIndex - IP: $IPAddress - Erro: $($_.Exception.Message)"
        return $false
    }
}

function Revert-Configuration {
    param([string]$ComputerName, [string]$AdapterIndex)
    
    Write-Host "Revertendo configuracao do adaptador $AdapterIndex..." -ForegroundColor Yellow
    
    if (-not $global:OriginalConfigs.ContainsKey($AdapterIndex)) {
        Write-Host "Nenhuma configuracao original encontrada para este adaptador" -ForegroundColor Red
        return $false
    }
    
    $originalConfig = $global:OriginalConfigs[$AdapterIndex]
    
    try {
        $adapter = Get-WmiObject -Class Win32_NetworkAdapterConfiguration -ComputerName $ComputerName -Filter "Index=$AdapterIndex"
        
        if ($adapter) {
            if ($originalConfig.DHCPEnabled) {
                # Reverte para DHCP
                $result = $adapter.EnableDHCP()
                if ($result.ReturnValue -eq 0) {
                    Write-Host "Configuracao revertida para DHCP" -ForegroundColor Green
                }
            } else {
                # Reverte para IP estatico original
                $result = $adapter.EnableStatic($originalConfig.IPAddress[0], $originalConfig.IPSubnet[0])
                if ($result.ReturnValue -eq 0) {
                    Write-Host "IP estatico original restaurado: $($originalConfig.IPAddress[0])" -ForegroundColor Green
                }
                
                # Restaura gateway
                if ($originalConfig.DefaultIPGateway) {
                    $adapter.SetGateways($originalConfig.DefaultIPGateway)
                }
                
                # Restaura DNS
                if ($originalConfig.DNSServerSearchOrder) {
                    $adapter.SetDNSServerSearchOrder($originalConfig.DNSServerSearchOrder)
                }
            }
            
            Add-OperationHistory -Operation "Reversao Configuracao" -Status "Sucesso" -Details "Computador: $ComputerName - Adaptador: $AdapterIndex"
            return $true
        }
    }
    catch {
        Write-Host "Erro ao reverter configuracao: $($_.Exception.Message)" -ForegroundColor Red
        Add-OperationHistory -Operation "Reversao Configuracao" -Status "Falha" -Details "Computador: $ComputerName - Adaptador: $AdapterIndex - Erro: $($_.Exception.Message)"
        return $false
    }
}

function Get-ServicesInfo {
    param([string]$ComputerName)
    
    Write-Host "Coletando informacoes de servicos de rede..." -ForegroundColor Yellow
    
    try {
        $services = Get-WmiObject -Class Win32_Service -ComputerName $ComputerName | Where-Object {
            $_.Name -like "*dhcp*" -or $_.Name -like "*dns*" -or $_.Name -like "*network*" -or $_.Name -like "*ip*"
        }
        
        Write-Host "SERVICOS DE REDE:" -ForegroundColor Cyan
        foreach ($service in $services) {
            $statusColor = if ($service.State -eq "Running") { "Green" } else { "Red" }
            Write-Host "  $($service.Name): $($service.State) ($($service.StartMode))" -ForegroundColor $statusColor
        }
        
        return $true
    }
    catch {
        Write-Host "Erro ao coletar servicos: $($_.Exception.Message)" -ForegroundColor Red
        return $false
    }
}

function Get-EventLogs {
    param([string]$ComputerName)
    
    Write-Host "Verificando logs de sistema recentes..." -ForegroundColor Yellow
    
    try {
        $events = Get-WmiObject -Class Win32_NTLogEvent -ComputerName $ComputerName -Filter "LogFile='System' AND TimeGenerated >= '$(Get-Date).AddHours(-24).ToString('yyyyMMddHHmmss.000000-000')'" | Select-Object -First 10
        
        Write-Host "EVENTOS RECENTES DO SISTEMA:" -ForegroundColor Cyan
        foreach ($event in $events) {
            $level = switch ($event.Type) {
                "1" { "ERRO"; $color = "Red" }
                "2" { "AVISO"; $color = "Yellow" }
                "4" { "INFORMACAO"; $color = "White" }
                default { "OUTRO"; $color = "Gray" }
            }
            Write-Host "  [$level] $($event.SourceName): $($event.Message)" -ForegroundColor $color
        }
        
        return $true
    }
    catch {
        Write-Host "Erro ao coletar logs: $($_.Exception.Message)" -ForegroundColor Red
        return $false
    }
}

function Show-OperationHistory {
    Write-Host "HISTORICO DE OPERACOES:" -ForegroundColor Cyan
    Write-Host "==================================================================================" -ForegroundColor Cyan
    
    foreach ($entry in $global:OperationHistory) {
        $statusColor = if ($entry.Status -eq "Sucesso") { "Green" } else { "Red" }
        Write-Host "[$($entry.Timestamp)] $($entry.Computer) - $($entry.Operation): " -NoNewline
        Write-Host $entry.Status -ForegroundColor $statusColor
        Write-Host "  Detalhes: $($entry.Details)" -ForegroundColor Gray
    }
}

function Show-MainMenu {
    Write-Host "MENU PRINCIPAL - Computador: $($global:CurrentRemoteComputer)" -ForegroundColor Cyan
    Write-Host "==================================================================================" -ForegroundColor Cyan
    Write-Host "1.  Testar conectividade avancada" -ForegroundColor White
    Write-Host "2.  Informacoes completas do sistema" -ForegroundColor White
    Write-Host "3.  Configuracoes detalhadas de rede" -ForegroundColor White
    Write-Host "4.  Habilitar DHCP automatico" -ForegroundColor White
    Write-Host "5.  Configurar IP estatico" -ForegroundColor White
    Write-Host "6.  Reverter configuracao de rede" -ForegroundColor White
    Write-Host "7.  Informacoes de servicos de rede" -ForegroundColor White
    Write-Host "8.  Ver logs do sistema" -ForegroundColor White
    Write-Host "9.  Historico de operacoes" -ForegroundColor White
    Write-Host "10. Testar conectividade apos alteracoes" -ForegroundColor White
    Write-Host "11. Trocar computador remoto" -ForegroundColor White
    Write-Host "12. Sair" -ForegroundColor White
    Write-Host ""
}

# EXECUCAO PRINCIPAL
do {
    Show-Header
    
    if (-not $global:CurrentRemoteComputer -or $RemoteIP) {
        if (-not $RemoteIP) {
            $RemoteIP = Read-Host "Digite o IP do computador remoto"
        }
        
        # Valida formato do IP
        if (-not ($RemoteIP -match "^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$")) {
            Write-Host "IP invalido. Use o formato: 192.168.1.100" -ForegroundColor Red
            pause
            continue
        }
        
        Write-Host "INICIANDO CONEXAO COM: $RemoteIP" -ForegroundColor Yellow
        Write-Host ""
        
        # Obtem nome do computador
        $computerName = Get-ComputerNameFromIP -IPAddress $RemoteIP
        
        if (-not $computerName) {
            Write-Host "Nao foi possivel continuar sem o nome do computador." -ForegroundColor Red
            pause
            continue
        }
        
        $global:CurrentRemoteComputer = $computerName
        $RemoteIP = $null  # Reseta para proximas iteracoes
    }
    
    # Teste de conectividade inicial
    Write-Host "Testando conectividade inicial..." -ForegroundColor Yellow
    $connectionStatus = Test-AdvancedRemoteConnection -ComputerName $global:CurrentRemoteComputer
    
    if (-not $connectionStatus.Ping) {
        Write-Host "AVISO: Computador pode estar offline ou inacessivel." -ForegroundColor Red
        $continue = Read-Host "Deseja continuar mesmo assim? (S/N)"
        if ($continue -ne "S" -and $continue -ne "s") {
            $global:CurrentRemoteComputer = $null
            continue
        }
    }
    
    # Menu principal
    do {
        Show-Header
        Write-Host "Computador Atual: $($global:CurrentRemoteComputer)" -ForegroundColor Cyan
        Write-Host "Status Conectividade: " -NoNewline
        Write-Host "$(if ($connectionStatus.Ping) {'Online'} else {'Offline'})" -ForegroundColor $(if ($connectionStatus.Ping) {"Green"} else {"Red"})
        Write-Host ""
        
        Show-MainMenu
        $choice = Read-Host "Digite sua opcao (1-12)"
        
        switch ($choice) {
            "1" {
                Show-Header
                Write-Host "TESTE DE CONECTIVIDADE AVANCADA" -ForegroundColor Yellow
                $connectionStatus = Test-AdvancedRemoteConnection -ComputerName $global:CurrentRemoteComputer
                pause
            }
            "2" {
                Show-Header
                Write-Host "INFORMACOES COMPLETAS DO SISTEMA" -ForegroundColor Yellow
                Get-ComprehensiveSystemInfo -ComputerName $global:CurrentRemoteComputer
                pause
            }
            "3" {
                Show-Header
                Write-Host "CONFIGURACOES DETALHADAS DE REDE" -ForegroundColor Yellow
                $adapters = Get-DetailedNetworkInfo -ComputerName $global:CurrentRemoteComputer
                pause
            }
            "4" {
                Show-Header
                Write-Host "HABILITAR DHCP AUTOMATICO" -ForegroundColor Yellow
                $adapterIndex = Read-Host "Digite o indice do adaptador"
                $result = Set-RemoteDHCP -ComputerName $global:CurrentRemoteComputer -AdapterIndex $adapterIndex
                
                if ($result) {
                    Write-Host "Verificando conectividade apos alteracao..." -ForegroundColor Yellow
                    Test-AdvancedRemoteConnection -ComputerName $global:CurrentRemoteComputer
                }
                pause
            }
            "5" {
                Show-Header
                Write-Host "CONFIGURAR IP ESTATICO" -ForegroundColor Yellow
                $adapterIndex = Read-Host "Digite o indice do adaptador"
                $staticIP = Read-Host "Digite o IP estatico"
                $subnetMask = Read-Host "Digite a mascara de rede"
                $gateway = Read-Host "Digite o gateway (opcional)"
                $dnsInput = Read-Host "Digite os servidores DNS separados por virgula (opcional)"
                
                $dnsServers = @()
                if ($dnsInput) {
                    $dnsServers = $dnsInput -split ','
                }
                
                $result = Set-RemoteStaticIP -ComputerName $global:CurrentRemoteComputer -AdapterIndex $adapterIndex -IPAddress $staticIP -SubnetMask $subnetMask -Gateway $gateway -DNS $dnsServers
                
                if ($result) {
                    Write-Host "Verificando conectividade apos alteracao..." -ForegroundColor Yellow
                    Test-AdvancedRemoteConnection -ComputerName $global:CurrentRemoteComputer
                }
                pause
            }
            "6" {
                Show-Header
                Write-Host "REVERTER CONFIGURACAO DE REDE" -ForegroundColor Yellow
                $adapterIndex = Read-Host "Digite o indice do adaptador para reverter"
                $result = Revert-Configuration -ComputerName $global:CurrentRemoteComputer -AdapterIndex $adapterIndex
                
                if ($result) {
                    Write-Host "Verificando conectividade apos reversao..." -ForegroundColor Yellow
                    Test-AdvancedRemoteConnection -ComputerName $global:CurrentRemoteComputer
                }
                pause
            }
            "7" {
                Show-Header
                Write-Host "INFORMACOES DE SERVICOS DE REDE" -ForegroundColor Yellow
                Get-ServicesInfo -ComputerName $global:CurrentRemoteComputer
                pause
            }
            "8" {
                Show-Header
                Write-Host "LOGS DO SISTEMA" -ForegroundColor Yellow
                Get-EventLogs -ComputerName $global:CurrentRemoteComputer
                pause
            }
            "9" {
                Show-Header
                Show-OperationHistory
                pause
            }
            "10" {
                Show-Header
                Write-Host "TESTE DE CONECTIVIDADE POS-ALTERACOES" -ForegroundColor Yellow
                Test-AdvancedRemoteConnection -ComputerName $global:CurrentRemoteComputer
                pause
            }
            "11" {
                $global:CurrentRemoteComputer = $null
                break
            }
            "12" {
                Write-Host "Saindo do script..." -ForegroundColor Green
                exit
            }
            default {
                Write-Host "Opcao invalida" -ForegroundColor Red
                pause
            }
        }
    } while ($global:CurrentRemoteComputer)
} while ($true)