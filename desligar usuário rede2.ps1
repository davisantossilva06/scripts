# script.ps1 - Scanner completo de rede BETIM.PMB
param(
    [Parameter(Mandatory=$true)]
    [string]$UserName
)

# Configurações de cores
$SuccessColor = "Green"
$WarningColor = "Yellow" 
$ErrorColor = "Red"
$InfoColor = "Cyan"
$QuestionColor = "Magenta"
$DetailColor = "Gray"

# Configurações da rede
$Domain = "BETIM.PMB"
$NetworkPath = "\\betim.pmb"

function Write-Colored {
    param([string]$Message, [string]$Color = "White")
    Write-Host $Message -ForegroundColor $Color
}

function Test-DomainConnectivity {
    Write-Colored "Testando conectividade com o dominio $Domain..." $InfoColor
    
    $tests = @()
    
    # Teste 1: Ping para o dominio
    try {
        Write-Colored "  Executando ping para $Domain..." $DetailColor
        $pingTest = Test-Connection -ComputerName $Domain -Count 2 -Quiet
        $tests += @{Name = "Ping"; Result = $pingTest }
        Write-Colored "  Ping: $($pingTest)" $(if($pingTest){$SuccessColor}else{$ErrorColor})
    } catch {
        Write-Colored "  Ping: Falhou" $ErrorColor
        $tests += @{Name = "Ping"; Result = $false }
    }
    
    # Teste 2: Resolucao DNS
    try {
        Write-Colored "  Resolvendo DNS do dominio..." $DetailColor
        $dnsTest = [System.Net.Dns]::GetHostEntry($Domain)
        $tests += @{Name = "DNS"; Result = $true }
        Write-Colored "  DNS: Resolvido - $($dnsTest.HostName)" $SuccessColor
    } catch {
        Write-Colored "  DNS: Falha na resolucao" $ErrorColor
        $tests += @{Name = "DNS"; Result = $false }
    }
    
    # Teste 3: Teste de autenticacao
    try {
        Write-Colored "  Testando autenticacao no dominio..." $DetailColor
        $domainTest = (Get-WmiObject -Class Win32_ComputerSystem).Domain
        $authTest = ($domainTest -eq $Domain)
        $tests += @{Name = "Autenticacao"; Result = $authTest }
        Write-Colored "  Autenticacao: $authTest (Dominio: $domainTest)" $(if($authTest){$SuccessColor}else{$WarningColor})
    } catch {
        Write-Colored "  Autenticacao: Falhou" $ErrorColor
        $tests += @{Name = "Autenticacao"; Result = $false }
    }
    
    return ($tests | Where-Object { $_.Result -eq $true }).Count -ge 2
}

function Get-DomainComputersComprehensive {
    Write-Colored "Buscando computadores no dominio $Domain..." $InfoColor
    
    $computers = @()
    
    # Metodo 1: Active Directory (mais confiavel)
    Write-Colored "  Metodo 1: Consultando Active Directory..." $DetailColor
    try {
        Import-Module ActiveDirectory -ErrorAction SilentlyContinue
        $adComputers = Get-ADComputer -Filter * -Properties Name, DNSHostName, OperatingSystem, LastLogonDate, Enabled | 
                      Where-Object { $_.Enabled -eq $true } |
                      Sort-Object Name
        
        if ($adComputers) {
            Write-Colored "  Active Directory: Encontrados $($adComputers.Count) computadores" $SuccessColor
            $computers = $adComputers
        }
    } catch {
        Write-Colored "  Active Directory: Falhou - $($_.Exception.Message)" $WarningColor
    }
    
    # Metodo 2: Net View (alternativo)
    if ($computers.Count -eq 0) {
        Write-Colored "  Metodo 2: Executando net view..." $DetailColor
        try {
            $netView = net view /domain:$Domain 2>$null | Where-Object { $_ -match "\\\\" }
            if ($netView) {
                foreach ($computer in $netView) {
                    if ($computer -match "\\\\(.+?)\s") {
                        $compName = $matches[1]
                        $computers += [PSCustomObject]@{
                            Name = $compName
                            DNSHostName = "$compName.$Domain"
                            Enabled = $true
                        }
                    }
                }
                Write-Colored "  Net View: Encontrados $($computers.Count) computadores" $SuccessColor
            }
        } catch {
            Write-Colored "  Net View: Falhou" $WarningColor
        }
    }
    
    # Metodo 3: DNS Query
    if ($computers.Count -eq 0) {
        Write-Colored "  Metodo 3: Consultando DNS..." $DetailColor
        try {
            $dnsComputers = [System.Net.Dns]::GetHostEntry($Domain)
            # Tentativa de encontrar outros computadores (limitado)
            Write-Colored "  DNS: Encontrado dominio, mas busca limitada" $WarningColor
        } catch {
            Write-Colored "  DNS: Falhou" $WarningColor
        }
    }
    
    if ($computers.Count -eq 0) {
        Write-Colored "  Nenhum computador encontrado no dominio" $ErrorColor
        return @()
    }
    
    Write-Colored "  Total de computadores encontrados: $($computers.Count)" $SuccessColor
    return $computers
}

function Get-NetworkSessionsDetailed {
    param([array]$Computers)
    
    Write-Colored "Escaneando sessoes detalhadas do usuario $UserName na rede..." $InfoColor
    
    $allSessions = @()
    $onlineComputers = 0
    
    foreach ($computer in $computers) {
        $computerName = $computer.Name
        $computerDNS = $computer.DNSHostName
        
        Write-Colored "  Verificando $computerName..." $DetailColor
        
        # Tentar diferentes metodos de conexao
        $targets = @($computerName, $computerDNS)
        $computerOnline = $false
        
        foreach ($target in $targets) {
            if ($computerOnline) { continue }
            
            try {
                Write-Colored "    Testando conectividade com $target..." $DetailColor
                if (Test-Connection -ComputerName $target -Count 1 -Quiet -ErrorAction SilentlyContinue) {
                    $computerOnline = $true
                    $onlineComputers++
                    
                    # Obter informacoes de IP
                    $ipAddress = "N/A"
                    try {
                        $ipInfo = [System.Net.Dns]::GetHostEntry($target)
                        $ipAddress = $ipInfo.AddressList[0].IPAddressToString
                    } catch {
                        $ipAddress = "Nao resolvido"
                    }
                    
                    Write-Colored "    Computador online: $target ($ipAddress)" $SuccessColor
                    
                    # Metodo 1: Query User via Invoke-Command
                    Write-Colored "    Buscando sessoes com Query User..." $DetailColor
                    try {
                        $sessions = Invoke-Command -ComputerName $target -ScriptBlock {
                            query user $using:UserName 2>$null
                        } -ErrorAction Stop
                        
                        if ($sessions -and $sessions -match $using:UserName) {
                            foreach ($session in $sessions) {
                                if ($session -match $using:UserName) {
                                    $sessionParts = $session -split '\s+'
                                    
                                    $sessionInfo = [PSCustomObject]@{
                                        ComputerName = $computerName
                                        IPAddress = $ipAddress
                                        Username = $sessionParts[0]
                                        SessionName = $sessionParts[1]
                                        ID = $sessionParts[2]
                                        State = $sessionParts[3]
                                        IdleTime = $sessionParts[4]
                                        LogonTime = "$($sessionParts[5]) $($sessionParts[6])"
                                        LogonDate = try { [DateTime]::Parse("$($sessionParts[5]) $($sessionParts[6])") } catch { "N/A" }
                                        SessionType = "RDP/Terminal"
                                        Domain = $using:Domain
                                        Source = "Query User"
                                    }
                                    
                                    $allSessions += $sessionInfo
                                    Write-Colored "      Sessao encontrada: $($sessionInfo.SessionName) - $($sessionInfo.State)" $SuccessColor
                                }
                            }
                        } else {
                            Write-Colored "      Nenhuma sessao encontrada" $WarningColor
                        }
                    } catch {
                        Write-Colored "      Query User falhou: $($_.Exception.Message)" $WarningColor
                    }
                    
                    # Metodo 2: Processos do usuario
                    Write-Colored "    Buscando processos do usuario..." $DetailColor
                    try {
                        $processes = Invoke-Command -ComputerName $target -ScriptBlock {
                            Get-Process -IncludeUserName -ErrorAction SilentlyContinue | 
                            Where-Object {$_.UserName -like "*$using:UserName*"} |
                            Select-Object ProcessName, Id, StartTime, UserName, MachineName
                        } -ErrorAction SilentlyContinue
                        
                        if ($processes) {
                            foreach ($process in $processes) {
                                $sessionInfo = [PSCustomObject]@{
                                    ComputerName = $computerName
                                    IPAddress = $ipAddress
                                    Username = $process.UserName
                                    SessionName = "Processo: $($process.ProcessName)"
                                    ID = $process.Id
                                    State = "Executando"
                                    IdleTime = "N/A"
                                    LogonTime = if($process.StartTime) { $process.StartTime.ToString() } else { "N/A" }
                                    LogonDate = if($process.StartTime) { $process.StartTime } else { $null }
                                    SessionType = "Processo"
                                    Domain = $using:Domain
                                    Source = "Process List"
                                }
                                
                                $allSessions += $sessionInfo
                                Write-Colored "      Processo encontrado: $($process.ProcessName) (PID: $($process.Id))" $SuccessColor
                            }
                        }
                    } catch {
                        Write-Colored "      Busca de processos falhou" $WarningColor
                    }
                    
                    # Metodo 3: Logons do sistema
                    Write-Colored "    Verificando logons do sistema..." $DetailColor
                    try {
                        $logons = Invoke-Command -ComputerName $target -ScriptBlock {
                            Get-WinEvent -FilterHashtable @{LogName='Security'; ID=4624} -MaxEvents 10 -ErrorAction SilentlyContinue |
                            Where-Object { $_.Message -like "*$using:UserName*" } |
                            Select-Object TimeCreated, @{Name='LogonType'; Expression={
                                if ($_.Message -like "*Logon Type:*10*") { "RemoteInteractive" }
                                elseif ($_.Message -like "*Logon Type:*2*") { "Interactive" }
                                elseif ($_.Message -like "*Logon Type:*3*") { "Network" }
                                else { "Other" }
                            }}
                        } -ErrorAction SilentlyContinue
                        
                        if ($logons) {
                            foreach ($logon in $logons) {
                                $sessionInfo = [PSCustomObject]@{
                                    ComputerName = $computerName
                                    IPAddress = $ipAddress
                                    Username = $using:UserName
                                    SessionName = "Logon: $($logon.LogonType)"
                                    ID = "N/A"
                                    State = "Logon Registrado"
                                    IdleTime = "N/A"
                                    LogonTime = $logon.TimeCreated.ToString()
                                    LogonDate = $logon.TimeCreated
                                    SessionType = $logon.LogonType
                                    Domain = $using:Domain
                                    Source = "Security Log"
                                }
                                
                                $allSessions += $sessionInfo
                                Write-Colored "      Logon encontrado: $($logon.LogonType) - $($logon.TimeCreated)" $SuccessColor
                            }
                        }
                    } catch {
                        Write-Colored "      Verificacao de logons falhou" $WarningColor
                    }
                    
                    break  # Se conectou com sucesso, passa para o proximo computador
                }
            } catch {
                # Continuar para o proximo target
            }
        }
        
        if (-not $computerOnline) {
            Write-Colored "    Computador offline ou inacessivel" $WarningColor
        }
    }
    
    Write-Colored "  Computadores online verificados: $onlineComputers de $($computers.Count)" $InfoColor
    Write-Colored "  Total de sessoes/processos encontrados: $($allSessions.Count)" $InfoColor
    
    return $allSessions
}

function Get-NetworkSharesAndFiles {
    Write-Colored "Buscando compartilhamentos e arquivos abertos..." $InfoColor
    
    $networkResources = @()
    
    # Metodo 1: Compartilhamentos SMB
    Write-Colored "  Verificando compartilhamentos SMB..." $DetailColor
    try {
        $smbShares = Get-SmbShare -ErrorAction SilentlyContinue | Where-Object { $_.Path -like "*$UserName*" }
        if ($smbShares) {
            foreach ($share in $smbShares) {
                $networkResources += [PSCustomObject]@{
                    Type = "Compartilhamento"
                    Name = $share.Name
                    Path = $share.Path
                    Computer = $env:COMPUTERNAME
                    User = $UserName
                }
                Write-Colored "    Compartilhamento: $($share.Name) - $($share.Path)" $SuccessColor
            }
        }
    } catch {
        Write-Colored "    Verificacao SMB falhou" $WarningColor
    }
    
    # Metodo 2: Arquivos abertos
    Write-Colored "  Verificando arquivos abertos..." $DetailColor
    try {
        $openFiles = net file 2>$null | Where-Object { $_ -match $UserName }
        if ($openFiles) {
            foreach ($file in $openFiles) {
                $networkResources += [PSCustomObject]@{
                    Type = "Arquivo Aberto"
                    Name = $file
                    Path = "N/A"
                    Computer = $env:COMPUTERNAME
                    User = $UserName
                }
                Write-Colored "    Arquivo aberto: $file" $SuccessColor
            }
        }
    } catch {
        Write-Colored "    Verificacao de arquivos falhou" $WarningColor
    }
    
    return $networkResources
}

function Show-ComprehensiveReport {
    param(
        [array]$Sessions,
        [array]$Resources
    )
    
    Write-Colored "RELATORIO COMPLETO DA REDE $Domain" $QuestionColor
    Write-Colored "==========================================" $QuestionColor
    Write-Colored "Usuario: $UserName" $QuestionColor
    Write-Colored "Data/Hora do escaneamento: $(Get-Date)" $QuestionColor
    Write-Colored "Total de sessoes/processos encontrados: $($Sessions.Count)" $QuestionColor
    Write-Colored "==========================================" $QuestionColor
    
    if ($Sessions.Count -gt 0) {
        Write-Colored "SESSOES E PROCESSOS ENCONTRADOS:" $SuccessColor
        
        $Sessions | Group-Object ComputerName | ForEach-Object {
            $computerSessions = $_.Group
            $firstSession = $computerSessions[0]
            
            Write-Colored "Computador: $($_.Name)" $InfoColor
            Write-Colored "IP: $($firstSession.IPAddress)" $InfoColor
            Write-Colored "Sessoes ativas: $($computerSessions.Count)" $InfoColor
            Write-Colored "----------------------------------------" $InfoColor
            
            foreach ($session in $computerSessions) {
                Write-Colored "  Tipo: $($session.SessionType)" $DetailColor
                Write-Colored "  Sessao/Processo: $($session.SessionName)" $DetailColor
                Write-Colored "  ID: $($session.ID)" $DetailColor
                Write-Colored "  Estado: $($session.State)" $DetailColor
                Write-Colored "  Tempo Ocioso: $($session.IdleTime)" $DetailColor
                Write-Colored "  Horario Logon: $($session.LogonTime)" $DetailColor
                Write-Colored "  Fonte: $($session.Source)" $DetailColor
                Write-Colored "  ---" $DetailColor
            }
            Write-Colored "" $InfoColor
        }
    } else {
        Write-Colored "Nenhuma sessao ou processo encontrado para o usuario $UserName" $WarningColor
    }
    
    if ($Resources.Count -gt 0) {
        Write-Colored "RECURSOS DE REDE ENCONTRADOS:" $SuccessColor
        foreach ($resource in $Resources) {
            Write-Colored "  Tipo: $($resource.Type)" $InfoColor
            Write-Colored "  Nome: $($resource.Name)" $InfoColor
            Write-Colored "  Caminho: $($resource.Path)" $InfoColor
            Write-Colored "  Computador: $($resource.Computer)" $InfoColor
            Write-Colored "  ---" $InfoColor
        }
    }
    
    # Estatisticas resumidas
    $uniqueComputers = ($Sessions | Group-Object ComputerName).Count
    $rdpSessions = ($Sessions | Where-Object { $_.SessionType -eq "RDP/Terminal" }).Count
    $processSessions = ($Sessions | Where-Object { $_.SessionType -eq "Processo" }).Count
    $logonSessions = ($Sessions | Where-Object { $_.SessionType -like "Logon:*" }).Count
    
    Write-Colored "ESTATISTICAS RESUMIDAS:" $QuestionColor
    Write-Colored "  Computadores com sessoes: $uniqueComputers" $InfoColor
    Write-Colored "  Sessoes RDP/Terminal: $rdpSessions" $InfoColor
    Write-Colored "  Processos ativos: $processSessions" $InfoColor
    Write-Colored "  Logons registrados: $logonSessions" $InfoColor
    Write-Colored "  Recursos de rede: $($Resources.Count)" $InfoColor
}

function Confirm-Disconnection {
    Write-Colored "CONFIRMACAO DE DESLIGAMENTO" $QuestionColor
    Write-Colored "================================" $QuestionColor
    
    $choice = ""
    while ($choice -notin "S","N") {
        Write-Colored "Deseja prosseguir com o desligamento do usuario $UserName de TODOS os recursos da rede? (S/N)" $QuestionColor
        $choice = Read-Host "Digite S para Sim ou N para Nao"
        $choice = $choice.ToUpper()
    }
    
    return $choice -eq "S"
}

# EXECUCAO PRINCIPAL
Clear-Host
Write-Colored "SCANNER DE REDE - DOMINIO $Domain" $InfoColor
Write-Colored "==========================================" $InfoColor

# Verificar privilegios
if (-NOT ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")) {
    Write-Colored "ERRO: Execute como Administrador para funcoes completas" $ErrorColor
    exit 1
}

# Testar conectividade com o dominio
if (-not (Test-DomainConnectivity)) {
    Write-Colored "Falha na conectividade com o dominio $Domain" $ErrorColor
    exit 1
}

# Buscar computadores no dominio
$computers = Get-DomainComputersComprehensive
if ($computers.Count -eq 0) {
    Write-Colored "Nenhum computador encontrado no dominio" $ErrorColor
    exit 1
}

# Escanear sessoes detalhadas
$userSessions = Get-NetworkSessionsDetailed -Computers $computers

# Buscar recursos de rede
$networkResources = Get-NetworkSharesAndFiles

# Mostrar relatorio completo
Show-ComprehensiveReport -Sessions $userSessions -Resources $networkResources

# Confirmar antes de prosseguir para desligamento
if (Confirm-Disconnection) {
    Write-Colored "Iniciando processo de desligamento..." $SuccessColor
    # Aqui viriam as funcoes de desligamento (mantidas do script anterior)
} else {
    Write-Colored "Operacao cancelada pelo usuario" $WarningColor
}

Write-Colored "Escaneamento concluido" $InfoColor