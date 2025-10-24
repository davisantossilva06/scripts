# script.ps1 - Desconectar usuário de recursos de rede BETIM.PMB
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

# Configurações da rede
$Domain = "BETIM.PMB"
$NetworkPath = "\\betim.pmb"

function Write-Colored {
    param([string]$Message, [string]$Color = "White")
    Write-Host $Message -ForegroundColor $Color
}

function Test-NetworkConnection {
    Write-Colored "`n[1/8] Testando conectividade com a rede $Domain..." $InfoColor
    
    try {
        # Testar conexão com o domínio
        $domainTest = Test-Connection -ComputerName $Domain -Count 1 -Quiet
        if ($domainTest) {
            Write-Colored "SUCESSO: Conexao com dominio $Domain estabelecida" $SuccessColor
            return $true
        } else {
            Write-Colored "ERRO: Nao foi possivel conectar ao dominio $Domain" $ErrorColor
            return $false
        }
    }
    catch {
        Write-Colored "ERRO: Falha na conexao com a rede: $($_.Exception.Message)" $ErrorColor
        return $false
    }
}

function Get-DomainComputers {
    Write-Colored "`n[2/8] Buscando computadores no dominio $Domain..." $InfoColor
    
    try {
        # Buscar computadores no domínio usando AD
        $computers = Get-ADComputer -Filter {Enabled -eq $true} -Properties Name, OperatingSystem, LastLogonDate | 
                    Where-Object {$_.Name -ne $env:COMPUTERNAME} |
                    Sort-Object Name
        
        if ($computers) {
            Write-Colored "SUCESSO: Encontrados $($computers.Count) computadores no dominio" $SuccessColor
            return $computers
        } else {
            Write-Colored "AVISO: Nenhum computador encontrado no dominio" $WarningColor
            return @()
        }
    }
    catch {
        Write-Colored "AVISO: Usando metodo alternativo para buscar computadores..." $WarningColor
        
        # Método alternativo - busca por rede
        try {
            $computers = Get-NetComputer -Domain $Domain -ErrorAction SilentlyContinue
            if ($computers) {
                Write-Colored "SUCESSO: Encontrados $($computers.Count) computadores (metodo alternativo)" $SuccessColor
                return $computers
            }
        }
        catch {
            Write-Colored "ERRO: Nao foi possivel buscar computadores do dominio" $ErrorColor
            return @()
        }
    }
}

function Scan-UserSessionsNetwork {
    param([array]$Computers)
    
    Write-Colored "`n[3/8] Escaneando sessoes do usuario $UserName em toda a rede..." $InfoColor
    
    $userSessions = @()
    $scannedCount = 0
    $foundCount = 0
    
    foreach ($computer in $computers) {
        $computerName = $computer.Name
        
        # Pular computadores inacessíveis
        if ($computerName -eq $env:COMPUTERNAME) { continue }
        
        try {
            Write-Colored "  Verificando $computerName..." "Gray"
            
            # Testar se o computador está online
            if (Test-Connection -ComputerName $computerName -Count 1 -Quiet -ErrorAction SilentlyContinue) {
                
                # Buscar sessões via query user remotamente
                $sessions = Invoke-Command -ComputerName $computerName -ScriptBlock {
                    query user $using:UserName 2>$null
                } -ErrorAction SilentlyContinue
                
                $scannedCount++
                
                if ($sessions -and $sessions -match $using:UserName) {
                    Write-Colored "    SESSOES ENCONTRADAS em $computerName" $SuccessColor
                    $foundCount++
                    
                    # Obter informações de rede do computador
                    $ipAddress = "N/A"
                    try {
                        $ipInfo = [System.Net.Dns]::GetHostEntry($computerName)
                        $ipAddress = $ipInfo.AddressList[0].IPAddressToString
                    } catch {
                        $ipAddress = "Nao resolvido"
                    }
                    
                    # Processar informações das sessões
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
                                Domain = $using:Domain
                            }
                            
                            $userSessions += $sessionInfo
                            
                            Write-Colored "      Usuario: $($sessionInfo.Username)" $InfoColor
                            Write-Colored "      Sessao: $($sessionInfo.SessionName)" $InfoColor
                            Write-Colored "      ID: $($sessionInfo.ID)" $InfoColor
                            Write-Colored "      Estado: $($sessionInfo.State)" $InfoColor
                            Write-Colored "      IP: $($sessionInfo.IPAddress)" $InfoColor
                            Write-Colored "      ---" $InfoColor
                        }
                    }
                }
            } else {
                Write-Colored "  $computerName - OFFLINE" "DarkGray"
            }
        }
        catch {
            Write-Colored "  $computerName - INACESSIVEL" "DarkGray"
        }
    }
    
    Write-Colored "`nRESUMO DO ESCANEAMENTO:" $InfoColor
    Write-Colored "  Computadores escaneados: $scannedCount" $InfoColor
    Write-Colored "  Computadores com sessoes: $foundCount" $InfoColor
    Write-Colored "  Total de sessoes encontradas: $($userSessions.Count)" $InfoColor
    
    return $userSessions
}

function Get-NetworkUserProcesses {
    param([array]$Computers)
    
    Write-Colored "`n[4/8] Buscando processos do usuario $UserName na rede..." $InfoColor
    
    $userProcesses = @()
    $scannedCount = 0
    $foundCount = 0
    
    foreach ($computer in $computers) {
        $computerName = $computer.Name
        
        if ($computerName -eq $env:COMPUTERNAME) { continue }
        
        try {
            Write-Colored "  Verificando processos em $computerName..." "Gray"
            
            if (Test-Connection -ComputerName $computerName -Count 1 -Quiet -ErrorAction SilentlyContinue) {
                
                $processes = Invoke-Command -ComputerName $computerName -ScriptBlock {
                    Get-Process -IncludeUserName -ErrorAction SilentlyContinue | 
                    Where-Object {$_.UserName -like "*$using:UserName*"} |
                    Select-Object ProcessName, Id, MachineName, UserName
                } -ErrorAction SilentlyContinue
                
                $scannedCount++
                
                if ($processes) {
                    Write-Colored "    PROCESSOS ENCONTRADOS em $computerName" $SuccessColor
                    $foundCount++
                    
                    foreach ($process in $processes) {
                        $processInfo = [PSCustomObject]@{
                            ComputerName = $computerName
                            ProcessName = $process.ProcessName
                            ProcessID = $process.Id
                            UserName = $process.UserName
                        }
                        
                        $userProcesses += $processInfo
                        
                        Write-Colored "      Processo: $($process.ProcessName) (PID: $($process.Id))" $InfoColor
                    }
                }
            }
        }
        catch {
            # Silenciar erros de computadores inacessíveis
        }
    }
    
    Write-Colored "  Processos encontrados em $foundCount computadores" $InfoColor
    return $userProcesses
}

function Show-UserNetworkSummary {
    param(
        [array]$Sessions,
        [array]$Processes
    )
    
    Write-Colored "`nRELATORIO COMPLETO DO USUARIO NA REDE" $QuestionColor
    Write-Colored "==========================================" $QuestionColor
    Write-Colored "Usuario: $UserName" $QuestionColor
    Write-Colored "Dominio: $Domain" $QuestionColor
    Write-Colored "Data/Hora: $(Get-Date)" $QuestionColor
    Write-Colored "==========================================" $QuestionColor
    
    if ($Sessions.Count -gt 0) {
        Write-Colored "`nSESSOES ATIVAS ENCONTRADAS:" $SuccessColor
        $Sessions | Group-Object ComputerName | ForEach-Object {
            Write-Colored "  Computador: $($_.Name)" $InfoColor
            Write-Colored "  IP: $(($_.Group[0]).IPAddress)" $InfoColor
            Write-Colored "  Sessoes: $($_.Count)" $InfoColor
            $_.Group | ForEach-Object {
                Write-Colored "    - $($_.SessionName) (ID: $($_.ID), Estado: $($_.State))" $InfoColor
            }
            Write-Colored "" $InfoColor
        }
    } else {
        Write-Colored "`nNenhuma sessao ativa encontrada na rede" $WarningColor
    }
    
    if ($Processes.Count -gt 0) {
        Write-Colored "`nPROCESSOS ATIVOS ENCONTRADOS:" $SuccessColor
        $Processes | Group-Object ComputerName | ForEach-Object {
            Write-Colored "  Computador: $($_.Name)" $InfoColor
            Write-Colored "  Processos: $($_.Count)" $InfoColor
            $_.Group | ForEach-Object {
                Write-Colored "    - $($_.ProcessName) (PID: $($_.ProcessID))" $InfoColor
            }
            Write-Colored "" $InfoColor
        }
    } else {
        Write-Colored "`nNenhum processo ativo encontrado na rede" $WarningColor
    }
}

function Confirm-NetworkDisconnection {
    Write-Colored "`nCONFIRMACAO DE DESLIGAMENTO" $QuestionColor
    Write-Colored "================================" $QuestionColor
    
    $choice = ""
    while ($choice -notin "S","N") {
        Write-Colored "`nDeseja prosseguir com o desligamento do usuario $UserName de TODOS os recursos da rede $Domain? (S/N)" $QuestionColor
        $choice = Read-Host "Digite S para Sim ou N para Nao"
        $choice = $choice.ToUpper()
    }
    
    return $choice -eq "S"
}

function Disconnect-NetworkSessions {
    param([array]$Sessions)
    
    Write-Colored "`n[5/8] Desconectando sessoes em toda a rede..." $InfoColor
    
    $disconnectedCount = 0
    $totalSessions = $Sessions.Count
    
    foreach ($session in $Sessions) {
        try {
            Write-Colored "  Desconectando $($session.Username) de $($session.ComputerName)..." "Gray"
            
            $result = Invoke-Command -ComputerName $session.ComputerName -ScriptBlock {
                logoff $using:session.ID 2>$null
            } -ErrorAction SilentlyContinue
            
            if ($?) {
                Write-Colored "    SUCESSO: Sessao $($session.ID) desconectada" $SuccessColor
                $disconnectedCount++
            } else {
                Write-Colored "    AVISO: Nao foi possivel desconectar sessao $($session.ID)" $WarningColor
            }
        }
        catch {
            Write-Colored "    ERRO: Falha ao desconectar de $($session.ComputerName): $($_.Exception.Message)" $ErrorColor
        }
    }
    
    Write-Colored "`nTotal de sessoes desconectadas: $disconnectedCount de $totalSessions" $SuccessColor
}

function Stop-NetworkProcesses {
    param([array]$Processes)
    
    Write-Colored "`n[6/8] Parando processos em toda a rede..." $InfoColor
    
    $stoppedCount = 0
    $totalProcesses = $Processes.Count
    
    foreach ($process in $Processes) {
        try {
            Write-Colored "  Parando $($process.ProcessName) em $($process.ComputerName)..." "Gray"
            
            $result = Invoke-Command -ComputerName $process.ComputerName -ScriptBlock {
                Stop-Process -Id $using:process.ProcessID -Force -ErrorAction SilentlyContinue
            } -ErrorAction SilentlyContinue
            
            if ($?) {
                Write-Colored "    SUCESSO: Processo $($process.ProcessName) (PID: $($process.ProcessID)) parado" $SuccessColor
                $stoppedCount++
            } else {
                Write-Colored "    AVISO: Nao foi possivel parar processo $($process.ProcessName)" $WarningColor
            }
        }
        catch {
            Write-Colored "    ERRO: Falha ao parar processo em $($process.ComputerName): $($_.Exception.Message)" $ErrorColor
        }
    }
    
    Write-Colored "`nTotal de processos parados: $stoppedCount de $totalProcesses" $SuccessColor
}

function Close-NetworkResources {
    Write-Colored "`n[7/8] Fechando recursos de rede compartilhados..." $InfoColor
    
    # Fechar arquivos abertos em compartilhamentos
    try {
        $openFiles = Get-SmbOpenFile -ErrorAction SilentlyContinue | Where-Object {$_.ClientUserName -like "*$UserName*"}
        
        if ($openFiles) {
            Write-Colored "Arquivos abertos em compartilhamentos:" $SuccessColor
            foreach ($file in $openFiles) {
                try {
                    Close-SmbOpenFile -FileId $file.FileId -Force -ErrorAction SilentlyContinue
                    Write-Colored "  Arquivo fechado: $($file.Path)" $SuccessColor
                }
                catch {
                    Write-Colored "  AVISO: Nao foi possivel fechar: $($file.Path)" $WarningColor
                }
            }
        } else {
            Write-Colored "Nenhum arquivo aberto encontrado em compartilhamentos" $WarningColor
        }
    }
    catch {
        Write-Colored "AVISO: Nao foi possivel verificar arquivos de rede compartilhados" $WarningColor
    }
}

function Verify-NetworkDisconnection {
    param([array]$Computers)
    
    Write-Colored "`n[8/8] Verificando desconexao em toda a rede..." $InfoColor
    
    Start-Sleep -Seconds 5
    
    $remainingSessions = @()
    $remainingProcesses = @()
    
    foreach ($computer in $computers) {
        $computerName = $computer.Name
        
        try {
            if (Test-Connection -ComputerName $computerName -Count 1 -Quiet -ErrorAction SilentlyContinue) {
                
                # Verificar sessões remanescentes
                $sessions = Invoke-Command -ComputerName $computerName -ScriptBlock {
                    query user $using:UserName 2>$null
                } -ErrorAction SilentlyContinue
                
                if ($sessions -and $sessions -match $using:UserName) {
                    $remainingSessions += $computerName
                }
                
                # Verificar processos remanescentes
                $processes = Invoke-Command -ComputerName $computerName -ScriptBlock {
                    Get-Process -IncludeUserName -ErrorAction SilentlyContinue | 
                    Where-Object {$_.UserName -like "*$using:UserName*"}
                } -ErrorAction SilentlyContinue
                
                if ($processes) {
                    $remainingProcesses += $computerName
                }
            }
        }
        catch {
            # Continuar verificação em outros computadores
        }
    }
    
    if ($remainingSessions.Count -eq 0 -and $remainingProcesses.Count -eq 0) {
        Write-Colored "SUCESSO: Usuario $UserName completamente desconectado de toda a rede $Domain!" $SuccessColor
    } else {
        Write-Colored "AVISO: Alguns recursos ainda podem estar ativos:" $WarningColor
        if ($remainingSessions.Count -gt 0) {
            Write-Colored "  Sessoes remanescentes em: $($remainingSessions -join ', ')" $WarningColor
        }
        if ($remainingProcesses.Count -gt 0) {
            Write-Colored "  Processos remanescentes em: $($remainingProcesses -join ', ')" $WarningColor
        }
    }
}

# Execução principal
Clear-Host
Write-Colored "==========================================" $InfoColor
Write-Colored "DESCONEXAO DE USUARIO DA REDE BETIM.PMB" $InfoColor
Write-Colored "==========================================" $InfoColor

# Verificar privilégios administrativos
if (-NOT ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")) {
    Write-Colored "ERRO: Execute como Administrador para funcoes completas!" $ErrorColor
    exit 1
}

# Testar conectividade com a rede
if (-not (Test-NetworkConnection)) {
    Write-Colored "Nao foi possivel continuar. Verifique a conexao com a rede $Domain." $ErrorColor
    exit 1
}

# Buscar computadores no domínio
$networkComputers = Get-DomainComputers
if ($networkComputers.Count -eq 0) {
    Write-Colored "Nenhum computador encontrado no dominio $Domain." $WarningColor
    exit 1
}

# Escanear usuário em toda a rede
$userSessions = Scan-UserSessionsNetwork -Computers $networkComputers
$userProcesses = Get-NetworkUserProcesses -Computers $networkComputers

# Mostrar relatório completo
Show-UserNetworkSummary -Sessions $userSessions -Processes $userProcesses

# Confirmar antes de prosseguir
if (-not (Confirm-NetworkDisconnection)) {
    Write-Colored "Operacao cancelada pelo usuario." $WarningColor
    exit 0
}

# Executar desligamento em rede
if ($userSessions.Count -gt 0) {
    Disconnect-NetworkSessions -Sessions $userSessions
}

if ($userProcesses.Count -gt 0) {
    Stop-NetworkProcesses -Processes $userProcesses
}

Close-NetworkResources
Verify-NetworkDisconnection -Computers $networkComputers

Write-Colored "`nOperacao de desligamento em rede concluida!" $InfoColor

.\desconectar-usuario.ps1 -UserName "nome.do.usuario"