param(
    [Parameter(Mandatory=$true)]
    [string]$UserName
)

$SuccessColor = "Green"
$WarningColor = "Yellow" 
$ErrorColor = "Red"
$InfoColor = "Cyan"
$QuestionColor = "Magenta"

function Write-Colored {
    param([string]$Message, [string]$Color = "White")
    Write-Host $Message -ForegroundColor $Color
}

function Get-UserSessionDetails {
    Write-Colored "`n[1/7] Buscando informacoes detalhadas das sessoes do usuario $UserName..." $InfoColor
    
    $sessionInfo = @()
    
    $sessions = query user $UserName 2>$null
    
    if ($sessions -and $sessions -match $UserName) {
        Write-Colored "Sessoes ativas encontradas:" $SuccessColor
        
        foreach ($session in $sessions) {
            if ($session -match $UserName) {
                $sessionParts = $session -split '\s+'
                
                $sessionObj = [PSCustomObject]@{
                    Username = $sessionParts[0]
                    SessionName = $sessionParts[1]
                    ID = $sessionParts[2]
                    State = $sessionParts[3]
                    IdleTime = $sessionParts[4]
                    LogonTime = "$($sessionParts[5]) $($sessionParts[6])"
                }
                
                $sessionInfo += $sessionObj
                
                Write-Colored "  Usuario: $($sessionObj.Username)" $InfoColor
                Write-Colored "  Sessao: $($sessionObj.SessionName)" $InfoColor
                Write-Colored "  ID: $($sessionObj.ID)" $InfoColor
                Write-Colored "  Estado: $($sessionObj.State)" $InfoColor
                Write-Colored "  Tempo Ocioso: $($sessionObj.IdleTime)" $InfoColor
                Write-Colored "  Horario Logon: $($sessionObj.LogonTime)" $InfoColor
                Write-Colored "  ---" $InfoColor
            }
        }
    } else {
        Write-Colored "Nenhuma sessao ativa encontrada para $UserName" $WarningColor
    }
    
    Write-Colored "`nBuscando processos e conexoes de rede..." $InfoColor
    
    $processes = Get-Process -IncludeUserName -ErrorAction SilentlyContinue | 
                 Where-Object {$_.UserName -like "*$UserName*"}
    
    if ($processes) {
        $uniqueMachines = $processes | Group-Object MachineName | Where-Object {$_.Name -ne ""}
        
        if ($uniqueMachines) {
            Write-Colored "Maquinas/Processos encontrados:" $SuccessColor
            foreach ($machine in $uniqueMachines) {
                Write-Colored "  Maquina: $($machine.Name)" $InfoColor
                $sampleProcess = $machine.Group[0]
                Write-Colored "  Processo: $($sampleProcess.ProcessName)" $InfoColor
                Write-Colored "  PID: $($sampleProcess.Id)" $InfoColor
                Write-Colored "  ---" $InfoColor
            }
        }
    }
    
    # Tentar identificar IPs via conexoes de rede
    try {
        $networkConnections = Get-NetTCPConnection -ErrorAction SilentlyContinue | 
                            Where-Object {$_.OwningProcess -in $processes.Id}
        
        if ($networkConnections) {
            $uniqueIPs = $networkConnections | Where-Object {$_.RemoteAddress -ne "0.0.0.0" -and $_.RemoteAddress -ne "127.0.0.1"} | 
                        Select-Object RemoteAddress -Unique
            
            if ($uniqueIPs) {
                Write-Colored "Conexoes de rede identificadas:" $SuccessColor
                foreach ($ip in $uniqueIPs) {
                    if ($ip.RemoteAddress) {
                        Write-Colored "  IP: $($ip.RemoteAddress)" $InfoColor
                        
                        # Tentar resolver nome da maquina
                        try {
                            $hostname = [System.Net.Dns]::GetHostEntry($ip.RemoteAddress).HostName
                            Write-Colored "  Nome da Maquina: $hostname" $InfoColor
                        } catch {
                            Write-Colored "  Nome da Maquina: Nao resolvido" $WarningColor
                        }
                        Write-Colored "  ---" $InfoColor
                    }
                }
            }
        }
    } catch {
        Write-Colored "Nao foi possivel obter informacoes detalhadas de rede" $WarningColor
    }
    
    return $sessionInfo
}

function Confirm-Disconnection {
    Write-Colored "`n" $QuestionColor
    Write-Colored "RESUMO DAS INFORMACOES ENCONTRADAS:" $QuestionColor
    Write-Colored "Usuario: $UserName" $QuestionColor
    Write-Colored "Computador local: $env:COMPUTERNAME" $QuestionColor
    Write-Colored "Data/Hora da verificacao: $(Get-Date)" $QuestionColor
    Write-Colored "`n" $QuestionColor
    
    $choice = ""
    while ($choice -notin "S","N") {
        Write-Colored "Deseja prosseguir com o desligamento do usuario $UserName de todos os recursos? (S/N)" $QuestionColor
        $choice = Read-Host "Digite S para Sim ou N para Nao"
        $choice = $choice.ToUpper()
    }
    
    return $choice -eq "S"
}

function Disconnect-UserSessions {
    Write-Colored "`n[2/7] Desconectando sessoes RDP/Terminal Services..." $InfoColor
    
    try {
        $sessionsBefore = query user $UserName 2>$null
        
        if ($sessionsBefore -and $sessionsBefore -match $UserName) {
            $result = logoff $UserName 2>$null
            Start-Sleep -Seconds 2
            
            $sessionsAfter = query user $UserName 2>$null
            if (-not $sessionsAfter -or $sessionsAfter -notmatch $UserName) {
                Write-Colored "SUCESSO: Todas as sessoes foram desconectadas" $SuccessColor
            } else {
                Write-Colored "AVISO: Algumas sessoes podem ainda estar ativas" $WarningColor
            }
        } else {
            Write-Colored "AVISO: Nenhuma sessao encontrada para desconectar" $WarningColor
        }
    }
    catch {
        Write-Colored "ERRO: Falha ao executar comando de logoff: $($_.Exception.Message)" $ErrorColor
    }
}

function Stop-UserProcesses {
    Write-Colored "`n[3/7] Parando processos do usuario..." $InfoColor
    
    $processes = Get-Process -IncludeUserName -ErrorAction SilentlyContinue | 
                 Where-Object {$_.UserName -like "*$UserName*"}
    
    if ($processes) {
        $processCount = $processes.Count
        Write-Colored "Encontrados $processCount processos para parar" $SuccessColor
        
        $stoppedCount = 0
        foreach ($process in $processes) {
            try {
                Stop-Process -Id $process.Id -Force -ErrorAction Stop
                Write-Colored "  Processo parado: $($process.ProcessName) (PID: $($process.Id))" $SuccessColor
                $stoppedCount++
            }
            catch {
                Write-Colored "  AVISO: Nao foi possivel parar $($process.ProcessName): $($_.Exception.Message)" $WarningColor
            }
        }
        Write-Colored "Total de processos parados: $stoppedCount de $processCount" $SuccessColor
    } else {
        Write-Colored "Nenhum processo encontrado para $UserName" $WarningColor
    }
}

function Close-NetworkFiles {
    Write-Colored "`n[4/7] Fechando arquivos de rede abertos..." $InfoColor
    
    try {
        $openFiles = net file 2>$null | Where-Object {$_ -match $UserName}
        
        if ($openFiles) {
            Write-Colored "Arquivos de rede abertos encontrados:" $SuccessColor
            $openFiles | ForEach-Object { Write-Colored "  $_" $InfoColor }
            
            $closedCount = 0
            net file | ForEach-Object {
                if ($_ -match "^\s*(\d+).*$UserName") {
                    $id = $matches[1]
                    net file $id /close 2>$null
                    Write-Colored "  Arquivo fechado (ID: $id)" $SuccessColor
                    $closedCount++
                }
            }
            Write-Colored "Total de arquivos fechados: $closedCount" $SuccessColor
        } else {
            Write-Colored "Nenhum arquivo de rede aberto encontrado" $WarningColor
        }
    }
    catch {
        Write-Colored "ERRO: Nao foi possivel verificar arquivos de rede: $($_.Exception.Message)" $ErrorColor
    }
}

function Check-UserShares {
    Write-Colored "`n[5/7] Verificando compartilhamentos acessados..." $InfoColor
    
    try {
        $shares = net session 2>$null | Where-Object {$_ -match $UserName}
        
        if ($shares) {
            Write-Colored "Compartilhamentos acessados encontrados:" $SuccessColor
            $shares | ForEach-Object { Write-Colored "  $_" $InfoColor }
            
            net session \\$env:COMPUTERNAME /delete 2>$null
            Write-Colored "Sessoes de compartilhamento encerradas" $SuccessColor
        } else {
            Write-Colored "Nenhum compartilhamento ativo encontrado" $WarningColor
        }
    }
    catch {
        Write-Colored "ERRO: Nao foi possivel verificar compartilhamentos: $($_.Exception.Message)" $ErrorColor
    }
}

function Clear-UserCache {
    Write-Colored "`n[6/7] Limpando credenciais e cache do usuario..." $InfoColor
    
    try {
      
        cmdkey /list 2>$null | Where-Object {$_ -match $UserName} | ForEach-Object {
            if ($_ -match "Target:\s*(.+)") {
                $target = $matches[1]
                cmdkey /delete:$target 2>$null
                Write-Colored "  Credencial removida: $target" $SuccessColor
            }
        }
        
        Write-Colored "Operacao de limpeza de cache concluida" $SuccessColor
    }
    catch {
        Write-Colored "AVISO: Nao foi possivel limpar todo o cache: $($_.Exception.Message)" $WarningColor
    }
}

function Verify-Disconnection {
    Write-Colored "`n[7/7] Verificando resultado final..." $InfoColor
    
    Start-Sleep -Seconds 3
    
    $remainingSessions = query user $UserName 2>$null
    $remainingProcesses = Get-Process -IncludeUserName -ErrorAction SilentlyContinue | 
                         Where-Object {$_.UserName -like "*$UserName*"}
    
    if (-not $remainingSessions -and -not $remainingProcesses) {
        Write-Colored "SUCESSO: Usuario $UserName completamente desconectado!" $SuccessColor
    } else {
        Write-Colored "AVISO: Alguns recursos podem ainda estar ativos:" $WarningColor
        if ($remainingSessions) {
            Write-Colored "  Sessoes remanescentes encontradas:" $WarningColor
            $remainingSessions | ForEach-Object { Write-Colored "  $_" $WarningColor }
        }
        if ($remainingProcesses) {
            Write-Colored "  Processos remanescentes: $($remainingProcesses.Count)" $WarningColor
        }
    }
}

Clear-Host
Write-Colored "==========================================" $InfoColor
Write-Colored "DESCONEXAO DE USUARIO DA REDE" $InfoColor
Write-Colored "==========================================" $InfoColor

if (-NOT ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")) {
    Write-Colored "ERRO: Execute como Administrador para funcoes completas!" $ErrorColor
    exit 1
}

$sessionDetails = Get-UserSessionDetails

if (-not (Confirm-Disconnection)) {
    Write-Colored "Operacao cancelada pelo usuario." $WarningColor
    exit 0
}

Disconnect-UserSessions
Stop-UserProcesses
Close-NetworkFiles
Check-UserShares
Clear-UserCache
Verify-Disconnection

Write-Colored "`nOperacao concluida!" $InfoColor