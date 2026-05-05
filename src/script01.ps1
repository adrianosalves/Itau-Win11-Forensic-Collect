<#
.SYNOPSIS
    Coleta automatizada de evidências forenses para estações Windows 10/11 sinalizadas pelo Banco Itaú.
.DESCRIPTION
    Ferramenta de resposta a incidentes que coleta, de forma somente leitura, artefatos do sistema,
    logs do Windows, estado de rede (com processos, caminhos e hashes), recursos de segurança e 
    pontos de persistência relacionados ao ambiente do App Itaú. O output é compactado e preparado 
    para envio seguro à equipe de TI/banco.
.PARAMETER OutputPath
    Caminho personalizado para salvar as evidências. Padrão: $env:TEMP\Itau_Forensics_<Timestamp>
.PARAMETER RetainUnpacked
    Mantém a pasta extraída após criação do ZIP. Padrão: $false
.PARAMETER HoursBack
    Período (em horas) para filtrar logs do Windows. Padrão: 72
.NOTES
    Autor   : [Seu Nome/Handle GitHub]
    Versão  : 1.0.2 (Rede avançada: Processos + Caminhos + Hashes SHA256)
    Data    : 2026-05-06
    Licença : MIT
    AVISO   : FERRAMENTA DE USO EXCLUSIVO EM AMBIENTES CORPORATIVOS AUTORIZADOS.
              NÃO COLETA SENHAS, TOKENS, CREDENCIAIS OU DADOS PESSOAIS SENSÍVEIS.
.EXAMPLE
    .\Collect-ItauForensics.ps1
.EXAMPLE
    .\Collect-ItauForensics.ps1 -OutputPath "D:\Evidence" -HoursBack 48 -RetainUnpacked
#>

[CmdletBinding()]
param(
    [string]$OutputPath = "",
    [switch]$RetainUnpacked,
    [int]$HoursBack = 72
)

#Requires -RunAsAdministrator
#Requires -Version 5.1

$ErrorActionPreference = "Continue"
$ProgressPreference = "SilentlyContinue"

#region Inicialização
if ($env:OS -notmatch "Windows_NT") { throw "Este script suporta apenas Windows." }
$WinVer = [System.Environment]::OSVersion.Version.Major
if ($WinVer -lt 10) { Write-Warning "Script otimizado para Windows 10/11. Resultados podem variar em versões anteriores." }

$Timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
$BaseDir = if ($OutputPath) { $OutputPath } else { Join-Path $env:TEMP "Itau_Forensics_$Timestamp" }
New-Item -Path $BaseDir -ItemType Directory -Force | Out-Null

$LogFile = Join-Path $BaseDir "execution.log"
$Summary = [System.Collections.Generic.List[string]]::new()

function Log-Step {
    param([string]$Step, [string]$Msg, [switch]$Success, [switch]$Warn, [switch]$Error)
    $color = if ($Success) { "Green" } elseif ($Warn) { "Yellow" } elseif ($Error) { "Red" } else { "Cyan" }
    $prefix = if ($Success) { "[✓]" } elseif ($Warn) { "[!]" } elseif ($Error) { "[✗]" } else { "[*]" }
    $line = "$prefix $Step : $Msg"
    Write-Host $line -ForegroundColor $color
    Add-Content -Path $LogFile -Value "$(Get-Date -Format 'o') | $line"
}
#endregion

try {
    #region 1. Informações do Sistema
    Log-Step "1/8" "Coletando dados do sistema..."
    try {
        systeminfo | Out-File (Join-Path $BaseDir "01_SystemInfo.txt") -Encoding UTF8
        Get-ComputerInfo | Select-Object WindowsProductName, OsVersion, OsBuildNumber, CsName, CsDomain, OsArchitecture |
            Format-Table | Out-File (Join-Path $BaseDir "01_SysBrief.txt") -Encoding UTF8
        $Summary.Add("✅ System Info: OK")
    }
    catch { Log-Step "ERRO 1/8" "Falha ao coletar systeminfo: $($_.Exception.Message)" -Warn; $Summary.Add("⚠️  System Info: Parcial") }
    #endregion

    #region 2. App Itaú
    Log-Step "2/8" "Mapeando artefatos do App Itaú..."
    try {
        $ItauReport = @()
        $SearchPaths = @("$env:ProgramFiles\Itaú", "${env:ProgramFiles(x86)}\Itaú", "$env:LOCALAPPDATA\Itaú", "$env:APPDATA\Itaú")
        $FoundExe = $null
        foreach ($p in $SearchPaths) {
            if (Test-Path $p) {
                $FoundExe = Get-ChildItem -Path $p -Recurse -Filter "*.exe" -ErrorAction SilentlyContinue | Select-Object -First 1
                if ($FoundExe) { break }
            }
        }
        if ($FoundExe) {
            $ItauReport += [PSCustomObject]@{ Path=$FoundExe.FullName; SHA256=(Get-FileHash $FoundExe.FullName -Algorithm SHA256).Hash; Version=[System.Diagnostics.FileVersionInfo]::GetVersionInfo($FoundExe.FullName).FileVersion; Modified=$FoundExe.LastWriteTimeUtc }
        }
        Get-AppxPackage -Name "*Itau*" -ErrorAction SilentlyContinue | ForEach-Object {
            $ItauReport += [PSCustomObject]@{ Path=$_.InstallLocation; SHA256=$null; Version=$_.Version; Modified=$_.InstallDate }
        }
        if ($ItauReport) { $ItauReport | Format-List | Out-File (Join-Path $BaseDir "02_ItauApp_Details.txt") -Encoding UTF8 } 
        else { "Nenhum artefato do App Itaú encontrado nos caminhos padrão." | Out-File (Join-Path $BaseDir "02_ItauApp_Details.txt") -Encoding UTF8 }
        
        $AllFiles = @()
        foreach ($p in $SearchPaths) { if (Test-Path $p) { $AllFiles += Get-ChildItem -Path $p -Recurse -Force -ErrorAction SilentlyContinue } }
        if ($AllFiles) { $AllFiles | Select-Object FullName, Length, LastWriteTime, Attributes | Export-Csv (Join-Path $BaseDir "02_ItauApp_Files.csv") -NoTypeInformation -Encoding UTF8 }
        else { "Nenhum arquivo encontrado." | Out-File (Join-Path $BaseDir "02_ItauApp_Files.csv") -Encoding UTF8 }
        $Summary.Add("✅ Itaú App: $(if($FoundExe){'Desktop Found'}else{'Store/None'})")
    }
    catch { Log-Step "ERRO 2/8" "Falha ao mapear app Itaú: $($_.Exception.Message)" -Warn; $Summary.Add("⚠️  Itaú App: Parcial") }
    #endregion

    #region 3. Logs Windows
    Log-Step "3/8" "Exportando logs (últimas $($HoursBack)h)..."
    try {
        $Since = (Get-Date).AddHours(-$HoursBack)
        Get-WinEvent -FilterHashtable @{LogName='Application'; StartTime=$Since} -MaxEvents 3000 -ErrorAction SilentlyContinue |
            Where-Object {$_.Message -match 'Itaú|itau|aplicativoitau'} |
            Select-Object TimeCreated, Id, ProviderName, LevelDisplayName, Message |
            Export-Csv (Join-Path $BaseDir "03_WinEvents_Itau.csv") -NoTypeInformation -Encoding UTF8

        Get-WinEvent -FilterHashtable @{LogName='Security'; StartTime=$Since; ID=4624,4625,4688,4104} -MaxEvents 1500 -ErrorAction SilentlyContinue |
            Select-Object TimeCreated, Id, Message |
            Export-Csv (Join-Path $BaseDir "03_WinEvents_Security.csv") -NoTypeInformation -Encoding UTF8
        $Summary.Add("✅ Windows Events: OK")
    }
    catch { Log-Step "ERRO 3/8" "Falha ao exportar logs: $($_.Exception.Message)" -Warn; $Summary.Add("⚠️  Windows Events: Parcial") }
    #endregion

    #region 4. Rede Avançada (Processos + Caminhos + Hashes)
    Log-Step "4/8" "Coletando conexões de rede com processos, caminhos e hashes SHA256..."
    try {
        # 4.1 Backup bruto do netstat (para referência forense cruzada)
        netstat -ano | Out-File (Join-Path $BaseDir "04_Netstat_Raw.txt") -Encoding UTF8

        # 4.2 Cache de hashes para evitar reprocessamento do mesmo executável
        $HashCache = @{}

        # 4.3 Coleta estruturada
        $NetConns = Get-NetTCPConnection -ErrorAction SilentlyContinue
        $NetworkReport = foreach ($conn in $NetConns) {
            $pid = $conn.OwningProcess
            $proc = $null
            try { $proc = Get-Process -Id $pid -ErrorAction Stop } catch { $proc = $null }

            $procName = if ($proc) { $proc.ProcessName } else { "Desconhecido(PID:$pid)" }
            $procPath = if ($proc -and $proc.Path) { $proc.Path } else { "N/A" }
            $procHash = "N/A"

            if ($procPath -ne "N/A" -and (Test-Path $procPath)) {
                if ($HashCache.ContainsKey($procPath)) {
                    $procHash = $HashCache[$procPath]
                } else {
                    try {
                        $procHash = (Get-FileHash -Path $procPath -Algorithm SHA256 -ErrorAction Stop).Hash
                        $HashCache[$procPath] = $procHash
                    } catch {
                        $procHash = "Erro_Acesso/Protegido"
                        $HashCache[$procPath] = $procHash
                    }
                }
            }

            [PSCustomObject]@{
                LocalAddress  = $conn.LocalAddress
                LocalPort     = $conn.LocalPort
                RemoteAddress = $conn.RemoteAddress
                RemotePort    = $conn.RemotePort
                State         = $conn.State
                PID           = $pid
                ProcessName   = $procName
                ProcessPath   = $procPath
                ProcessSHA256 = $procHash
            }
        }

        $NetworkReport | Export-Csv (Join-Path $BaseDir "04_Network_Connections_Enhanced.csv") -NoTypeInformation -Encoding UTF8
        $Summary.Add("✅ Network/Process/Hash: OK ($($NetworkReport.Count) conexões mapeadas)")
    }
    catch { Log-Step "ERRO 4/8" "Falha ao coletar rede avançada: $($_.Exception.Message)" -Warn; $Summary.Add("⚠️  Network: Parcial") }
    #endregion

    #region 5. Segurança Windows
    Log-Step "5/8" "Verificando recursos de proteção..."
    try {
        $Mp = Get-MpComputerStatus -ErrorAction SilentlyContinue
        $VBS = Get-CimInstance Win32_DeviceGuard -Namespace "root\Microsoft\Windows\DeviceGuard" -ErrorAction SilentlyContinue
        $SecureBoot = try { Confirm-SecureBootUEFI } catch { "Indisponível" }
        [PSCustomObject]@{
            Defender_RealTime = $Mp.RealTimeProtectionEnabled
            Defender_Behavior = $Mp.BehaviorMonitorEnabled
            Defender_Network  = $Mp.IoavProtectionEnabled
            VBS_Running       = ($VBS.SecurityServicesRunning -join ", ")
            VBS_Configured    = ($VBS.SecurityServicesConfigured -join ", ")
            SecureBoot        = $SecureBoot
            TPM_Present       = (Get-Tpm).TpmPresent
        } | Format-List | Out-File (Join-Path $BaseDir "05_SecurityFeatures.txt") -Encoding UTF8
        $Summary.Add("✅ Security Features: OK")
    }
    catch { Log-Step "ERRO 5/8" "Falha ao verificar segurança: $($_.Exception.Message)" -Warn; $Summary.Add("⚠️  Security Features: Parcial") }
    #endregion

    #region 6. Persistência
    Log-Step "6/8" "Analisando pontos de persistência..."
    try {
        $RunPaths = @(
            "HKLM:\Software\Microsoft\Windows\CurrentVersion\Run",
            "HKCU:\Software\Microsoft\Windows\CurrentVersion\Run",
            "HKLM:\Software\Microsoft\Windows\CurrentVersion\RunOnce",
            "HKCU:\Software\Microsoft\Windows\CurrentVersion\RunOnce"
        )
        $Persistence = @()
        foreach ($k in $RunPaths) { 
            if (Test-Path $k) { 
                $items = Get-ItemProperty -Path $k -ErrorAction SilentlyContinue
                if ($items) {
                    $Persistence += $items | Select-Object * -ExcludeProperty PSPath, PSParentPath, PSProvider | 
                        Add-Member -MemberType NoteProperty -Name "RegistryPath" -Value $k -PassThru
                }
            } 
        }
        if ($Persistence) { $Persistence | Export-Csv (Join-Path $BaseDir "06_Registry_RunKeys.csv") -NoTypeInformation -Encoding UTF8 }
        else { "Nenhuma chave de persistência encontrada" | Out-File (Join-Path $BaseDir "06_Registry_RunKeys.txt") -Encoding UTF8 }

        $TasksItau = Get-ScheduledTask -ErrorAction SilentlyContinue | Where-Object {$_.TaskName -match 'Itaú|itau'}
        if ($TasksItau) { $TasksItau | Select-Object TaskName, State, LastRunTime, NextRunTime | Export-Csv (Join-Path $BaseDir "06_Tasks_Itau.csv") -NoTypeInformation -Encoding UTF8 }
        else { "Nenhuma tarefa agendada relacionada ao Itaú encontrada" | Out-File (Join-Path $BaseDir "06_Tasks_Itau.txt") -Encoding UTF8 }
        
        $ServicesItau = Get-Service | Where-Object {$_.DisplayName -match 'Itaú|itau'}
        if ($ServicesItau) { $ServicesItau | Select-Object Name, DisplayName, Status, StartType | Export-Csv (Join-Path $BaseDir "06_Services_Itau.csv") -NoTypeInformation -Encoding UTF8 }
        else { "Nenhum serviço relacionado ao Itaú encontrado" | Out-File (Join-Path $BaseDir "06_Services_Itau.txt") -Encoding UTF8 }
        
        $Summary.Add("✅ Persistence/Run/Tasks/Services: OK")
    }
    catch { Log-Step "ERRO 6/8" "Falha ao analisar persistência: $($_.Exception.Message)" -Warn; "Erro na coleta de persistência: $($_.Exception.Message)" | Out-File (Join-Path $BaseDir "06_ERROR.txt") -Encoding UTF8; $Summary.Add("⚠️  Persistence: Parcial (verificar 06_ERROR.txt)") }
    #endregion

    #region 7. Relatório
    Log-Step "7/8" "Gerando resumo executivo..."
    try {
        $Summary | Out-File (Join-Path $BaseDir "99_Summary.txt") -Encoding UTF8
        $Readme = @"
========================================
 RELATÓRIO DE COLETA - BANCO ITAÚ
 Máquina: $env:COMPUTERNAME
 Usuário: $env:USERNAME
 Data/Hora: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')
========================================
$(Get-Content (Join-Path $BaseDir "99_Summary.txt") -Raw)
========================================
 PRÓXIMOS PASSOS:
 1. Valide hash do exe com versão oficial do Itaú
 2. Correlacione timeline de acesso × logs do banco
 3. Envie pacote via canal seguro + senha separada
 4. NÃO reutilize credenciais antes de formatação (se comprometido)
========================================
"@
        $Readme | Out-File (Join-Path $BaseDir "99_README.txt") -Encoding UTF8
    }
    catch { Log-Step "ERRO 7/8" "Falha ao gerar relatório: $($_.Exception.Message)" -Warn }
    #endregion

    #region 8. Compactação
    Log-Step "8/8" "Compactando evidências..."
    try {
        $ZipPath = "$BaseDir.zip"
        Compress-Archive -Path "$BaseDir\*" -DestinationPath $ZipPath -Force -ErrorAction Stop
        $ZipHash = (Get-FileHash $ZipPath -Algorithm SHA256).Hash
        Log-Step "FINAL" "Coleta concluída." -Success
        Write-Host "`n ZIP: $ZipPath" -ForegroundColor Magenta
        Write-Host "🔐 SHA256: $ZipHash" -ForegroundColor Yellow
        Write-Host "⚠️  ENVIE A SENHA POR CANAL SEPARADO. NUNCA INCLUA CREDENCIAIS NOS ANEXOS." -ForegroundColor Red

        if (-not $RetainUnpacked) { Remove-Item -Path $BaseDir -Recurse -Force }
    }
    catch { Log-Step "ERRO 8/8" "Falha ao compactar: $($_.Exception.Message)" -Error; Write-Host "`n️  Os arquivos permanecem em: $BaseDir" -ForegroundColor Yellow }
    #endregion
}
catch {
    Log-Step "ERRO CRÍTICO" $_.Exception.Message -Error
    Write-Host "`n❌ Falha crítica. Verifique permissões de administrador e políticas de grupo." -ForegroundColor Red
    exit 1
}