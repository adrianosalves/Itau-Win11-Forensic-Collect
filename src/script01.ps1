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
    Versão  : 1.1.0 (Prefetch + MRU + Drivers + Processos Suspeitos + RI)
    Data    : 2026-05-05
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
if (-not (Test-Path $BaseDir)) {
    New-Item -Path $BaseDir -ItemType Directory -Force | Out-Null
}

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
    Log-Step "1/11" "Coletando dados do sistema..."
    try {
        systeminfo | Out-File (Join-Path $BaseDir "01_SystemInfo.txt") -Encoding UTF8
        Get-ComputerInfo | Select-Object WindowsProductName, OsVersion, OsBuildNumber, CsName, CsDomain, OsArchitecture |
            Format-Table | Out-File (Join-Path $BaseDir "01_SysBrief.txt") -Encoding UTF8
        $Summary.Add("✅ System Info: OK")
    }
    catch { Log-Step "ERRO 1/8" "Falha ao coletar systeminfo: $($_.Exception.Message)" -Warn; $Summary.Add("⚠️  System Info: Parcial") }
    #endregion

    #region 2. App Itaú
    Log-Step "2/11" "Mapeando artefatos do App Itaú..."
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
    Log-Step "3/11" "Exportando logs (últimas $($HoursBack)h)..."
    try {
        $Since = (Get-Date).AddHours(-$HoursBack)
        Get-WinEvent -FilterHashtable @{LogName='Application'; StartTime=$Since} -MaxEvents 3000 -ErrorAction SilentlyContinue |
            Where-Object {$_.Message -match 'Itaú|itau|aplicativoitau'} |
            Select-Object TimeCreated, Id, ProviderName, LevelDisplayName, Message |
            Export-Csv (Join-Path $BaseDir "03_WinEvents_Itau.csv") -NoTypeInformation -Encoding UTF8

        # Eventos Security expandidos
        Get-WinEvent -FilterHashtable @{LogName='Security'; StartTime=$Since; ID=4624,4625,4627,4672,4688,4104,4656,4663,1102} -MaxEvents 2000 -ErrorAction SilentlyContinue |
            Select-Object TimeCreated, Id, Message |
            Export-Csv (Join-Path $BaseDir "03_WinEvents_Security.csv") -NoTypeInformation -Encoding UTF8

        # Eventos PowerShell
        Get-WinEvent -FilterHashtable @{LogName='Microsoft-Windows-PowerShell/Operational'; StartTime=$Since; ID=4103,4104} -MaxEvents 1000 -ErrorAction SilentlyContinue |
            Select-Object TimeCreated, Id, Message |
            Export-Csv (Join-Path $BaseDir "03_WinEvents_PowerShell.csv") -NoTypeInformation -Encoding UTF8
        $Summary.Add("✅ Windows Events: OK (Security + PowerShell)")
    }
    catch { Log-Step "ERRO 3/11" "Falha ao exportar logs: $($_.Exception.Message)" -Warn; $Summary.Add("⚠️  Windows Events: Parcial") }
    #endregion

    #region 4. Rede Avançada (Processos + Caminhos + Hashes)
    Log-Step "4/11" "Coletando conexões de rede com processos, caminhos e hashes SHA256..."
    try {
        # 4.1 Backup bruto do netstat (para referência forense cruzada)
        netstat -ano | Out-File (Join-Path $BaseDir "04_Netstat_Raw.txt") -Encoding UTF8

        # 4.2 Cache de hashes para evitar reprocessamento do mesmo executável
        $HashCache = @{}

        # 4.3 Coleta estruturada
        $NetConns = Get-NetTCPConnection -ErrorAction SilentlyContinue
        $NetworkReport = foreach ($conn in $NetConns) {
            $procId = $conn.OwningProcess
            $proc = $null
            try { $proc = Get-Process -Id $procId -ErrorAction Stop } catch { $proc = $null }

            $procName = if ($proc) { $proc.ProcessName } else { "Desconhecido(PID:$procId)" }
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
                PID           = $procId
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
    Log-Step "5/11" "Verificando recursos de proteção..."
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
    Log-Step "6/11" "Analisando pontos de persistência..."
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
                    $props = $items.PSObject.Properties | Where-Object { $_.Name -notmatch '^PS' }
                    foreach ($prop in $props) {
                        $Persistence += [PSCustomObject]@{
                            RegistryPath = $k
                            Name        = $prop.Name
                            Value       = $prop.Value
                            Type        = if ($prop.TypeNameOfValue) { $prop.TypeNameOfValue.Split('.')[-1] } else { "String" }
                        }
                    }
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
    catch { Log-Step "ERRO 6/11" "Falha ao analisar persistência: $($_.Exception.Message)" -Warn; "Erro na coleta de persistência: $($_.Exception.Message)" | Out-File (Join-Path $BaseDir "06_ERROR.txt") -Encoding UTF8; $Summary.Add("⚠️  Persistence: Parcial (verificar 06_ERROR.txt)") }
    #endregion

    #region 7. Prefetch
    Log-Step "7/11" "Analisando artefatos Prefetch..."
    try {
        $PrefetchPath = "$env:SystemRoot\Prefetch"
        if (Test-Path $PrefetchPath) {
            $PrefetchFiles = Get-ChildItem -Path $PrefetchPath -Filter "*.pf" -ErrorAction SilentlyContinue |
                Select-Object Name, LastWriteTime, Length |
                Sort-Object LastWriteTime -Descending | Select-Object -First 100
            $PrefetchFiles | Export-Csv (Join-Path $BaseDir "07_Prefetch.csv") -NoTypeInformation -Encoding UTF8
            $Summary.Add("✅ Prefetch: $($PrefetchFiles.Count) arquivos")
        } else {
            "Prefetch não disponível" | Out-File (Join-Path $BaseDir "07_Prefetch.txt") -Encoding UTF8
            $Summary.Add("⚠️  Prefetch: Indisponível")
        }
    }
    catch { Log-Step "ERRO 7/11" "Falha ao analisar Prefetch: $($_.Exception.Message)" -Warn; $Summary.Add("⚠️  Prefetch: Parcial") }
    #endregion

    #region 8. MRU e JumpList
    Log-Step "8/11" "Coletando MRU e JumpList..."
    try {
        $MruReport = @()

        # JumpList do App Itaú
        $JumpListPaths = @(
            "$env:APPDATA\Microsoft\Windows\Recent\AutomaticDestinations",
            "$env:APPDATA\Microsoft\Windows\Recent\CustomDestinations"
        )
        foreach ($jl in $JumpListPaths) {
            if (Test-Path $jl) {
                $jlFiles = Get-ChildItem -Path $jl -Filter "*.automaticDestinations-ms" -ErrorAction SilentlyContinue
                foreach ($f in $jlFiles) {
                    $MruReport += [PSCustomObject]@{ Type="JumpList"; Path=$f.FullName; Modified=$f.LastWriteTime; Size=$f.Length }
                }
            }
        }

        # Recent Docs
        $RecentPath = "$env:APPDATA\Microsoft\Windows\Recent"
        if (Test-Path $RecentPath) {
            $RecentDocs = Get-ChildItem -Path $RecentPath -Filter "*Itau*" -ErrorAction SilentlyContinue |
                Select-Object Name, LastWriteTime, Length | Sort-Object LastWriteTime -Descending
            foreach ($rd in $RecentDocs) {
                $MruReport += [PSCustomObject]@{ Type="RecentDoc"; Path=$rd.Name; Modified=$rd.LastWriteTime; Size=$rd.Length }
            }
        }

        if ($MruReport) {
            $MruReport | Export-Csv (Join-Path $BaseDir "08_MRU_JumpList.csv") -NoTypeInformation -Encoding UTF8
            $Summary.Add("✅ MRU/JumpList: $($MruReport.Count) itens")
        } else {
            "Nenhum MRU/JumpList relacionado encontrado" | Out-File (Join-Path $BaseDir "08_MRU_JumpList.txt") -Encoding UTF8
            $Summary.Add("⚠️  MRU/JumpList: Nenhum achado")
        }
    }
    catch { Log-Step "ERRO 8/11" "Falha ao coletar MRU: $($_.Exception.Message)" -Warn; $Summary.Add("⚠️  MRU: Parcial") }
    #endregion

    #region 9. Drivers Carregados
    Log-Step "9/11" "Analisando drivers carregados..."
    try {
        $Drivers = Get-Process -Module -ErrorAction SilentlyContinue | Where-Object { $_.ModuleName -match '\.sys$' }
        $DriverReport = @()
        $DriverHashCache = @{}
        foreach ($drv in $Drivers) {
            $path = if ($drv.FileName) { $drv.FileName } else { "N/A" }
            $hash = "N/A"
            if ($path -ne "N/A" -and (Test-Path $path)) {
                if ($DriverHashCache.ContainsKey($path)) {
                    $hash = $DriverHashCache[$path]
                } else {
                    try { $hash = (Get-FileHash -Path $path -Algorithm SHA256 -ErrorAction SilentlyContinue).Hash } catch { }
                    $DriverHashCache[$path] = $hash
                }
            }
            $sig = $null
            try { $sig = Get-AuthenticodeSignature -FilePath $path -ErrorAction SilentlyContinue } catch { }
            $DriverReport += [PSCustomObject]@{
                ModuleName = $drv.ModuleName
                FilePath  = $path
                SHA256    = $hash
                Signed    = if ($sig.Status) { $sig.Status.ToString() } else { "Unknown" }
            }
        }
        $DriverReport | Export-Csv (Join-Path $BaseDir "09_Drivers.csv") -NoTypeInformation -Encoding UTF8
        $Unsigned = $DriverReport | Where-Object { $_.Signed -ne "Valid" }
        $Summary.Add("✅ Drivers: $($DriverReport.Count) carregados, $($Unsigned.Count) não assinados")
    }
    catch { Log-Step "ERRO 9/11" "Falha ao analisar drivers: $($_.Exception.Message)" -Warn; $Summary.Add("⚠️  Drivers: Parcial") }
    #endregion

    #region 10. Processos Suspeitos
    Log-Step "10/11" "Detectando processos suspeitos..."
    try {
        $ProcReport = @()
        $AllProcs = Get-Process -ErrorAction SilentlyContinue
        $SuspiciousPaths = @('\Temp\', '\Downloads\', '\AppData\Local\Temp\', '$env:TEMP')
        $SuspiciousPPIDs = @(0, 4) # System e Idle

        foreach ($p in $AllProcs) {
            $suspicious = $false
            $reasons = @()

            # Verificar caminho anômalo
            if ($p.Path) {
                foreach ($sp in $SuspiciousPaths) {
                    if ($p.Path -match [regex]::Escape($sp)) {
                        $suspicious = $true
                        $reasons += "Caminho_anômalo"
                        break
                    }
                }
            }

            # Verificar PPID suspeito
            try {
                $parent = Get-CimInstance Win32_Process -Filter "ProcessId = $($p.Id)" -ErrorAction SilentlyContinue
                if ($parent -and $parent.ParentProcessId -in $SuspiciousPPIDs) {
                    $suspicious = $true
                    $reasons += "PPID_suspeito"
                }
            } catch { }

            if ($suspicious) {
                $ProcReport += [PSCustomObject]@{
                    PID        = $p.Id
                    Name       = $p.ProcessName
                    Path       = $p.Path
                    PPID       = if ($parent) { $parent.ParentProcessId } else { "N/A" }
                    Reasons    = ($reasons -join ", ")
                    StartTime  = $p.StartTime
                }
            }
        }

        if ($ProcReport) {
            $ProcReport | Export-Csv (Join-Path $BaseDir "10_SuspiciousProcesses.csv") -NoTypeInformation -Encoding UTF8
            $Summary.Add("⚠️  Processos Suspeitos: $($ProcReport.Count) detectados")
        } else {
            "Nenhum processo suspeito detectado" | Out-File (Join-Path $BaseDir "10_SuspiciousProcesses.txt") -Encoding UTF8
            $Summary.Add("✅ Processos Suspeitos: Nenhum achado")
        }
    }
    catch { Log-Step "ERRO 10/11" "Falha ao detectar processos: $($_.Exception.Message)" -Warn; $Summary.Add("⚠️  Processos: Parcial") }
    #endregion

    #region 11. Resposta a Incidentes (Triagem)
    Log-Step "11/11" "Triagem de indicadores de comprometimento..."
    try {
        $IRReport = @()

        # Conexões suspeitas (portas incomuns ou sinais de C2)
        $SuspiciousPorts = @(4444, 5555, 6666, 7777, 8888, 31337, 1337)
        $NetTCP = Get-NetTCPConnection -State Listen -ErrorAction SilentlyContinue
        foreach ($conn in $NetTCP) {
            if ($conn.LocalPort -in $SuspiciousPorts -or $conn.LocalPort -gt 10000) {
                $proc = Get-Process -Id $conn.OwningProcess -ErrorAction SilentlyContinue
                $IRReport += [PSCustomObject]@{
                    Type     = "Porta_Anômala"
                    Detail   = "Porta $($conn.LocalPort) em listen"
                    Process  = if ($proc) { $proc.ProcessName } else { "PID:$($conn.OwningProcess)" }
                    Severity = "Alta"
                }
            }
        }

        # DNS queries suspeitas (simplificado - apenas listar)
        $DnsQueries = Get-DnsClientCache -ErrorAction SilentlyContinue | Select-Object -First 50
        $SuspiciousDomains = $DnsQueries | Where-Object { $_.Entry -match '(itau|bank|secure|login).*\.exe|\.xyz|\.top|\.click' }
        foreach ($d in $SuspiciousDomains) {
            $IRReport += [PSCustomObject]@{
                Type     = "DNS_Suspeito"
                Detail   = $d.Entry
                Process  = "N/A"
                Severity = "Média"
            }
        }

        if ($IRReport) {
            $IRReport | Export-Csv (Join-Path $BaseDir "11_IR_Triage.csv") -NoTypeInformation -Encoding UTF8
            $Summary.Add("⚠️  Triagem IR: $($IRReport.Count) indicadores")
        } else {
            "Nenhum indicador de comprometimento detectado" | Out-File (Join-Path $BaseDir "11_IR_Triage.txt") -Encoding UTF8
            $Summary.Add("✅ Triagem IR: Limpo")
        }
    }
    catch { Log-Step "ERRO 11/11" "Falha na triagem IR: $($_.Exception.Message)" -Warn; $Summary.Add("⚠️  Triagem IR: Parcial") }
    #endregion

    #region 12. Relatório
    Log-Step "12/11" "Gerando resumo executivo..."
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
    catch { Log-Step "ERRO 12/11" "Falha ao gerar relatório: $($_.Exception.Message)" -Warn }
    #endregion

    #region 13. Compactação
    Log-Step "13/11" "Compactando evidências..."
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
    catch { Log-Step "ERRO 13/11" "Falha ao compactar: $($_.Exception.Message)" -Error; Write-Host "`n️  Os arquivos permanecem em: $BaseDir" -ForegroundColor Yellow }
    #endregion
}
catch {
    Log-Step "ERRO CRÍTICO" $_.Exception.Message -Error
    Write-Host "`n❌ Falha crítica. Verifique permissões de administrador e políticas de grupo." -ForegroundColor Red
    exit 1
}