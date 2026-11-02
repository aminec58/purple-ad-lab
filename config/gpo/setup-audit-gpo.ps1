# config/gpo/setup-audit-gpo.ps1 - S09
# Cree la GPO "PURPLELAB - Audit avance" et la lie au domaine + OU Domain Controllers.
# A executer sur DC01 en admin du domaine. Idempotent (relancable).
#Requires -Modules GroupPolicy, ActiveDirectory
$ErrorActionPreference = 'Stop'

$GpoName = 'PURPLELAB - Audit avance'
$Domain  = Get-ADDomain
$DomDN   = $Domain.DistinguishedName
$DcOU    = $Domain.DomainControllersContainer

# 1. GPO
$gpo = Get-GPO -Name $GpoName -ErrorAction SilentlyContinue
if (-not $gpo) { $gpo = New-GPO -Name $GpoName -Comment 'S09 - audit avance, cmdline 4688, PowerShell logging' }
$guid = "{$($gpo.Id)}".ToUpper()

# 2. Parametres registre (Registry.pol)
$dw = @(
  # Forcer les sous-categories d'audit (ignore l'audit "legacy")
  @('HKLM\System\CurrentControlSet\Control\Lsa', 'SCENoApplyLegacyAuditPolicy', 1),
  # Ligne de commande dans 4688
  @('HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\System\Audit', 'ProcessCreationIncludeCmdLine_Enabled', 1),
  # PowerShell : Script Block (4104) + Module Logging (4103)
  @('HKLM\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging', 'EnableScriptBlockLogging', 1),
  @('HKLM\Software\Policies\Microsoft\Windows\PowerShell\ModuleLogging', 'EnableModuleLogging', 1),
  # Journal Security : 512 Mo (valeur en Ko)
  @('HKLM\Software\Policies\Microsoft\Windows\EventLog\Security', 'MaxSize', 524288)
)
foreach ($r in $dw) {
  Set-GPRegistryValue -Guid $gpo.Id -Key $r[0] -ValueName $r[1] -Type DWord -Value $r[2] | Out-Null
}
Set-GPRegistryValue -Guid $gpo.Id -Key 'HKLM\Software\Policies\Microsoft\Windows\PowerShell\ModuleLogging\ModuleNames' `
  -ValueName '*' -Type String -Value '*' | Out-Null

# 3. Audit avance (audit.csv) - le GUID fait foi, independant de la langue de l'OS
$sub = @(
  # Nom                                     GUID       1=Reussite 2=Echec 3=les deux   # events
  @('Audit Credential Validation',          '923f', 3),   # 4776 (NTLM : spraying, PtH)
  @('Audit Kerberos Authentication Service','9242', 3),   # 4768, 4771
  @('Audit Kerberos Service Ticket Operations','9240', 3),# 4769
  @('Audit Logon',                          '9215', 3),   # 4624, 4625
  @('Audit Logoff',                         '9216', 1),   # 4634
  @('Audit Account Lockout',                '9217', 1),   # 4625 (verrouille)
  @('Audit Special Logon',                  '921b', 1),   # 4672
  @('Audit Process Creation',               '922b', 1),   # 4688
  @('Audit User Account Management',        '9235', 3),   # 4720, 4738, 4740...
  @('Audit Security Group Management',      '9237', 3),   # 4728, 4732, 4756
  @('Audit Directory Service Changes',      '923c', 1)    # 5136 (ACL/attributs, scen. 5)
)
$label = @{ 1 = 'Success'; 2 = 'Failure'; 3 = 'Success and Failure' }
$csv = @('Machine Name,Policy Target,Subcategory,Subcategory GUID,Inclusion Setting,Exclusion Setting,Setting Value')
foreach ($s in $sub) {
  $csv += ",System,$($s[0]),{0cce$($s[1])-69ae-11d9-bed3-505054503030},$($label[$s[2]]),,$($s[2])"
}
$gpoPath  = "C:\Windows\SYSVOL\domain\Policies\$guid"
$auditDir = "$gpoPath\Machine\Microsoft\Windows NT\Audit"
New-Item -ItemType Directory -Path $auditDir -Force | Out-Null
$csv | Set-Content -Path "$auditDir\audit.csv" -Encoding ASCII

# 4. Declarer les CSE (Registry + Audit avance) et incrementer la version machine
$gpcDN = "CN=$guid,CN=Policies,CN=System,$DomDN"
$ext   = '[{35378EAC-683F-11D2-A89A-00C04FBBCFA2}{D02B1F72-3407-48AE-BA88-E8213C6761F1}]' +
         '[{F3CCC681-B74C-4060-9F26-CD84525DCA2A}{0F3F3735-573D-9804-99E4-AB2A69BA5FD4}]'
$ver   = [int](Get-ADObject $gpcDN -Properties versionNumber).versionNumber + 1
Set-ADObject $gpcDN -Replace @{ gPCMachineExtensionNames = $ext; versionNumber = $ver }
(Get-Content "$gpoPath\GPT.INI") -replace '^Version=\d+', "Version=$ver" |
  Set-Content "$gpoPath\GPT.INI" -Encoding ASCII

# 5. Liens : racine du domaine (clients, a la jonction) + OU DC en ordre 1 (avant Default DC Policy)
foreach ($t in @($DomDN, $DcOU)) {
  if (-not ((Get-GPInheritance -Target $t).GpoLinks | Where-Object DisplayName -eq $GpoName)) {
    New-GPLink -Guid $gpo.Id -Target $t -LinkEnabled Yes | Out-Null
  }
}
Set-GPLink -Guid $gpo.Id -Target $DcOU -Order 1 | Out-Null

gpupdate /force | Out-Null
Write-Host "OK - GPO '$GpoName' $guid (version $ver) liee a $DomDN et $DcOU" -ForegroundColor Green
