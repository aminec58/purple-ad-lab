# config/ad/setup-vulns.ps1 — Phase 3 : vulnérabilisation VOLONTAIRE de purplelab.local
# ⚠️ Lab isolé uniquement. À exécuter APRÈS validation de la télémétrie,
#    puis snapshot clean-baseline-<date> sur chaque VM.
# Mots de passe volontairement faibles = documentés (but du lab).
Import-Module ActiveDirectory
$dom = Get-ADDomain
$dn  = $dom.DistinguishedName
$ou  = "OU=Lab,$dn"

# --- OU ---
New-ADOrganizationalUnit -Name Lab -Path $dn -ProtectedFromAccidentalDeletion $false
"Utilisateurs","Services","Groupes" | ForEach-Object {
  New-ADOrganizationalUnit -Name $_ -Path $ou -ProtectedFromAccidentalDeletion $false }

function New-LabUser($sam, $nom, $mdp, $sousOU) {
  New-ADUser -Name $nom -SamAccountName $sam -UserPrincipalName "$sam@purplelab.local" `
    -Path "OU=$sousOU,$ou" -Enabled $true -PasswordNeverExpires $true `
    -AccountPassword (ConvertTo-SecureString $mdp -AsPlainText -Force)
}
function New-StrongPwd { -join ((33..126) | Get-Random -Count 20 | ForEach-Object {[char]$_}) + "aA1!" }

# --- Utilisateurs ---
New-LabUser j.dupont  "Julie Dupont"   "Automne2026!"   Utilisateurs   # spraying
New-LabUser m.martin  "Marc Martin"    "Automne2026!"   Utilisateurs   # spraying
New-LabUser l.bernard "Lucie Bernard"  (New-StrongPwd)  Utilisateurs
New-LabUser s.petit   "Sami Petit"     (New-StrongPwd)  Utilisateurs
New-LabUser a.roux    "Alex Roux"      "Password1"      Utilisateurs   # AS-REP
New-LabUser svc-sql   "svc-sql"        "P@ssw0rd"       Services       # Kerberoasting
New-LabUser svc-web   "svc-web"        "Welcome1"       Services       # délégation

# --- 1. Pas de verrouillage de compte (spraying illimité) ---
Set-ADDefaultDomainPasswordPolicy -Identity $dom.DNSRoot -LockoutThreshold 0

# --- 2. AS-REP roasting : pré-auth Kerberos désactivée ---
Set-ADAccountControl a.roux -DoesNotRequirePreAuth $true

# --- 3. Kerberoasting : SPN + RC4 forcé (hash plus rapide à casser) ---
Set-ADUser svc-sql -ServicePrincipalNames @{Add='MSSQLSvc/sql01.purplelab.local:1433'} `
  -Replace @{'msDS-SupportedEncryptionTypes'=4}

# --- 4. Délégation contrainte + transition de protocole vers le DC ---
Set-ADUser svc-web -ServicePrincipalNames @{Add='HTTP/web01.purplelab.local'} `
  -Add @{'msDS-AllowedToDelegateTo'=@('cifs/DC01.purplelab.local','cifs/DC01')}
Set-ADAccountControl svc-web -TrustedToAuthForDelegation $true

# --- 5. ACL abusive : Helpdesk a GenericAll sur svc-web ---
New-ADGroup -Name Helpdesk -GroupScope Global -Path "OU=Groupes,$ou"
Add-ADGroupMember Helpdesk -Members j.dupont
dsacls (Get-ADUser svc-web).DistinguishedName /G "PURPLELAB\Helpdesk:GA" | Out-Null

Write-Host "[+] Faiblesses posées." -ForegroundColor Green
