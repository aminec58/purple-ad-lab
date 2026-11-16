# Durcissement Active Directory

Ce fichier regroupe les durcissements du lab, scénario par scénario. Les quatre premiers ont été appliqués puis vérifiés au rejeu : la détection se déclenche et l'attaque est bloquée ou limitée. Le détail de chaque rejeu, avec les captures, est dans les docs de [`docs/03-scenarios/`](../docs/03-scenarios/). Les faiblesses de départ sont posées par [`config/ad/setup-vulns.ps1`](../config/ad/setup-vulns.ps1).

Entre deux scénarios, je reviens à l'AD vulnérable, puisque chaque scénario a besoin de sa faiblesse. Ces mesures ne sont donc pas toutes en place en même temps aujourd'hui. Elles seront reposées ensemble dans l'état durci final.

| # | Scénario | Durcissement appliqué | Effet au rejeu |
|---|---|---|---|
| 1 | Password spraying | Verrouillage 5 essais / 30 min, longueur 14 et complexité, double réinitialisation des comptes compromis | 5 échecs sur 5, l'ancien mot de passe est refusé |
| 2 | AS-REP roasting | Pré-authentification rétablie, double réinitialisation, compte leurre | Seul le leurre répond, `a.roux:Password1` refusé |
| 3 | Kerberoasting | AES seul et mot de passe aléatoire de 32 caractères sur les comptes à SPN, compte leurre à SPN | Tickets en AES, environ 240 fois plus lents à casser, anciens mots de passe refusés |
| 4 | Pass-the-Hash | Mot de passe administrateur local unique par poste, `LocalAccountTokenFilterPolicy` à 0 | L'ancien condensat ne donne plus accès à CLIENT02 |
| 5 | Chemin vers Domain Admin | Prévu : nettoyage des ACL, délégation, tiering | Pas encore joué |

## Scénario 1 : politique de mots de passe et verrouillage

Le domaine n'avait aucun verrouillage (`LockoutThreshold` à 0) et acceptait des mots de passe de 7 caractères. Sur DC01 :

```powershell
Set-ADDefaultDomainPasswordPolicy -Identity purplelab.local `
  -LockoutThreshold 5 -LockoutDuration 00:30:00 -LockoutObservationWindow 00:30:00 `
  -MinPasswordLength 14 -ComplexityEnabled $true
```

Le verrouillage ne fait que ralentir un spraying lent. Ce qui bloque vraiment, c'est de changer les mots de passe trouvés. J'ai réinitialisé `j.dupont` et `m.martin` avec un mot de passe aléatoire, deux fois de suite : après une seule réinitialisation, l'ancien mot de passe reste accepté en NTLM pendant un moment (tolérance sur le mot de passe précédent). La double réinitialisation est reprise dans les scénarios suivants.

Une fois la politique durcie, `Set-ADAccountPassword` refuse tout mot de passe de moins de 14 caractères, y compris pour les comptes de service.

## Scénario 2 : pré-authentification Kerberos

`a.roux` avait l'option « ne pas demander la pré-authentification Kerberos ». Sur DC01 :

```powershell
Set-ADAccountControl a.roux -DoesNotRequirePreAuth $false

1..2 | % { $p = -join ((33..126) | Get-Random -Count 24 | % {[char]$_})
  Set-ADAccountPassword a.roux -Reset -NewPassword (ConvertTo-SecureString $p -AsPlainText -Force) }
```

Corriger le compte supprime l'événement que la règle Wazuh surveille. Pour garder une détection, j'ai créé un compte leurre, `svc-legacy-backup`, qui conserve l'option vulnérable avec un mot de passe aléatoire de 32 caractères que personne ne connaît. Toute demande de ticket pour ce compte déclenche la règle `100121` au niveau 15.

```powershell
$h = -join ((33..126) | Get-Random -Count 32 | % {[char]$_})
New-ADUser svc-legacy-backup -Path "OU=Services,OU=Lab,DC=purplelab,DC=local" `
  -Description "Sauvegarde legacy" -Enabled $true `
  -AccountPassword (ConvertTo-SecureString $h -AsPlainText -Force)
Set-ADAccountControl svc-legacy-backup -DoesNotRequirePreAuth $true
```

Pour vérifier qu'il ne reste que le leurre :

```powershell
Get-ADUser -Filter 'DoesNotRequirePreAuth -eq $true' | Select-Object SamAccountName
```

## Scénario 3 : comptes de service à SPN

`svc-sql` était explicitement en RC4. `svc-web` n'avait aucun type de chiffrement déclaré, et le DC lui délivrait quand même du RC4. Il faut donc poser AES sur tous les comptes à SPN, pas seulement sur ceux marqués RC4. Sur DC01 :

```powershell
function New-RandPwd { -join ((33..126) | Get-Random -Count 32 | ForEach-Object {[char]$_}) }
foreach ($u in 'svc-sql','svc-web') {
  Set-ADUser $u -KerberosEncryptionType AES128,AES256
  1..2 | ForEach-Object { Set-ADAccountPassword $u -Reset -NewPassword (ConvertTo-SecureString (New-RandPwd) -AsPlainText -Force) }
}
```

Un ticket AES reste cassable hors ligne. Le passage en AES ralentit l'attaquant, et c'est le mot de passe aléatoire de 32 caractères qui rend le cassage irréaliste.

Même logique de leurre qu'au scénario 2 : `svc-mssql-legacy` porte un SPN crédible, reste en RC4 et n'est utilisé par rien. La règle `100132` alerte sur toute demande de ticket le concernant, quel que soit le chiffrement.

```powershell
New-ADUser -Name "svc-mssql-legacy" -SamAccountName "svc-mssql-legacy" -Path "OU=Services,OU=Lab,DC=purplelab,DC=local" -Description "Instance SQL legacy (sauvegardes)" -AccountPassword (ConvertTo-SecureString (New-RandPwd) -AsPlainText -Force) -Enabled $true -PasswordNeverExpires $true
Set-ADUser svc-mssql-legacy -ServicePrincipalNames @{Add="MSSQLSvc/sqlbak01.purplelab.local:1433"} -KerberosEncryptionType RC4
```

La mesure de référence serait un gMSA, dont le mot de passe est géré et renouvelé par AD. Je ne l'ai pas déployé, faute de vrai service SQL dans le lab.

## Scénario 4 : comptes administrateurs locaux

Ce durcissement se fait sur les postes, pas dans l'annuaire. L'attaque reposait sur le compte administrateur local `amin`, identique sur CLIENT01 et CLIENT02 : le condensat lu dans le SAM du premier ouvrait le second.

La mesure qui casse la technique est un mot de passe différent sur chaque poste. Je l'ai simulé à la main en changeant celui de CLIENT02 (`net user amin <nouveau mot de passe>`). Pour un compte local, une seule modification suffit, la tolérance NTLM du scénario 1 ne concerne que les comptes du domaine. En production, c'est le rôle de LAPS, qui génère et renouvelle un mot de passe par machine.

Deuxième mesure, remettre le filtrage des jetons distants à sa valeur par défaut. Avec la clé à 0, un compte local autre que l'Administrateur intégré ne peut pas exécuter de commande à distance, même avec le bon condensat. Dans le lab elle avait été passée à 1 pour rendre l'attaque possible.

```powershell
reg add HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System /v LocalAccountTokenFilterPolicy /t REG_DWORD /d 0 /f
```

Enfin, rien à faire pour LSASS : Windows 11 protège sa mémoire par défaut et `sekurlsa::logonpasswords` a échoué. La lecture du SAM, elle, reste possible pour un administrateur local, d'où l'importance du mot de passe unique.

## Scénario 5 : mesures prévues

Le scénario n'est pas encore joué, ces mesures ne sont donc ni appliquées ni vérifiées. Elles répondent aux deux faiblesses restantes de `setup-vulns.ps1` : le groupe `Helpdesk` a `GenericAll` sur `svc-web`, et `svc-web` a une délégation contrainte avec transition de protocole vers `cifs/DC01`.

```powershell
# Retirer le droit du groupe Helpdesk sur svc-web
dsacls (Get-ADUser svc-web).DistinguishedName /R "PURPLELAB\Helpdesk"

# Supprimer la délégation de svc-web vers le DC
Set-ADAccountControl svc-web -TrustedToAuthForDelegation $false
Set-ADUser svc-web -Clear 'msDS-AllowedToDelegateTo'
```

À compléter après le scénario : vérification avec BloodHound qu'aucun chemin ne subsiste, comptes à privilèges marqués comme non délégables, et séparation des comptes d'administration par niveau.
