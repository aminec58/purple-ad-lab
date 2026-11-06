# Architecture  

## Réseau
- Hyperviseur : VMware Workstation Pro
- Segment : **host-only** isolé, `10.10.10.0/24`
- **DHCP VMware désactivé** (le DC assure DNS ; adressage statique)
- Domaine : `purplelab.local`

## Machines

| VM       | Rôle                                    | OS                  | IP           |
|----------|-----------------------------------------|---------------------|--------------|
| DC       | AD DS + DNS (vulnérable)                | Windows Server 2022 | 10.10.10.10  |
| CLIENT01 | Poste joint                             | Windows 11 Pro      | 10.10.10.21  |
| CLIENT02 | Poste joint                             | Windows 11 Pro      | 10.10.10.22  |
| KALI     | Attaque                                 | Kali Linux          | 10.10.10.50  |
| SIEM     | Wazuh + Velociraptor                    | Ubuntu Server       | 10.10.10.100 |

## Faiblesses introduites sur le DC (matière des 5 scénarios)

> ⚠️ **Rien n'est posé pour l'instant.** Ces faiblesses se créent en **phase 3 (vulnérabilisation)**, *après* la mise en place **et la vérification** de la télémétrie (phase 2). Raison : la baseline reste propre, et la **création** des faiblesses doit elle-même être visible dans les logs (événements horodatés sur une télémétrie déjà validée).
>
> Les mots de passe sont **volontairement faibles** — c'est l'objet du lab, documenté comme tel. Les comptes, SPN et valeurs ci-dessous **reflètent le script de phase 3 [`config/ad/setup-vulns.ps1`](../config/ad/setup-vulns.ps1)** déjà présent dans le dépôt (extraits cités, non exécutés ici). Aucun autre secret (mot de passe Administrateur/DSRM, clés d'enrôlement) n'est écrit dans le dépôt — cf. `.gitignore`.

Domaine `purplelab.local` — DC `DC01` = `10.10.10.10`. Les objets sont créés dans `OU=Lab` (sous-OU `Utilisateurs` / `Services` / `Groupes`).

| # | Faiblesse | Compte / objet | Scénario | MITRE |
|---|-----------|----------------|----------|-------|
| 1 | Mots de passe faibles + verrouillage désactivé | `j.dupont`, `m.martin`, `a.roux` ; `LockoutThreshold 0` | Password spraying | T1110.003 |
| 2 | Compte de service avec SPN + mdp faible + RC4 forcé | `svc-sql` — SPN `MSSQLSvc/sql01.purplelab.local:1433` | Kerberoasting | T1558.003 |
| 3 | Pré-authentification Kerberos désactivée | `a.roux` (`DONT_REQ_PREAUTH`) | AS-REP roasting | T1558.004 |
| 4 | Délégation contrainte + transition de protocole | `svc-web` → `cifs/DC01` (`msDS-AllowedToDelegateTo` + `TrustedToAuthForDelegation`) | Mouvement latéral / pivot | T1550.002 |
| 5 | Chaîne d'ACL vers le DC | `j.dupont` → groupe `Helpdesk` → `GenericAll` sur `svc-web` | Chemin vers DA | T1087 / abus d'ACL |

> Comptes « bruit » : `l.bernard` et `s.petit` reçoivent des **mots de passe forts** (aléatoires) — ils ne sont pas des cibles, ils rendent le spraying réaliste.

**Chaîne complète vers le DC** (ce que recouvrent les scénarios 1→5) :
`spraying` sur `j.dupont` (mdp faible) → `j.dupont ∈ Helpdesk` → `Helpdesk` a `GenericAll` sur `svc-web` (prise de contrôle) → `svc-web` est en **délégation contrainte avec transition de protocole** vers `cifs/DC01` → usurpation d'un **Domain Admin** sur le DC. Aucun `GenericAll` ne porte directement sur un compte DA : c'est la combinaison ACL + délégation qui mène au DC.

### #1 — Mots de passe faibles + verrouillage désactivé
**Pourquoi c'est exploitable.** Plusieurs comptes ont un mot de passe trivial (`Automne2026!`, `Password1`, `P@ssw0rd`, `Welcome1`) et la **politique de verrouillage est à 0** (aucun verrouillage). Un attaquant peut donc tester un mot de passe courant sur tous les comptes, en boucle, sans jamais bloquer personne.

```powershell
# extrait config/ad/setup-vulns.ps1 (phase 3)
New-LabUser j.dupont "Julie Dupont" "Automne2026!" Utilisateurs
New-LabUser m.martin "Marc Martin"  "Automne2026!" Utilisateurs
Set-ADDefaultDomainPasswordPolicy -Identity $dom.DNSRoot -LockoutThreshold 0
```

**Détection attendue.** Rafale de **4625** (échec d'ouverture de session) sur plusieurs comptes depuis une même source, suivie d'un **4624** (succès) quand un mot de passe tombe. (Avec `LockoutThreshold 0`, **aucun 4740** ne viendra signaler un verrouillage.)
**Durcissement :** [hardening-ad.md #1](../remediation/hardening-ad.md#1--mots-de-passe-faibles-et-verrouillage-désactivé).

### #2 — Compte de service `svc-sql` avec SPN + mot de passe faible
**Pourquoi c'est exploitable.** Tout utilisateur authentifié peut demander un ticket de service (TGS) pour un compte porteur d'un SPN. Le ticket est chiffré avec la clé dérivée du mot de passe de `svc-sql` (`P@ssw0rd`, faible) → **cassable hors-ligne**. Le script **force RC4** (`msDS-SupportedEncryptionTypes=4`), ce qui accélère encore le crack.

```powershell
# extrait config/ad/setup-vulns.ps1 (phase 3)
New-LabUser svc-sql "svc-sql" "P@ssw0rd" Services
Set-ADUser svc-sql -ServicePrincipalNames @{Add='MSSQLSvc/sql01.purplelab.local:1433'} `
  -Replace @{'msDS-SupportedEncryptionTypes'=4}
```

> `sql01` est le **nom de service du SPN**, pas une VM du lab : pour le Kerberoasting, seul le SPN enregistré sur le compte compte — aucun hôte `sql01` n'a besoin d'exister.

**Détection attendue.** **4769** (demande de TGS) avec **type de chiffrement RC4 (0x17)** pour le SPN, en particulier par un compte sans rapport avec le service.
**Durcissement :** [hardening-ad.md #2](../remediation/hardening-ad.md#2--compte-svc-sql-avec-spn-et-rc4).

### #3 — Compte `a.roux` sans pré-authentification Kerberos
**Pourquoi c'est exploitable.** Avec l'option `DONT_REQ_PREAUTH`, le KDC renvoie une réponse AS-REP à **quiconque** la demande pour `a.roux`, sans preuve d'identité. Cette réponse contient un blob chiffré avec la clé du compte → **cassable hors-ligne** (AS-REP roasting), d'autant que `a.roux` a un mot de passe faible (`Password1`).

```powershell
# extrait config/ad/setup-vulns.ps1 (phase 3)
New-LabUser a.roux "Alex Roux" "Password1" Utilisateurs
Set-ADAccountControl a.roux -DoesNotRequirePreAuth $true
```

**Détection attendue.** **4768** (demande de TGT) **sans pré-authentification**, type de chiffrement RC4.
**Durcissement :** [hardening-ad.md #3](../remediation/hardening-ad.md#3--pré-authentification-kerberos-désactivée).

### #4 — `svc-web` : délégation contrainte avec transition de protocole
**Pourquoi c'est exploitable.** `svc-web` est configuré en **délégation contrainte avec transition de protocole** (`TrustedToAuthForDelegation = true`) vers `cifs/DC01`. Via **S4U2Self + S4U2Proxy**, quiconque contrôle `svc-web` peut obtenir un ticket de service **au nom de n'importe quel utilisateur** — y compris un Domain Admin — vers le partage CIFS du DC, et donc agir sur `DC01`. C'est le **pivot** de la chaîne vers le DC (voir #5).

```powershell
# extrait config/ad/setup-vulns.ps1 (phase 3)
New-LabUser svc-web "svc-web" "Welcome1" Services
Set-ADUser svc-web -ServicePrincipalNames @{Add='HTTP/web01.purplelab.local'} `
  -Add @{'msDS-AllowedToDelegateTo'=@('cifs/DC01.purplelab.local','cifs/DC01')}
Set-ADAccountControl svc-web -TrustedToAuthForDelegation $true
```

**Détection attendue.** **5136** (modification d'objet annuaire) sur `msDS-AllowedToDelegateTo` et sur `userAccountControl` (bit `TrustedToAuthForDelegation`) ; côté Kerberos, **4769** issus de requêtes **S4U** (ticket « for user » puis vers `cifs/DC01`) inhabituelles.
**Durcissement :** [hardening-ad.md #4](../remediation/hardening-ad.md#4--délégation-contrainte-de-svc-web-vers-le-dc).

### #5 — Chaîne d'ACL `j.dupont` → `Helpdesk` → `svc-web` → DC
**Pourquoi c'est exploitable.** Le groupe `Helpdesk` détient un droit excessif (`GenericAll`) sur `svc-web`, et `j.dupont` (compromis par spraying) en est membre. L'attaquant enchaîne : contrôle de `j.dupont` → via `Helpdesk`, `GenericAll` sur `svc-web` (réinitialisation du mot de passe / prise de contrôle) → exploitation de la **délégation contrainte** de `svc-web` vers `cifs/DC01` → usurpation d'un **Domain Admin** sur le DC. La cible du `GenericAll` n'est donc **pas** un compte DA, mais le compte de service qui sert de pivot.

```powershell
# extrait config/ad/setup-vulns.ps1 (phase 3)
New-ADGroup -Name Helpdesk -GroupScope Global -Path "OU=Groupes,$ou"
Add-ADGroupMember Helpdesk -Members j.dupont
dsacls (Get-ADUser svc-web).DistinguishedName /G "PURPLELAB\Helpdesk:GA"
```

**Détection attendue.** Collecte **SharpHound** (requêtes LDAP massives, **4662** accès à l'objet) ; **5136** sur les ACL (`nTSecurityDescriptor`) de `svc-web` lors de la pose du droit.
**Durcissement :** [hardening-ad.md #5](../remediation/hardening-ad.md#5--chaîne-dacl-helpdesk-vers-svc-web).

> Schéma à exporter dans `images/architecture.png`.
