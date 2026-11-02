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
| CLIENT01 | Poste joint                             | Windows 10/11       | 10.10.10.21  |
| CLIENT02 | Poste joint                             | Windows 10/11       | 10.10.10.22  |
| KALI     | Attaque                                 | Kali Linux          | 10.10.10.50  |
| SIEM     | Wazuh + Velociraptor                    | Ubuntu Server       | 10.10.10.100 |

## Faiblesses introduites sur le DC (matière des 5 scénarios)

> ⚠️ **Rien n'est posé pour l'instant.** Ces faiblesses se créent en **phase 3 (vulnérabilisation)**, *après* la mise en place **et la vérification** de la télémétrie (phase 2). Raison : la baseline reste propre, et la **création** des faiblesses doit elle-même être visible dans les logs (événements horodatés sur une télémétrie déjà validée).
>
> Les mots de passe sont **volontairement faibles** — c'est l'objet du lab, documenté comme tel. **Aucun secret réel** n'est écrit ici ni ailleurs dans le dépôt (cf. `.gitignore`). Les valeurs des commandes ci-dessous sont des **exemples** à fixer au moment de la phase 3 ; elles sont référencées pour reproductibilité, pas exécutées maintenant.

Domaine `purplelab.local` — DC `DC01` = `10.10.10.10`.

| # | Faiblesse | Compte / objet | Scénario | MITRE |
|---|-----------|----------------|----------|-------|
| 1 | Mots de passe faibles + verrouillage laxiste | `jmartin`, `pdurand`, `slefevre` | Password spraying | T1110.003 |
| 2 | Compte de service avec SPN + mdp faible | `svc-sql` — SPN `MSSQLSvc/dc01.purplelab.local:1433` | Kerberoasting | T1558.003 |
| 3 | Pré-authentification Kerberos désactivée | `svc-legacy` (`DONT_REQ_PREAUTH`) | AS-REP roasting | T1558.004 |
| 4 | Délégation Kerberos non contrainte | `svc-legacy` ou un hôte (`TRUSTED_FOR_DELEGATION`) | Mouvement latéral | T1550.002 |
| 5 | Chaîne d'ACL vers un compte Domain Admin | `jmartin` → groupe `Helpdesk` → `GenericAll` sur un DA | Chemin vers DA | T1087 / abus d'ACL |

Chaque durcissement correspondant est détaillé dans [`remediation/hardening-ad.md`](../remediation/hardening-ad.md).

### #1 — Mots de passe faibles + verrouillage laxiste
**Pourquoi c'est exploitable.** Des comptes utilisateurs ont un mot de passe trivial/commun, et la politique de verrouillage est absente ou très permissive (seuil nul ou très élevé). Un attaquant peut donc tester **un** mot de passe courant sur **beaucoup** de comptes (spraying) sans jamais déclencher de verrouillage.

```powershell
# phase 3 — DC01 (valeurs d'EXEMPLE, mdp volontairement faibles)
"jmartin","pdurand","slefevre" | ForEach-Object {
  New-ADUser -Name $_ -SamAccountName $_ -Enabled $true `
    -AccountPassword (ConvertTo-SecureString 'Automne2024' -AsPlainText -Force)
}
net accounts /lockoutthreshold:0   # verrouillage désactivé = laxiste
```

**Détection attendue.** Rafale de **4625** (échec d'ouverture de session) sur plusieurs comptes depuis une même source, suivie d'un **4624** (succès) quand un mot de passe tombe.
**Durcissement :** [hardening-ad.md #1](../remediation/hardening-ad.md#1--mots-de-passe-faibles--verrouillage-laxiste).

### #2 — Compte de service `svc-sql` avec SPN + mot de passe faible
**Pourquoi c'est exploitable.** Tout utilisateur authentifié peut demander un ticket de service (TGS) pour un compte porteur d'un SPN. Le ticket est chiffré avec la clé dérivée du mot de passe du compte de service : si ce mot de passe est faible, il est **cassable hors-ligne**. L'usage de RC4 facilite encore le crack.

```powershell
# phase 3 — DC01 (valeurs d'EXEMPLE)
New-ADUser -Name svc-sql -SamAccountName svc-sql -Enabled $true `
  -AccountPassword (ConvertTo-SecureString 'Sql2024' -AsPlainText -Force)
setspn -s MSSQLSvc/dc01.purplelab.local:1433 svc-sql
```

**Détection attendue.** **4769** (demande de TGS) avec **type de chiffrement RC4 (0x17)** demandé pour le SPN, en particulier par un compte sans rapport avec le service.
**Durcissement :** [hardening-ad.md #2](../remediation/hardening-ad.md#2--compte-de-service-svc-sql-avec-spn--mot-de-passe-faible).

### #3 — Compte `svc-legacy` sans pré-authentification Kerberos
**Pourquoi c'est exploitable.** Avec l'option `DONT_REQ_PREAUTH`, le KDC renvoie une réponse AS-REP à **quiconque** la demande pour ce compte, sans preuve d'identité. Cette réponse contient un blob chiffré avec la clé du compte → **cassable hors-ligne** (AS-REP roasting).

```powershell
# phase 3 — DC01 (valeur d'EXEMPLE)
New-ADUser -Name svc-legacy -SamAccountName svc-legacy -Enabled $true `
  -AccountPassword (ConvertTo-SecureString 'Legacy2024' -AsPlainText -Force)
Set-ADAccountControl -Identity svc-legacy -DoesNotRequirePreAuth $true
```

**Détection attendue.** **4768** (demande de TGT) **sans pré-authentification**, type de chiffrement RC4.
**Durcissement :** [hardening-ad.md #3](../remediation/hardening-ad.md#3--compte-svc-legacy-sans-pré-authentification-kerberos).

### #4 — Délégation Kerberos non contrainte
**Pourquoi c'est exploitable.** Un compte ou un hôte configuré en délégation **non contrainte** met en cache les TGT des utilisateurs qui s'y authentifient. Qui compromet cet objet peut rejouer ces TGT — y compris celui d'un administrateur — et pivoter (mouvement latéral, escalade).

```powershell
# phase 3 — DC01 (délégation non contrainte sur svc-legacy)
Set-ADAccountControl -Identity svc-legacy -TrustedForDelegation $true
```

**Détection attendue.** **5136** (modification d'objet annuaire) sur `userAccountControl` / `msDS-AllowedToDelegateTo` ; demandes de tickets **S4U** inhabituelles.
**Durcissement :** [hardening-ad.md #4](../remediation/hardening-ad.md#4--délégation-kerberos-non-contrainte).

### #5 — Chaîne d'ACL `jmartin` → `Helpdesk` → Domain Admin
**Pourquoi c'est exploitable.** `jmartin` est membre d'un groupe `Helpdesk` qui détient un droit excessif (`GenericAll`) sur un compte **Domain Admin**. En possédant `jmartin`, un attaquant peut (via ce chemin) réinitialiser le mot de passe du DA ou prendre le contrôle du compte → compromission du domaine.

```powershell
# phase 3 — DC01 (chaîne d'ACL ; da-admin = compte DA cible d'EXEMPLE)
New-ADGroup -Name Helpdesk -GroupScope Global
Add-ADGroupMember -Identity Helpdesk -Members jmartin
dsacls "CN=da-admin,CN=Users,DC=purplelab,DC=local" /G "PURPLELAB\Helpdesk:GA"
```

**Détection attendue.** Collecte **SharpHound** (requêtes LDAP massives, **4662** accès à l'objet) ; **5136** sur les ACL (`nTSecurityDescriptor`) lors de la pose du droit.
**Durcissement :** [hardening-ad.md #5](../remediation/hardening-ad.md#5--chaîne-dacl-jmartin--helpdesk--domain-admin).

> Schéma à exporter dans `images/architecture.png`.
