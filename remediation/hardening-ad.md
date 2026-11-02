# Durcissement Active Directory

Un durcissement **par faiblesse** introduite sur le DC (voir [`docs/00-architecture.md`](../docs/00-architecture.md)). Objectif de chaque scénario : au **rejeu**, la détection se déclenche **et** le durcissement **bloque ou limite** l'attaque.

| # | Faiblesse / scénario | Durcissement AD | Statut |
|---|----------------------|-----------------|--------|
| 1 | Mots de passe faibles — *Password spraying* | Politique de mots de passe robuste + verrouillage de compte + alerte sur rafales 4625 | ✅ rédigé |
| 2 | SPN + mdp faible — *Kerberoasting* | gMSA, AES uniquement, retrait des SPN inutiles | ✅ rédigé |
| 3 | Sans pré-auth — *AS-REP roasting* | Réactiver la pré-auth, mdp fort/gMSA, désactiver RC4 | ✅ rédigé |
| 4 | Délégation non contrainte — *Mouvement latéral* | Supprimer l'unconstrained, RBCD cadrée, comptes privilégiés non délégables | ✅ rédigé |
| 5 | Chaîne d'ACL — *Chemin vers DA* | Nettoyage des ACL, tiering administratif, retrait des droits excessifs | ✅ rédigé |

---

## #1 — Mots de passe faibles + verrouillage laxiste
- **Politique de mot de passe** (Default Domain Policy, ou PSO ciblée via `New-ADFineGrainedPasswordPolicy`) : longueur minimale ≥ 14, complexité activée, historique, expiration raisonnable.
- **Verrouillage de compte** : seuil 5–10 tentatives, durée et fenêtre d'observation de 15–30 min — de quoi casser le spraying sans faciliter le déni de service.
- **Interdire les mots de passe courants** (filtre de mot de passe, ou *Password Protection* on-prem si disponible).
- **Détection/alerte** : règle SIEM sur une rafale de **4625** multi-comptes depuis une même source.

```powershell
# politique de base
net accounts /minpwlen:14 /lockoutthreshold:5 /lockoutduration:30 /lockoutwindow:15
```

## #2 — Compte de service `svc-sql` avec SPN + mot de passe faible
- **Migrer vers un gMSA** (`New-ADServiceAccount`) : mot de passe géré, long (≥ 120 caractères), roté automatiquement → plus crackable.
- Si un compte classique reste nécessaire : **mot de passe ≥ 25 caractères aléatoires**.
- **Forcer AES et désactiver RC4** via `msDS-SupportedEncryptionTypes`.
- **Retirer les SPN inutiles** (`setspn -D`).
- **Détection** : surveiller les **4769** en **RC4 (0x17)**.

```powershell
# AES uniquement (AES128 + AES256 = 24) sur le compte de service
Set-ADUser svc-sql -Replace @{ 'msDS-SupportedEncryptionTypes' = 24 }
# retrait d'un SPN devenu inutile
setspn -D MSSQLSvc/dc01.purplelab.local:1433 svc-sql
```

## #3 — Compte `svc-legacy` sans pré-authentification Kerberos
- **Réactiver la pré-authentification** : retirer `DONT_REQ_PREAUTH`.
- **Mot de passe fort** (ou passage en gMSA) pour ôter tout intérêt au crack hors-ligne.
- **Désactiver RC4** (AES uniquement) sur le compte.
- **Détection** : alerte sur **4768** sans pré-auth / en RC4.

```powershell
Set-ADAccountControl -Identity svc-legacy -DoesNotRequirePreAuth $false
Set-ADUser svc-legacy -Replace @{ 'msDS-SupportedEncryptionTypes' = 24 }
```

## #4 — Délégation Kerberos non contrainte
- **Supprimer la délégation non contrainte** (`TrustedForDelegation`) sur les comptes/hôtes concernés.
- Si une délégation est réellement nécessaire : **délégation contrainte** ou **RBCD** limitée au strict service cible.
- **Protéger les comptes privilégiés** : marqueur « *Account is sensitive and cannot be delegated* » (`AccountNotDelegated`) + appartenance au groupe **Protected Users**.
- **Détection** : alerte sur **5136** touchant `userAccountControl` / `msDS-AllowedToDelegateTo`.

```powershell
Set-ADAccountControl -Identity svc-legacy -TrustedForDelegation $false
# comptes à privilèges : non délégables
Set-ADAccountControl -Identity da-admin -AccountNotDelegated $true
```

## #5 — Chaîne d'ACL `jmartin` → `Helpdesk` → Domain Admin
- **Nettoyer les ACL excessives** (`GenericAll`, `WriteDacl`, `WriteOwner`, `ForceChangePassword`…) sur les comptes et groupes à privilèges ; vérifier avec BloodHound/`dsacls` qu'aucun chemin ne subsiste.
- **Tiering administratif** (Tier 0/1/2) : aucun compte standard ne doit avoir de chemin vers un Domain Admin.
- **Moindre privilège** : retirer `jmartin` des groupes à droits étendus ; cadrer précisément ce que `Helpdesk` peut faire.

```powershell
# retrait du droit excessif accordé au groupe Helpdesk
dsacls "CN=da-admin,CN=Users,DC=purplelab,DC=local" /R "PURPLELAB\Helpdesk"
Remove-ADGroupMember -Identity Helpdesk -Members jmartin -Confirm:$false
```
