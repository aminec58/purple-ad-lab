# Durcissement Active Directory

Un durcissement **par faiblesse** réellement posée par [`config/ad/setup-vulns.ps1`](../config/ad/setup-vulns.ps1) (voir [`docs/00-architecture.md`](../docs/00-architecture.md)). Objectif de chaque scénario : au **rejeu**, la détection se déclenche **et** le durcissement **bloque ou limite** l'attaque.

| # | Faiblesse / scénario | Durcissement AD | Statut |
|---|----------------------|-----------------|--------|
| 1 | Mots de passe faibles — *Password spraying* | Politique de mots de passe robuste + verrouillage de compte + alerte sur rafales 4625 | ✅ rédigé |
| 2 | `svc-sql` SPN + mdp faible + RC4 — *Kerberoasting* | gMSA, AES uniquement, retrait des SPN inutiles | ✅ rédigé |
| 3 | `a.roux` sans pré-auth — *AS-REP roasting* | Réactiver la pré-auth, mdp fort, désactiver RC4 | ✅ rédigé |
| 4 | `svc-web` délégation contrainte — *Mouvement latéral* | Retirer la transition de protocole, cadrer/supprimer la délégation, comptes privilégiés non délégables | ✅ rédigé |
| 5 | Chaîne d'ACL `Helpdesk` → `svc-web` — *Chemin vers DA* | Nettoyage des ACL, tiering administratif, retrait des droits excessifs | ✅ rédigé |

---

## #1 — Mots de passe faibles et verrouillage désactivé
- **Politique de mot de passe** (Default Domain Policy, ou PSO ciblée via `New-ADFineGrainedPasswordPolicy`) : longueur minimale ≥ 14, complexité activée, historique, expiration raisonnable.
- **Rétablir le verrouillage de compte** : seuil 5–10 tentatives, durée et fenêtre d'observation de 15–30 min — de quoi casser le spraying sans faciliter le déni de service.
- **Interdire les mots de passe courants** (filtre de mot de passe, ou *Password Protection* on-prem si disponible).
- **Détection/alerte** : règle SIEM sur une rafale de **4625** multi-comptes depuis une même source.

```powershell
# rétablir une politique saine (annule LockoutThreshold 0)
net accounts /minpwlen:14 /lockoutthreshold:5 /lockoutduration:30 /lockoutwindow:15
```

## #2 — Compte `svc-sql` avec SPN et RC4
- **Migrer vers un gMSA** (`New-ADServiceAccount`) : mot de passe géré, long (≥ 120 caractères), roté automatiquement → plus crackable.
- Si un compte classique reste nécessaire : **mot de passe ≥ 25 caractères aléatoires**.
- **Forcer AES et désactiver RC4** via `msDS-SupportedEncryptionTypes` (annule le `=4` du script).
- **Retirer les SPN inutiles** (`setspn -D`).
- **Détection** : surveiller les **4769** en **RC4 (0x17)**.

```powershell
# AES uniquement (AES128 + AES256 = 24) sur le compte de service
Set-ADUser svc-sql -Replace @{ 'msDS-SupportedEncryptionTypes' = 24 }
# retrait du SPN devenu inutile
setspn -D MSSQLSvc/sql01.purplelab.local:1433 svc-sql
```

## #3 — Pré-authentification Kerberos désactivée
- **Réactiver la pré-authentification** sur `a.roux` : retirer `DONT_REQ_PREAUTH`.
- **Mot de passe fort** (le lab utilise `Password1`) ou passage du compte en service géré.
- **Désactiver RC4** (AES uniquement) sur le compte.
- **Détection** : alerte sur **4768** sans pré-auth / en RC4.

```powershell
Set-ADAccountControl a.roux -DoesNotRequirePreAuth $false
Set-ADUser a.roux -Replace @{ 'msDS-SupportedEncryptionTypes' = 24 }
```

## #4 — Délégation contrainte de `svc-web` vers le DC
- **Retirer la transition de protocole** : `TrustedToAuthForDelegation = $false` (supprime l'abus S4U2Self/S4U2Proxy).
- **Cadrer ou supprimer la délégation** : vider `msDS-AllowedToDelegateTo` ; ne **jamais** autoriser de délégation vers un service du DC (`cifs/DC01`) — c'est une escalade directe. Si une délégation est indispensable, préférer une **RBCD** définie côté ressource cible et limitée au strict nécessaire.
- **Protéger les comptes privilégiés** : marqueur « *Account is sensitive and cannot be delegated* » (`AccountNotDelegated`) + appartenance au groupe **Protected Users**.
- **Détection** : alerte sur **5136** touchant `msDS-AllowedToDelegateTo` / `userAccountControl`.

```powershell
Set-ADAccountControl svc-web -TrustedToAuthForDelegation $false
Set-ADUser svc-web -Clear 'msDS-AllowedToDelegateTo'
# comptes à privilèges : non délégables
Set-ADAccountControl -Identity <compte-DA> -AccountNotDelegated $true
```

## #5 — Chaîne d'ACL `Helpdesk` vers `svc-web`
- **Nettoyer les ACL excessives** (`GenericAll`, `WriteDacl`, `WriteOwner`, `ForceChangePassword`…) sur `svc-web` et les autres comptes/groupes à privilèges ; vérifier avec BloodHound/`dsacls` qu'aucun chemin ne subsiste.
- **Tiering administratif** (Tier 0/1/2) : un compte de service pivot comme `svc-web` ne doit pas être joignable depuis un groupe de support (`Helpdesk`), et aucun compte standard ne doit avoir de chemin vers le DC.
- **Moindre privilège** : retirer `j.dupont` de `Helpdesk` ; cadrer précisément ce que `Helpdesk` peut faire.

```powershell
# retrait du droit excessif accordé au groupe Helpdesk sur svc-web
dsacls (Get-ADUser svc-web).DistinguishedName /R "PURPLELAB\Helpdesk"
Remove-ADGroupMember -Identity Helpdesk -Members j.dupont -Confirm:$false
```
