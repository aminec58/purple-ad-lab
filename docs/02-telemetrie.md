# Télémétrie

Sans ces sources, les attaques AD sont invisibles dans le SIEM.

## 1. Audit avancé Windows (GPO) — ✅ S09 (DC01)
GPO **`PURPLELAB - Audit avance`** créée par [`config/gpo/setup-audit-gpo.ps1`](../config/gpo/setup-audit-gpo.ps1),
liée à la racine du domaine (postes, appliquée à la jonction) et à l'OU `Domain Controllers` (ordre 1).
Détail des sous-catégories : [`config/gpo/audit-policy.md`](../config/gpo/audit-policy.md).

- Connexions : **4624/4625**, 4634, 4672 ; validation NTLM **4776**
- Kerberos : **4768** (TGT), **4769** (TGS), **4771** (échec pré-auth)
- Gestion des comptes / groupes : 4720, 4738, 4740, 4728, 4732, 4756 ; changements AD 5136 (SACL en phase 3)
- Création de processus : **4688** + ligne de commande
- « Force audit policy subcategory settings » activé ; journal Security porté à 512 Mo

**Application (🖥️ PurpleAD-DC, SSH) :**
```powershell
Set-ExecutionPolicy -Scope Process Bypass -Force
C:\Users\Administrateur\setup-audit-gpo.ps1
```

**Validation sur DC01 (2026-11-02) :**
- `auditpol /get /subcategory:{GUID}` → les 11 sous-catégories au réglage attendu ✅
- `klist purge` + `klist get cifs/dc01.purplelab.local` → 4768 et 4769 générés ✅
- 4688 avec ligne de commande (`whoami`) ✅ ; 4624 ✅
- 4771 / 4625 / 4776 : à valider depuis Kali (mauvais mot de passe) lors du contrôle d'ingestion Wazuh ⏳

## 2. PowerShell — ✅ S09 (même GPO)
- Script Block Logging (**4104**) — vérifié sur DC01 ✅
- Module Logging, tous modules `*` (**4103**)
(sur DC et postes, via la GPO ci-dessus)

## 3. Sysmon
- Config SwiftOnSecurity
- Process, connexions réseau, accès LSASS
- Déployé sur CLIENT01 et CLIENT02

## 4. Validation (BLOQUANT)
Vérifier dans Wazuh que **les trois sources remontent** (audit Windows, PowerShell, Sysmon)
avant de lancer le moindre scénario d'attaque.
