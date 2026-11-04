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

## 3. Sysmon — ✅ S11 (CLIENT01, CLIENT02)

| Élément | Valeur |
|---|---|
| Binaire | `Sysmon64.exe` 15.22 (Sysinternals), signature Authenticode vérifiée |
| Config | SwiftOnSecurity `sysmonconfig-export.xml`, **non modifiée** — copie figée : [`config/sysmon/`](../config/sysmon/) |
| Emplacement | `C:\Sysmon\` sur chaque poste |
| Journal | `Microsoft-Windows-Sysmon/Operational`, 256 Mo |

**Déploiement (🖥️ Hôte Windows — clients sans Internet, binaire + config téléchargés sur l'hôte) :**
```powershell
foreach ($ip in '10.10.10.21','10.10.10.22') {
  ssh amin@$ip "powershell -NoProfile -Command New-Item -ItemType Directory -Force C:\Sysmon"
  scp .\Sysmon64.exe .\sysmonconfig-export.xml "amin@${ip}:C:/Sysmon/"
  ssh amin@$ip "C:\Sysmon\Sysmon64.exe -accepteula -i C:\Sysmon\sysmonconfig-export.xml"
  ssh amin@$ip "wevtutil sl Microsoft-Windows-Sysmon/Operational /ms:268435456"
}
```

**Validation (2026-11-04, les 2 postes) :** services `Sysmon64` + `SysmonDrv` Running ✅ ; IDs 1, 3, 11, 12, 13, 22 observés ✅ ; taille du journal = 268435456 ✅

**Limite connue :** pas d'ID 10 (ProcessAccess) — bloc vide dans la config SwiftOnSecurity → accès à **LSASS non journalisés**.
Angle mort assumé : traité comme écart de détection dans le scénario 4 (Pass-the-Hash), remédié par une config `sysmonconfig-purplelab.xml`.

**Bruit connu :** ID 8 (CreateRemoteThread) avec `StartFunction: CtrlRoutine` (csrss → console) = gestion de Ctrl+C, bénin.

## 4. Validation (BLOQUANT)
Vérifier dans Wazuh que **les trois sources remontent** (audit Windows, PowerShell, Sysmon)
avant de lancer le moindre scénario d'attaque.
