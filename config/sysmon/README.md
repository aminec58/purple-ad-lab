# Sysmon — configuration du lab

| Élément | Valeur |
|---|---|
| Version Sysmon | 15.22 (`Sysmon64.exe`, Sysinternals) |
| Config | `sysmonconfig-export.xml` — SwiftOnSecurity, **non modifiée** |
| Source | https://github.com/SwiftOnSecurity/sysmon-config (commit `1836897f12fbd6a0a473665ef6abc34a6b497e31`, récupéré le 2026-11-04) |
| Cibles | CLIENT01, CLIENT02 (`C:\Sysmon\`) |

## Installation / mise à jour de la config
```powershell
C:\Sysmon\Sysmon64.exe -accepteula -i C:\Sysmon\sysmonconfig-export.xml   # installation
C:\Sysmon\Sysmon64.exe -c C:\Sysmon\<config>.xml                          # rechargement d'une config
```

## Limite connue
Pas d'événement ID 10 (ProcessAccess) : le bloc `<ProcessAccess onmatch="include">` est vide, donc les accès à LSASS ne sont **pas** journalisés.
Angle mort volontaire : c'est l'écart de détection du scénario 4 ; la remédiation ajoutera `sysmonconfig-purplelab.xml` (règle LSASS).
