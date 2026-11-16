# Sysmon — configuration du lab

| Élément | Valeur |
|---|---|
| Version Sysmon | 15.22 (`Sysmon64.exe`, Sysinternals) |
| Config de base | `sysmonconfig-export.xml` — SwiftOnSecurity, **non modifiée** |
| Source | https://github.com/SwiftOnSecurity/sysmon-config (commit `1836897f12fbd6a0a473665ef6abc34a6b497e31`, récupéré le 2026-11-04) |
| Config du lab | `sysmonconfig-purplelab.xml` : la config de base plus une règle `ProcessAccess` sur LSASS |
| Cibles | CLIENT01, CLIENT02, DC01 (`C:\Sysmon\`) |

## Installation / mise à jour de la config
```powershell
C:\Sysmon\Sysmon64.exe -accepteula -i C:\Sysmon\sysmonconfig-export.xml   # installation
C:\Sysmon\Sysmon64.exe -c C:\Sysmon\<config>.xml                          # rechargement d'une config
```

## Limite de la config de base
Pas d'événement ID 10 (ProcessAccess) : le bloc `<ProcessAccess onmatch="include">` est vide, donc les accès à LSASS ne sont **pas** journalisés.
C'est l'angle mort relevé au scénario 4 (Pass-the-Hash).

## sysmonconfig-purplelab.xml

Cette variante ne change qu'une chose par rapport à la config SwiftOnSecurity : le bloc `ProcessAccess` contient une règle qui journalise tout accès à `C:\Windows\system32\lsass.exe`. L'en-tête du fichier indique le fork, le reste est identique (`diff` des deux fichiers pour le vérifier).

```xml
<ProcessAccess onmatch="include">
	<TargetImage name="T1003.001,LSASS" condition="is">C:\Windows\system32\lsass.exe</TargetImage>
</ProcessAccess>
```

Je n'ai pas filtré sur `GrantedAccess` dans Sysmon. Le tri se fait dans Wazuh : la règle `100141` (`detection/wazuh-rules/pass-the-hash.xml`) ne retient que les masques d'accès typiques d'un dump (`0x1010`, `0x1410`, `0x1438`, `0x143a`, `0x1fffff`). Le journal Sysmon garde ainsi tous les accès, ce qui sert à la chasse, et seuls les accès suspects alertent.

Chargement sur un poste, après copie du fichier dans `C:\Sysmon\` :

```powershell
C:\Sysmon\Sysmon64.exe -c C:\Sysmon\sysmonconfig-purplelab.xml
C:\Sysmon\Sysmon64.exe -c | Select-String ProcessAccess -Context 0,3      # vérifier la règle chargée
```

État : la config est écrite mais pas encore chargée sur les postes ni validée au rejeu. Deux points à vérifier à ce moment-là : le volume d'ID 10 produit par les accès légitimes à LSASS (antivirus, `svchost.exe`, agent Wazuh), et le déclenchement de `100141`, qui demande un vrai accès à la mémoire de LSASS alors que Windows 11 la protège par défaut.
