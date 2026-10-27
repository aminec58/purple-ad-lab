# Télémétrie

Sans ces sources, les attaques AD sont invisibles dans le SIEM.

## 1. Audit avancé Windows (GPO)
- Connexion / ouverture de session (logon)
- Gestion des comptes
- Accès au service Kerberos : **4768** (TGT), **4769** (TGS), **4771** (échec pré-auth)
- Création de processus : **4688** (+ ligne de commande)

## 2. PowerShell
- Script Block Logging
- Module Logging
(sur DC et postes, via GPO)

## 3. Sysmon
- Config SwiftOnSecurity
- Process, connexions réseau, accès LSASS
- Déployé sur CLIENT01 et CLIENT02

## 4. Validation (BLOQUANT)
Vérifier dans Wazuh que **les trois sources remontent** (audit Windows, PowerShell, Sysmon)
avant de lancer le moindre scénario d'attaque.
