# Déploiement de l'infrastructure

## Ordre d'installation
1. Réseau VMware host-only (DHCP VMware désactivé)
2. DC : IP statique, promotion AD DS + DNS, création du domaine `purplelab.local`
3. Clients : DNS pointé sur le DC, jonction au domaine
4. SIEM : Ubuntu Server, Wazuh (all-in-one) + serveur Velociraptor
5. Kali : mise à jour + outils (impacket, nxc/crackmapexec, bloodhound, rubeus…)
6. **Snapshot « clean baseline » de chaque VM**

## Dimensionnement conseillé

### Hôte 16 Go (serré — allumer les VM par vagues)
| VM       | RAM     | vCPU |
|----------|---------|------|
| DC       | 2 Go    | 2    |
| CLIENTxx | 2 Go    | 1    |
| KALI     | 2–3 Go  | 2    |
| SIEM     | 6 Go    | 2    |

Pendant un scénario : SIEM + DC + 1 client + Kali seulement.

### Hôte 32 Go (confortable — tout en parallèle)
| VM       | RAM   | vCPU |
|----------|-------|------|
| DC       | 4 Go  | 2    |
| CLIENTxx | 4 Go  | 2    |
| KALI     | 4 Go  | 2    |
| SIEM     | 8 Go  | 4    |

Disque : ~250 Go thin-provisioned au total. **SSD recommandé** (Wazuh/indexer Elastic).

---

## Réalisation — DC01

Première brique du lab : une forêt Active Directory `purplelab.local` sur Windows Server 2022, avec DNS intégré. Le DC reste **propre** jusqu'à la mise en place de la télémétrie ; les faiblesses volontaires (comptes faibles, SPN, pré-auth désactivée…) seront ajoutées ensuite.

### Spécifications

| Élément | Valeur |
|---|---|
| VM | `PurpleAD-DC` — 2 vCPU, 4 Go RAM, 60 Go NVMe, UEFI |
| OS | Windows Server 2022 Standard Evaluation (FR) |
| Réseau | VMnet2 host-only `10.10.10.0/24`, sans passerelle ni Internet |
| Hostname / IP | `DC01` / `10.10.10.10` |
| Domaine | `purplelab.local` (NetBIOS `PURPLELAB`), niveau fonctionnel 2016 |
| Rôles | AD DS, DNS, source de temps du domaine |

### 1. Préparation (avant promotion)

> ⚠️ Faire ces changements depuis la console VMware, pas en SSH : changer l'IP coupe la session.

```powershell
$if = (Get-NetAdapter | ? Status -eq Up).Name
New-NetIPAddress -InterfaceAlias $if -IPAddress 10.10.10.10 -PrefixLength 24
Set-DnsClientServerAddress -InterfaceAlias $if -ServerAddresses 127.0.0.1
Set-TimeZone -Id "Romance Standard Time"
Rename-Computer -NewName "DC01" -Restart
```

Le hostname est fixé **avant** la promotion : renommer un DC après coup est risqué.

### 2. Promotion en contrôleur de domaine

```powershell
Install-WindowsFeature AD-Domain-Services -IncludeManagementTools

Install-ADDSForest `
  -DomainName "purplelab.local" `
  -DomainNetbiosName "PURPLELAB" `
  -InstallDns `
  -ForestMode WinThreshold -DomainMode WinThreshold `
  -SafeModeAdministratorPassword (Read-Host "DSRM" -AsSecureString) `
  -Force
```

Le serveur redémarre automatiquement. **Attendre que les services soient prêts** avant la suite :

```powershell
Get-Service NTDS, DNS, ADWS | ft Name, Status   # tous Running
```

### 3. Post-configuration

```powershell
# Zone de recherche inversée + enregistrement PTR du DC
Add-DnsServerPrimaryZone -NetworkId "10.10.10.0/24" -ReplicationScope Forest
Add-DnsServerResourceRecordPtr -ZoneName "10.10.10.in-addr.arpa" -Name 10 `
  -PtrDomainName "DC01.purplelab.local"

# DC = source de temps de référence (Kerberos tolère 5 min d'écart)
w32tm /config /reliable:yes /syncfromflags:manual /update
```

### 4. Vérifications

| Test | Commande | Résultat obtenu |
|---|---|---|
| Domaine | `Get-ADDomain \| fl DNSRoot, NetBIOSName, DomainMode` | `purplelab.local` / `PURPLELAB` / `Windows2016Domain` |
| Enregistrement SRV | `Resolve-DnsName _ldap._tcp.dc._msdcs.purplelab.local -Type SRV` | `dc01.purplelab.local` → `10.10.10.10` |
| Résolution inverse | `Resolve-DnsName 10.10.10.10` | `DC01.purplelab.local` |
| Partages AD | `Get-SmbShare SYSVOL, NETLOGON` | Les deux partages présents |
| Santé globale | `dcdiag /q` | Seulement `SystemLog` / `DFSREvent` (voir ci-dessous) |

**Lecture de `dcdiag`** : sur un DC neuf, `DFSREvent` remonte les avertissements normaux de l'initialisation SYSVOL, et `SystemLog` les redémarrages des dernières 24 h. Aucun des deux n'indique un défaut de l'AD.

### 5. Problèmes rencontrés

| Problème | Cause | Solution |
|---|---|---|
| Serveur installé sans interface graphique | L'installeur sélectionne **Server Core** par défaut ; la conversion Core → GUI est impossible depuis Server 2016 | Réinstallation en choisissant « (expérience de bureau) » |
| Boot sur l'ISO raté | Le « Press any key » UEFI ne dure que ~5 s et exige que la VM ait le focus clavier | `VM → Power → Power On to Firmware` → Boot Manager → CD-ROM |
| DC injoignable après changement d'IP | IP du lab posée en SSH sur une carte encore connectée au NAT | Carte basculée sur VMnet2 depuis VMware, reconfiguration via la console |
| Erreur DNS `9901` sur la zone inverse | Commande lancée avant la fin du redémarrage post-promotion : zone AD-intégrée impossible tant que l'AD n'est pas actif | Attendre le reboot, vérifier `NTDS`/`DNS`/`ADWS`, relancer |

### 6. Accès d'administration

Le DC est administré depuis l'hôte via **OpenSSH Server** :

```powershell
ssh "PURPLELAB\Administrateur"@10.10.10.10
```

Cet accès est propre au lab. Il génère ses propres événements de connexion, à distinguer de l'activité d'attaque lors des scénarios.

### Étape suivante

Jonction de `CLIENT01` et `CLIENT02` (Windows 11) au domaine.
