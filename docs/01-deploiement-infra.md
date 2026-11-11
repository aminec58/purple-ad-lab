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

## Réalisation — CLIENT01 et CLIENT02

Les deux postes sont déployés à l'identique : seuls le nom et l'adresse IP changent.

### Spécifications

| Élément | CLIENT01 | CLIENT02 |
|---|---|---|
| VM (VMware) | `PurpleAD-CLIENT01` | `PurpleAD-CLIENT02` |
| OS | Windows 11 **Pro** (build 26300) | idem |
| Ressources | 4 Go RAM, 2 vCPU, 64 Go NVMe, vTPM | idem |
| Adresse IP | 10.10.10.21/24 | 10.10.10.22/24 |
| DNS | 10.10.10.10 (DC01) | idem |
| Compte local | `amin` (administrateur local) | idem |

### 1. Installation de Windows 11

- Édition **Pro** obligatoire : l'édition Famille ne peut pas joindre un domaine.
- OOBE sans Internet (réseau host-only) : à l'écran réseau, `Maj+F10` puis `start ms-cxh:localonly` pour créer directement un compte local.
- VMware Tools installés.

### 2. Accès d'administration (OpenSSH)

L'installation d'OpenSSH Server télécharge depuis Windows Update : la carte réseau passe temporairement en **NAT**, puis revient sur **VMnet2**. Le changement se fait depuis la console VMware, jamais en SSH.

```powershell
# PowerShell administrateur
Add-WindowsCapability -Online -Name OpenSSH.Server~~~~0.0.1.0
Set-Service sshd -StartupType Automatic; Start-Service sshd
# Réseau non identifié = profil Public → la règle OpenSSH par défaut (Domaine/Privé) ne s'applique pas
New-NetFirewallRule -Name sshd-any -DisplayName "sshd Any" -Enabled True -Direction Inbound -Protocol TCP -Action Allow -LocalPort 22 -Profile Any
```

### 3. Réseau, nom et jonction au domaine

```powershell
$if = (Get-NetAdapter | Where-Object Status -eq Up).Name
New-NetIPAddress -InterfaceAlias $if -IPAddress 10.10.10.21 -PrefixLength 24      # .22 pour CLIENT02
Set-DnsClientServerAddress -InterfaceAlias $if -ServerAddresses 10.10.10.10
Rename-Computer -NewName CLIENT01 -Restart                                          # CLIENT02
# Après redémarrage :
Add-Computer -DomainName purplelab.local -Credential PURPLELAB\Administrateur -Restart
```

### 4. Vérifications

| Test | Commande | Résultat obtenu |
|---|---|---|
| Appartenance au domaine | `(Get-ComputerInfo).CsDomain` | `purplelab.local` (les 2 postes) |
| GPO appliquées | `gpresult /r` | `Default Domain Policy` + `PURPLELAB - Audit avance` |
| Audit création de processus | `auditpol /get /subcategory:"Création du processus"` | Réussite (4688) |
| PowerShell Script Block Logging | `EnableScriptBlockLogging` (registre) | `1` |

### 5. Problèmes rencontrés

| Problème | Cause | Solution |
|---|---|---|
| Boucle « l'ordinateur a redémarré de manière inattendue » | Bug du setup Windows 11 | `Maj+F10` → `regedit` → `HKLM\SYSTEM\Setup\Status\ChildCompletion\setup.exe` passé de 1 à 3, puis redémarrer sans booter sur l'ISO |
| SSH en timeout vers le poste | Profil réseau **Public** : la règle OpenSSH par défaut ne couvre que Domaine/Privé | Règle `sshd-any` en `-Profile Any` |
| `Add-WindowsCapability` exige une élévation | Console non administrateur | Relancer PowerShell en administrateur |
| Jonction impossible, DNS en timeout | VM du DC éteinte | Démarrer `PurpleAD-DC` avant toute jonction |
| Commandes collées en SSH tronquées | Caractères perdus au collage | Retaper la commande |

## Réalisation — KALI

Machine d'attaque du lab, installée en dernier et **sans Internet** (réseau host-only) : l'ISO installeur de Kali embarque déjà la panoplie par défaut, pas besoin de `apt`.

### Spécifications

| Élément | Valeur |
|---|---|
| VM (VMware) | `PurpleAD-Kali` — 2 vCPU, 4 Go RAM, 40 Go, disque thin |
| OS | Kali Linux 2026.3 (installeur `kali-linux-2026.3-installer-amd64.iso`) |
| Réseau | **Custom : VMnet2 (Host-only)** — ⚠️ pas « Host-only » tout court (= VMnet1) ni NAT |
| Hostname / IP | `kali` / `10.10.10.50` (statique) |
| DNS | 10.10.10.10 (DC01) |
| Compte local | `amin` (sudo) |

### 1. Installation (offline)

Pas de DHCP sur VMnet2 → configuration réseau **manuelle** dans l'installeur :

| Champ | Valeur |
|---|---|
| Adresse IP | `10.10.10.50` |
| Masque réseau | `255.255.255.0` |
| Passerelle | *(vide — réseau isolé)* |
| Serveur de noms | `10.10.10.10` |
| Nom de domaine | *(vide — Kali n'est pas jointe au domaine)* |
| Miroir réseau | **Non** (pas d'Internet ; installation depuis l'ISO) |
| GRUB | `/dev/sda` (disque unique) |

### 2. Accès d'administration (SSH)

```bash
sudo systemctl enable --now ssh
```

Depuis l'hôte : `ssh amin@10.10.10.50`.

### 3. Vérifications

| Test | Commande | Résultat obtenu |
|---|---|---|
| Adresse IP | `ip -br a` | `eth0 … 10.10.10.50/24` |
| Joint le DC | `ping -c 2 10.10.10.10` | réponses |
| Résolution DNS | `nslookup dc01.purplelab.local 10.10.10.10` | `→ 10.10.10.10` |
| Outils présents | `which nxc impacket-GetNPUsers impacket-GetUserSPNs bloodhound-python` | tous trouvés |

### 4. Problèmes rencontrés

| Problème | Cause | Solution |
|---|---|---|
| Boucle PXE « Operating System not found » au reboot | VM éteinte avant la fin de l'install → disque vide, la VM tente le boot réseau | Rebrancher l'ISO (CD/DVD « Connect at power on »), rebooter dessus et **refaire l'install jusqu'au bout** (au besoin Power On to Firmware → Boot → CD-ROM) |
| `ping 10.10.10.10` → `Destination Host Unreachable` malgré la bonne IP | Carte réseau sur le mauvais switch (Host-only/VMnet1 ou NAT), pas VMnet2 | VM Settings → Network Adapter → **Custom : VMnet2**, puis `sudo ip link set eth0 down && sudo ip link set eth0 up` |

### Mise à jour (optionnelle)

Les outils sont déjà présents. Pour mettre Kali à jour avant une campagne : ajouter une carte **NAT temporaire**, `sudo apt update && sudo apt full-upgrade`, puis retirer la carte NAT (retour VMnet2 seul).

### Étape suivante

La VM `SIEM` (10.10.10.100, Wazuh all-in-one + serveur Velociraptor) et la télémétrie sont documentées dans [`02-telemetrie.md`](02-telemetrie.md). Après la validation d'ingestion : Sysmon sur le DC → snapshot `DC-ADDS-clean` → pose des vulnérabilités → snapshot `clean-baseline`.
