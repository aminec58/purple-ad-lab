# CONTEXTE — Lab AD Purple Team (purple-ad-lab)

> **Doc de passation unique** entre les conversations Claude (Projet claude.ai) et **Claude Code**.
> Source de vérité de l'état du lab. À relire en début de session, à mettre à jour en fin de session (procédure en §9).

**Dernière mise à jour :** 2026-11-11 — **S15 TOTALEMENT BOUCLÉ (Windows + Kerberos depuis Kali : 4625/4771/4776 ingérés) et Kali installée + opérationnelle (10.10.10.50, VMnet2, outils présents, SSH actif). `logall` remis à `no`. Prochaine étape : prépa baseline — Sysmon sur le DC (décidé : oui) → snapshot `DC-ADDS-clean` → pose des vulns → snapshot `clean-baseline` → S16 (scénario 1). Restes : canaux Sysmon/PS sur CLIENT02 ; CLIENT01/02 à redémarrer (Disconnected).**

> **Numérotation :** les `Sxx` suivent les **tickets Plane** (projet « Lab AD Purple Team », id ADPT), pas l'ancienne numérotation interne de ce fichier. Les entrées de journal §7 d'avant le 2026-11-05 gardent leur ancien numéro ; se fier à Plane pour « où on en est ».

---

## 0. TL;DR (à lire en premier)

- **Quoi :** lab Active Directory vulnérable, orienté Purple Team (attaque → détection → chasse → remédiation → rejeu), pour GitHub + CV.
- **Où on en est :** forêt **`purplelab.local`** opérationnelle, **télémétrie complète, ingestion validée (Windows + Kerberos depuis Kali)**. SIEM (.100) : Wazuh 4.14.9 all-in-one + Velociraptor 0.77.3, 5 services `enabled`. Agents Wazuh : **DC01 (001) Active** ; **CLIENT01 (002) + CLIENT02 (003) `Disconnected`** (VM à redémarrer / `WazuhSvc` à relancer). 3 clients Velociraptor. **Kali (10.10.10.50) installée et opérationnelle** sur VMnet2, outils présents (`nxc`, `impacket-*`, `bloodhound-python`), SSH actif. **S15 bouclé** : 4768/4769/4688/4104/Sysmon 1-3 (Windows) + 4625/4771/4776 (depuis Kali) vus dans `archives.json` ; Velociraptor validé. Captures `docs/images/s15-ingestion/` (01→07).
- **Prochaine action :** préparer la **baseline** : **Sysmon sur le DC01** (décidé : oui) → snapshot `DC-ADDS-clean` → pose des 5 vulnérabilités (`setup-vulns.ps1`) → snapshot `clean-baseline` sur toutes les VM → **S16 scénario 1** (password spraying). Petits restes : canaux Sysmon/PS sur CLIENT02, redémarrer CLIENT01/02. Les vulnérabilités (phase 3) se posent **après** la baseline.
- **Règle d'or :** l'AD reste *propre* tant que la télémétrie n'est pas en place **et l'ingestion vérifiée** (c'est fait). Les vulnérabilités (phase 3) se posent **après** le snapshot baseline.

---

## 1. Pour Claude Code — lire avant d'agir

### Environnement
| Élément | Valeur |
|---|---|
| Hôte | PC Windows d'Amine (`laptop-m5uslr30`), 32 Go RAM, **VMware Workstation Pro 17** |
| Dossier des VM | `C:\LAB-AD\<nom-VM>\` |
| ISO | `C:\Users\amine\Downloads\` (Server : `SERVER_EVAL_x64FRE_fr-fr.iso` ; SIEM : `ubuntu-24.04.3-live-server-amd64.iso` ; Kali : `kali-linux-2026.3-installer-amd64.iso`) |
| Cache d'outils (hôte) | `C:\LAB-AD\_tools\<outil>\` — téléchargés sur l'hôte (Internet) puis `scp` vers les VM |
| Réseau lab | **VMnet2 host-only**, `10.10.10.0/24`, adressage statique, **pas d'Internet**. L'hôte a une IP sur VMnet2 et joint les VM (SSH OK vers DC + clients + SIEM + Kali) |
| Accès Internet d'une VM | ajouter **temporairement** une 2e carte en **NAT** (download/MAJ), puis la retirer → retour VMnet2 seul. Vécu sur DC, clients et SIEM. |
| Dépôt GitHub | `aminec58/purple-ad-lab` (public, licence MIT, branche `main`), clone local `C:\Users\amine\purple-ad-lab`. Commits uniquement au nom d'Amine (pas de co-auteur Claude). |
| Suivi des tâches | Plane — workspace `cyber_RT`, projet « Lab AD Purple Team », identifiant **ADPT** |
| Vault Obsidian | `C:\Users\amine\Documents\Obsidian-Cyber` (« Obsidian-Cyber ») — relie tous les travaux cyber ; conventions dans son `CLAUDE.md`. Le dépôt reste la source de vérité, la note Obsidian = synthèse + lien. |

### Accès d'administration du lab (SSH depuis l'hôte)
| Machine | Commande | Compte |
|---|---|---|
| DC01 | `ssh "PURPLELAB\Administrateur@10.10.10.10"` | Administrateur du domaine |
| CLIENT01 | `ssh amin@10.10.10.21` | compte local `amin` |
| CLIENT02 | `ssh amin@10.10.10.22` | compte local `amin` |
| SIEM | `ssh amin@10.10.10.100` | compte local `amin` (sudo) |
| Kali | `ssh amin@10.10.10.50` | compte local `amin` (sudo) |

**Interfaces web du SIEM (depuis le navigateur de l'hôte) :**
- Wazuh Dashboard : `https://10.10.10.100` — user `admin` (mdp dans le gestionnaire d'Amine ; sinon `wazuh-passwords.txt` dans `wazuh-install-files.tar`, ou régénérer via `wazuh-passwords-tool.sh`).
- Velociraptor GUI : `https://10.10.10.100:8889` — user `admin` (mdp dans le gestionnaire). **GUI en `bind_address: 0.0.0.0`**. Frontend clients Velociraptor = **`:8000`**.
- ⚠️ **Certificats auto-signés** → « Non sécurisé », normal (accepter l'exception). **Utiliser Brave (ou Edge)** : le Chrome managé Orange bloque les invites d'auth Basic de Velociraptor.

- Shell SSH Windows : **se fier à l'invite** (`C:\…>` = cmd ; `PS C:\…>` = PowerShell), pas au nom de la machine. SIEM et Kali = bash.
- **Déploiement multi-postes :** préférer `scp` + `ssh amin@$ip "<cmd>"` **lancés depuis l'hôte** plutôt que coller dans une session SSH (évite les caractères mangés). Mot de passe demandé à chaque appel (pas de clé SSH).
- **Secrets hors dépôt :** mdp Administrateur du domaine ; mdp `admin` Wazuh + Velociraptor ; `wazuh-install-files.tar` ; `server.config.yaml` Velociraptor (**clé privée CA**) ; **`client.config.yaml` Velociraptor** (CA publique + nonce). → gestionnaire de mots de passe d'Amine, **jamais** dans le dépôt.
- SSH = accès d'admin → bruit dans les logs (sshd, logons type 3) à connaître pour ne pas le confondre avec une attaque en phase 4.

### Ce que Claude Code peut / ne peut pas faire
- ✅ Écrire et maintenir le dépôt : README, scripts (`.ps1`, `.sh`), règles Wazuh/Sigma, requêtes VQL Velociraptor, schéma d'archi, config agent.
- ✅ Générer les scripts qu'Amine exécute **lui-même** dans les VM (souvent via SSH depuis l'hôte).
- ❌ **Aucun accès direct aux VM** (réseau host-only isolé). Toute action dans une VM = commande fournie à Amine, qui renvoie la sortie. La **prise de contrôle (computer use)** pilote le bureau de l'hôte (fenêtres VMware, assistants) mais est **peu fiable pour piloter l'intérieur d'une VM** et une install d'OS longue (fenêtres empilées, focus, attentes) — vécu en install Kali, finie à la main par Amine. Le **navigateur intégré de Claude** ne peut pas ouvrir les GUI du SIEM (certificat auto-signé) → diagnostiquer via `curl` depuis le SIEM.
- ❌ Ne jamais committer de secrets réels ni de loot d'attaque (hashes, tickets, dumps, zips BloodHound) — `.gitignore` les bloque. Les mots de passe *volontairement faibles* des comptes vulnérables sont OK (documentés comme tels).

### Conventions
- Langue : **français** (docs, commits, commentaires). Réponses et scripts **concis**.
- **Chaque bloc de commandes commence par la machine cible** : `🖥️ PurpleAD-DC`, `🖥️ PurpleAD-CLIENT01/02`, `🖥️ PurpleAD-Kali`, `🖥️ PurpleAD-SIEM`, ou `🖥️ Hôte Windows`.
- Une session de travail = un ticket Plane `Sxx`, journalisée en §7.
- Commits : style `type: description` en français, **sans ligne `Co-Authored-By` Claude**.
- Snapshots : **de travail** `<VM>-<étape>` ; **baseline finale** `clean-baseline-<date>` sur chaque VM, juste avant la 1re attaque.
- **Arborescence du dépôt** (scaffold du 27/10) :
  ```
  purple-ad-lab/
  ├── README.md
  ├── LICENSE                         # MIT
  ├── .gitignore                      # bloque secrets, loot d'attaque, images de VM
  ├── docs/
  │   ├── CONTEXTE.md                 # ce fichier (copie du doc de passation)
  │   ├── 00-architecture.md
  │   ├── 01-deploiement-infra.md     # 1 section par VM (DC01, Clients, Kali, SIEM)
  │   ├── 02-telemetrie.md            # audit, PowerShell logging, Sysmon, agents, validation ingestion (bloquant)
  │   ├── 03-scenarios/               # 01-password-spraying … 05-path-to-da (+ 06 opt.)
  │   └── images/                     # captures (dont s13-siem/ et s15-ingestion/) + architecture.png
  ├── config/
  │   ├── ad/setup-vulns.ps1          # pose des 5 faiblesses (phase 3 uniquement)
  │   ├── gpo/audit-policy.md + setup-audit-gpo.ps1
  │   ├── sysmon/                     # sysmonconfig-export.xml (SwiftOnSecurity figée) + README.md
  │   ├── velociraptor/  wazuh/decoders/   # versions ASSAINIES uniquement (pas de secrets)
  ├── detection/sigma/  detection/wazuh-rules/
  ├── hunting/velociraptor/           # requêtes VQL
  ├── attack/scripts/
  └── remediation/hardening-ad.md
  ```
- Images : **`docs/images/`** (pas `docs/img/`). Captures S13 : `docs/images/s13-siem/` (01→06, committées). Captures S15 : `docs/images/s15-ingestion/` (01→07, committées — commit `5f2b716`). `architecture.png` + `.svg` committés.
- Tenir à jour la section **« Avancement »** du README et le **tableau des scénarios**.

### Pièges déjà rencontrés (ne pas reproduire)
- **Install Windows Server :** 1re ligne = **Core** (sans GUI). Pour la GUI, « (expérience de bureau) » → **↓ puis Entrée**. Core → GUI impossible après coup.
- **Install Windows 11 :** édition **Pro** (pas Famille, sinon pas de jonction domaine).
- **Boucle d'install Win 11** (« redémarré de manière inattendue ») : **Maj+F10** → `regedit` → `HKLM\SYSTEM\Setup\Status\ChildCompletion\setup.exe` 1→3 → OK ; au reboot ne pas presser de touche au « Press any key ».
- **Boot sur ISO (UEFI) :** VM → Power → **Power On to Firmware** → Boot Manager → CDROM.
- **OOBE Win 11 sans Internet :** à l'écran réseau **Maj+F10** → `start ms-cxh:localonly`. Repli : `reg add …\OOBE /v BypassNRO /t REG_DWORD /d 1 /f` puis reboot.
- **OpenSSH sur les clients :** `Add-WindowsCapability` télécharge depuis Windows Update → passer en **NAT** le temps de l'install, puis retour VMnet2. Exige PowerShell **admin**.
- **SSH client qui timeout = pare-feu** (réseau « Public ») : `New-NetFirewallRule -Name sshd-any -DisplayName "sshd Any" -Enabled True -Direction Inbound -Protocol TCP -Action Allow -LocalPort 22 -Profile Any`.
- **SSH qui timeout juste après démarrage d'une VM :** attendre la fin du boot, réessayer.
- **Collage SSH qui mange des caractères** : si une commande collée casse, la **retaper** (ou lancer depuis l'hôte en `ssh "…" "<cmd>"`).
- **Le DC doit être démarré** avant install/jonction d'un client ou avant que le SIEM/Kali résolve `dc01.purplelab.local`. Une cible éteinte → `ping` « Destination Host Unreachable ».
- **Ne jamais changer l'IP/le réseau d'une VM depuis une session SSH** (la session coupe). Le faire depuis la console VMware (VM éteinte pour ajout/retrait d'une carte NAT).
- **`Install-ADDSForest` redémarre tout seul** : attendre le reboot avant zone inverse/PTR.
- **scp/ssh depuis PowerShell :** guillemets autour de TOUTE la cible (`"PURPLELAB\Administrateur@10.10.10.10:C:/..."`), sinon `@` est interprété.
- Sans passerelle, profil réseau parfois « Public » après reboot → `Restart-Service NlaSvc -Force`.
- **Install Ubuntu (SIEM) — stockage LVM :** le partitionnement guidé n'alloue par défaut que ~la moitié du disque au LV `/`. **Éditer `ubuntu-lv` → taille max** (fait en S13 → `/` = 77 Go).
- **Vérif d'intégrité d'un binaire GitHub :** lire le **digest officiel** via l'API release GitHub (`/repos/<org>/<repo>/releases/tags/<tag>`), pas un hash lu dans un résumé de page.
- **Signature GPG d'un binaire `.gz` :** la `.sig` signe le binaire **décompressé** → `gpg --verify x.sig x` (après `gunzip`). Clé Velociraptor `0572F28B4EF19A043F4CBBE0B22A7FB19CB6CFA1`.
- **Velociraptor refuse de tourner en root :** commandes admin en `sudo -u velociraptor velociraptor --config /etc/velociraptor/server.config.yaml …` (c'est bien `/etc/velociraptor/…` = config du service, lisible par l'user `velociraptor`, pas `~/velo/…`).
- **Velociraptor « Not authorized » dans la GUI :** Chrome managé Orange bloque l'auth Basic → **Brave (ou Edge)**.

#### Pièges S14 (déploiement des agents/clients)
- **Commandes Windows sur le bon hôte :** `msiexec` / `net` / `sc` se lancent dans la session SSH d'une **machine Windows**, **pas** sur le SIEM/Kali (bash) → sinon « command not found ».
- **PowerShell : `sc` = alias de `Set-Content`** → `sc query` n'affiche rien d'utile. Utiliser **`sc.exe query`** ou **`Get-Service`**. (En cmd, `sc query` est normal.)
- **`msiexec /q` échoue en silence.** Diag : `msiexec /i … /qn /l*v C:\Windows\Temp\wz.log … & echo EXIT=%errorlevel%`. Codes : 0 OK, 1603 erreur install, 1619/1620 MSI illisible (mauvais download), 1625 bloqué par policy.
- **Service pas encore enregistré juste après `msiexec`** → `net start WazuhSvc` « nom de service non valide ». Attendre ~10 s (ou `sc.exe query WazuhSvc`) avant de démarrer.
- **Wazuh — nom d'agent unique obligatoire :** copier-coller sans changer `WAZUH_AGENT_NAME` → `ERROR: Duplicate agent name`, agent **non enrôlé**. **Toujours `hostname` avant d'installer.** Correctif : `& 'C:\Program Files (x86)\ossec-agent\agent-auth.exe' -m 10.10.10.100 -A <BON_NOM>` puis `Restart-Service WazuhSvc`.
- **Après reboot du SIEM, les services Wazuh ne remontent pas forcément** → `agent_control -l` renvoie `Cannot connect to 'queue/db/wdb': Connection refused`. `sudo systemctl start wazuh-manager`, puis **`systemctl enable`** les services.
- **Agent démarré AVANT que le manager soit up** → `Never connected` / `Disconnected` → `net stop WazuhSvc & net start WazuhSvc` (ou redémarrer la VM cliente).
- **Velociraptor `config client` :** en `sudo -u velociraptor … --config /etc/velociraptor/server.config.yaml` (la commande ouvre `/opt/velociraptor`). Gare au **fichier vide `root:root`** laissé par un `sudo tee` raté qui bloque ensuite les redirects `>`.
- **Velociraptor `server_urls` = `https://localhost:8000/`** par défaut → les clients ne joindraient pas le serveur. Corriger en `https://10.10.10.100:8000/` (`sed -i 's#https://localhost:8000/#https://10.10.10.100:8000/#'`). En self-signed, le TLS épingle la CA + un CN interne fixe, pas le hostname → mettre l'IP est sans risque.
- **Binaire Windows Velociraptor = `.exe.gz`** (pas d'asset `.exe` direct). Prendre `velociraptor-v0.77.3-windows-amd64.exe.gz` (non-legacy), le **décompresser** (`System.IO.Compression.GZipStream`) → `velociraptor.exe` (~70 Mo), vérifier taille + `Get-AuthenticodeSignature`=Valid. Une URL `…amd64.exe` sans `.gz` → 404 → « Not Found » (9 octets).
- **`scp` ne crée pas le dossier distant** → `dest open … No such file or directory`. Faire `ssh <cible> "mkdir C:\Velociraptor"` **avant** le `scp` de l'exe.

#### Pièges S15 (validation de l'ingestion)
- **Vérifier l'ingestion sans règle associée :** activer temporairement `<logall>` + `<logall_json>` = `yes` sur le manager (`/var/ossec/etc/ossec.conf`, restart), puis compter dans `/var/ossec/logs/archives/archives.json`. Sinon les events sans alerte n'apparaissent nulle part. **Remettre à `no` après** (fait).
- **Canaux manquants dans l'`ossec.conf` de l'agent :** par défaut seulement `Application`/`Security`/`System`. Ajouter deux `<localfile>` `eventchannel` pour `Microsoft-Windows-Sysmon/Operational` et `Microsoft-Windows-PowerShell/Operational`, sinon **4104 et Sysmon ne remontent pas**. `eventchannel` ne lit que les events **postérieurs** au `Restart-Service WazuhSvc` → régénérer les témoins après. (Fait sur CLIENT01, **reste CLIENT02**.)
- **`runas /netonly` via SSH ne marche pas :** la fenêtre `cmd` s'ouvre sur le bureau de la VM (invisible en SSH) et les commandes tapées repartent dans la session locale `amin` (sans creds domaine) → `klist get krbtgt` échoue `0x8009030e`, `\\dc01\SYSVOL` « introuvable ». **Pour générer 4768/4769 :** `net use \\dc01.purplelab.local\SYSVOL /user:PURPLELAB\Administrateur *` (authentifie dans la session courante). Le `klist` interactif peut afficher 0 ticket (session d'ouverture réseau distincte) : normal, le DC a quand même journalisé.
- **4625/4771/4776 depuis Kali :** `nxc smb 10.10.10.10 -u pentest_fake -p 'Wrong123!'` (NTLM → 4625+4776) et `impacket-getTGT purplelab.local/Administrateur:'Wrong123!' -dc-ip 10.10.10.10` (pré-auth Kerberos échouée → 4771). Lockout domaine désactivé par défaut → sans risque pour Administrateur.
- **Manager `failed` au boot malgré `systemctl enable` :** course de démarrage ; `sudo systemctl start wazuh-manager` relance (les agents repassent `Active`). Robustesse : drop-in `/etc/systemd/system/wazuh-manager.service.d/override.conf` → `[Unit] After=wazuh-indexer.service` + `[Service] Restart=on-failure / RestartSec=15`, puis `daemon-reload`.
- **Velociraptor après reboot :** les 3 clients se reconnectent seuls (~1 min) une fois le serveur up ; inutile de bouncer leur service sauf si l'un manque passé ce délai (`Restart-Service Velociraptor` sur le poste).

#### Pièges Kali (install + réseau)
- **Carte réseau de Kali = VMnet2 obligatoire :** choisir **« Custom: Specific virtual network » → VMnet2**, PAS « Host-only » tout court (= VMnet1) ni NAT. Sur le mauvais switch, Kali a bien son IP statique 10.10.10.50 mais **ne joint rien** (`ping` → `Destination Host Unreachable` = pas de réponse ARP). Correctif : changer le switch dans VM Settings (à chaud OK), puis sur Kali `sudo ip link set eth0 down && sudo ip link set eth0 up`.
- **Install offline (VMnet2 sans Internet) OK :** l'installeur `kali-linux-2026.3-installer-amd64.iso` embarque le metapackage par défaut → `nxc`, `impacket-*`, `bloodhound-python` présents **sans `apt`**. Config réseau manuelle dans l'installeur (pas de DHCP sur VMnet2) : IP `10.10.10.50`, masque `255.255.255.0`, passerelle **vide**, DNS `10.10.10.10`, nom de domaine **vide** (Kali n'est pas jointe au domaine), **miroir réseau = Non**.
- **GRUB :** à l'écran « périphérique où installer GRUB », taper **`/dev/sda`** (disque unique).
- **VM éteinte en pleine install → boucle PXE / « Operating System not found » :** l'install n'était pas finie, le disque est vide → la VM tente le réseau (PXE, échoue sur VMnet2). Correctif : VM Settings → CD/DVD « Connect at power on » + ISO Kali, rebooter sur l'ISO et **refaire l'install jusqu'au bout** (au besoin VM → Power On to Firmware → Boot → CD-ROM en premier).
- **Mettre Kali à jour plus tard :** carte **NAT temporaire** → `sudo apt update && sudo apt full-upgrade` → retour VMnet2. Pas indispensable (outils déjà présents), mais utile avant une campagne.

### Bruit connu dans la télémétrie (ne pas confondre avec une attaque)
- **Sysmon ID 8 (CreateRemoteThread) `CtrlRoutine` :** csrss → `powershell.exe`, `StartFunction = CtrlRoutine` = gestionnaire Ctrl+C → **bénin**. À exclure dans les règles Wazuh.
- **SSH d'administration :** sshd + logons type 3 (DC, clients, SIEM, Kali).

---

## 2. Objectif et critère de réussite

5 scénarios (+ 1 optionnel, §5), chacun en **boucle complète** : 1) attaque Kali · 2) détection Wazuh · 3) chasse Velociraptor · 4) remédiation (règle + durcissement AD) · 5) rejeu.

**Un scénario n'est « fini » que si, au rejeu, la détection se déclenche ET la remédiation bloque/limite l'attaque.**

**Livrable final :** README GitHub = schéma d'archi, prérequis, tableau récap par scénario (attaque / MITRE / détection Wazuh / requête Velociraptor / règle ajoutée / remédiation).

---

## 3. Architecture figée

| VM (VMware) | Hostname | IP | OS | Rôle / état télémétrie |
|---|---|---|---|---|
| PurpleAD-DC | DC01 | 10.10.10.10 | Windows Server 2022 Std Eval 21H2, build 20348, **GUI** | AD DS + DNS (vulnérable plus tard). **Wazuh ✅ Active (001)** · **Velociraptor ✅ en ligne** (`C.d50bcb70988d04ab`) |
| PurpleAD-CLIENT01 | CLIENT01 | 10.10.10.21 | Windows 11 (Velociraptor : Enterprise Eval 26H2) | **Sysmon ✅**, **Wazuh (002)** (+ canaux Sysmon/PS ajoutés S15) ⚠️ actuellement `Disconnected` (VM à redémarrer), **Velociraptor** (`C.b7e592d7b6ff6770`) |
| PurpleAD-CLIENT02 | CLIENT02 | 10.10.10.22 | Windows 11 (Velociraptor : Enterprise Eval 26H2) | **Sysmon ✅**, **Wazuh (003)** (⚠️ canaux Sysmon/PS à ajouter) ⚠️ actuellement `Disconnected`, **Velociraptor** (`C.6502c9c7dd461702`) |
| PurpleAD-Kali | kali | 10.10.10.50 | Kali 2026.3 | Attaque — **✅ installée et opérationnelle** (VMnet2, outils présents, SSH actif). User local `amin`. |
| PurpleAD-SIEM | siem | 10.10.10.100 | Ubuntu Server 24.04.5 | **Wazuh 4.14.9 (manager 000) + serveur Velociraptor 0.77.3 ✅** (5 services `enabled`) |

- Domaine : **`purplelab.local`**, NetBIOS **`PURPLELAB`**, niveau forêt/domaine 2016.
- DNS de toutes les machines → 10.10.10.10 ; le DC pointe sur 127.0.0.1. Pas de passerelle. Zone inverse + PTR DC01. SIEM + Kali : DNS 10.10.10.10, `Europe/Paris`.
- **Sysmon (clients) :** `Sysmon64.exe` 15.22 + `sysmonconfig-export.xml` (SwiftOnSecurity, commit `1836897`), journal 256 Mo. **Pas d'ID 10 (ProcessAccess)** → accès LSASS non journalisés (écart documenté du scénario 4). **Pas encore de Sysmon sur le DC — décidé : à ajouter avant la baseline.** Copie figée : `config/sysmon/`.
- **Agents Wazuh :** MSI **4.14.9**, enrôlement authd (1515), `WAZUH_MANAGER=WAZUH_REGISTRATION_SERVER=10.10.10.100`, noms DC01/CLIENT01/CLIENT02. Config `C:\Program Files (x86)\ossec-agent\ossec.conf` (`<address>10.10.10.100</address>`). **Canaux :** DC01 = Application/Security/System ; **CLIENT01 = + `Microsoft-Windows-Sysmon/Operational` + `Microsoft-Windows-PowerShell/Operational` (S15)** ; **CLIENT02 = ces deux canaux restent à ajouter.**
- **Clients Velociraptor :** binaire Windows `velociraptor-v0.77.3-windows-amd64.exe` (décompressé du `.exe.gz`, ~70 Mo) + `client.config.yaml` dans `C:\Velociraptor\`, installé en service via `velociraptor.exe --config … service install`. **3 clients** dans la GUI `:8889`.
- **SIEM — composants (S13/S14) :**
  - **Wazuh 4.14.9 all-in-one** : manager, indexer (OpenSearch 2.19.6, heap 1 Go), dashboard, filebeat. Dépôt Wazuh **figé**. authd (1515), remoted (1514). **5 services `systemctl enable` (S15)** — mais le manager a fini `failed` à un reboot (course de démarrage) → `start` manuel, drop-in `Restart=on-failure` conseillé (§1).
  - **Serveur Velociraptor 0.77.3** (sumo-musl, service `.deb` `velociraptor_server`). GUI `:8889` (`0.0.0.0`), frontend clients `:8000`, user `admin`. Config service `/etc/velociraptor/server.config.yaml` (secret). **`client.config.yaml`** généré en S14 (`config client`), `server_urls = https://10.10.10.100:8000/`, dans `~/velo/`.
- **Note scénario #6 (BadSuccessor) :** nécessiterait un **DC/serveur Windows Server 2025**. VM non créée — à décider en fin de projet.

### Ressources et état des VM
Toutes dans `C:\LAB-AD\<nom>\`, carte **Custom : VMnet2 (Host-only)** (pour Kali : « Custom: Specific virtual network → VMnet2 »).
⚠️ Onglets VMware fermés : rouvrir via **File → Open → `C:\LAB-AD\<nom>\<nom>.vmx`**.
⚠️ **Espace disque hôte (C:) limité** (~24 Go libres au moment de l'install Kali) : pour gagner de la place, éteindre proprement (pas suspendre) les VM inutiles (les `.vmem` ≈ RAM), supprimer les snapshots de travail, compacter les disques thin. **Synchro Google Drive / OneDrive = mauvaise idée** pour les VM → disque externe ou nettoyage.

| VM | RAM | vCPU | Disque | OS installé / état |
|---|---|---|---|---|
| PurpleAD-DC | 4 Go | 2 | 60 Go | ✅ Server 2022 **GUI**, DC promu, **Wazuh + Velociraptor** |
| PurpleAD-CLIENT01 | 4 Go | 2 | 64 Go | ✅ Win 11, joint, OpenSSH, **Sysmon + Wazuh (+ canaux S15) + Velociraptor** |
| PurpleAD-CLIENT02 | 4 Go | 2 | 64 Go | ✅ idem CLIENT01 (canaux Sysmon/PS à ajouter) |
| PurpleAD-Kali | 4 Go | 2 | 40 Go | ✅ **Kali 2026.3 installée**, VMnet2, outils présents, SSH actif |
| PurpleAD-SIEM | 8 Go | 4 | 80 Go (`/`=77 Go) | ✅ Ubuntu 24.04.5, **Wazuh 4.14.9 + Velociraptor** |

~28 Go RAM alloués sur 32 avec Kali : tout tourne en parallèle mais serré (disque hôte surtout). Disques thin-provisioned.

---

## 4. Roadmap

| Phase | Ticket Plane | Contenu | État |
|---|---|---|---|
| 1 — Infra | S04 | Création des 5 VM sur VMnet2 | ✅ |
| | S05 | Snapshots baseline | ⏸️ reporté (baseline = juste avant 1re attaque) |
| | S06 | Install Server 2022 + promotion DC | ✅ (reste snapshot `DC-ADDS-clean`) |
| | S07 | Install Win 11 CLIENT01/02 + jonction domaine | ✅ |
| | — | **Install Kali (10.10.10.50)** | ✅ **faite (11/11)**, VMnet2, outils présents |
| 2 — Télémétrie | S09 | GPO audit avancé (4768/4769/4771, 4688, comptes, logon) | ✅ DC + clients |
| | S10 | PowerShell Script Block (4104) + Module Logging (4103) | ✅ DC + clients |
| | S11 | Sysmon SwiftOnSecurity sur CLIENT01/02 | ✅ |
| | S13 | Install Wazuh all-in-one + serveur Velociraptor (VM SIEM) | ✅ |
| | S14 | Déployer agents Wazuh + clients Velociraptor (DC + postes) | ✅ |
| | **S15 (+ S12)** | **Valider l'ingestion + requête Velociraptor + partie Kali** | ✅ **COMPLET** (Windows : 4768/4769/4688/4104/Sysmon 1-3 + Velociraptor ; Kali : 4625/4771/4776) |
| 3 — Baseline + Vulnérabilisation | — | Sysmon DC → snapshot `DC-ADDS-clean` → `config/ad/setup-vulns.ps1` → snapshot `clean-baseline` | ⏳ **prochaine** |
| 4 — Scénarios | S16→S20 | 5 boucles complètes (§5) | ⏳ |
| 4bis — Extension (opt.) | S23 | Scénario #6 BadSuccessor : + serveur Server 2025 | ⏳ optionnel |
| 5 — Livrable | S21 | README final | ⏳ |

---

## 5. Scénarios

| # | Attaque | Outil | MITRE | Fichier | État |
|---|---|---|---|---|---|
| 1 | Password spraying | CrackMapExec / nxc | T1110.003 | `docs/03-scenarios/01-password-spraying.md` | ⏳ |
| 2 | AS-REP roasting | Impacket GetNPUsers / Rubeus | T1558.004 | `02-asrep-roasting.md` | ⏳ |
| 3 | Kerberoasting | Rubeus / Impacket GetUserSPNs | T1558.003 | `03-kerberoasting.md` | ⏳ |
| 4 | Pass-the-Hash + latéral | Mimikatz + CrackMapExec | T1550.002 | `04-pass-the-hash.md` | ⏳ — **écart prévu : pas de Sysmon ID 10 (LSASS)** → remédiation = règle ProcessAccess lsass |
| 5 | Chemin vers Domain Admin | BloodHound / SharpHound | T1087 | `05-path-to-da.md` | ⏳ |
| 6 | BadSuccessor (abus dMSA) | SharpSuccessor / Rubeus / PowerShell | T1098 / T1078 | `06-badsuccessor.md` | ⏳ **optionnel — nécessite un DC Server 2025** |

**Scénario #4 — note détection :** config SwiftOnSecurity d'origine → dump LSASS Mimikatz = **aucun** Sysmon ID 10. « Détection » = constater l'angle mort ; « Remédiation » = `config/sysmon/sysmonconfig-purplelab.xml` (+ `<ProcessAccess onmatch="include">` sur `lsass.exe`, `GrantedAccess` typiques Mimikatz) rechargé par `Sysmon64.exe -c` + règle Wazuh ; rejeu → ID 10 + alerte.

**Scénario #6 — cadrage :** pré-requis **Server 2025** dédié. Abus du lien de migration dMSA. Détection : SACL + 4662 sur attributs dMSA, 5136/5137, auth dMSA 2946. Remédiation : verrouiller `CreateChild`/write sur les OU + tiering.

---

## 6. Décisions prises (et pourquoi)

| Date | Décision | Raison |
|---|---|---|
| 2026-10 | VMware Workstation Pro, host-only VMnet2, `10.10.10.0/24` statiques | Isolement, reproductibilité |
| 2026-10-27 | Scaffold du dépôt | Structure fixée |
| 2026-10-31 | Domaine `purplelab.local` 2016 ; vulns après télémétrie ; baseline reporté | Baseline propre |
| 2026-11-01 | Administration en SSH depuis l'hôte | Confort, sortie lisible |
| 2026-11-03 | Scénario #6 au backlog ; clients Win 11 + OpenSSH ; mdp Administrateur réinitialisé | Valeur CV ; débloquer la jonction |
| 2026-11-04 | Sysmon config SwiftOnSecurity non modifiée → pas d'ID 10 ; commits au seul nom d'Amine | Angle mort LSASS = écart documenté |
| 2026-11-05 | SIEM Ubuntu + LV `/` max ; Wazuh 4.14 all-in-one + dépôt figé ; Velociraptor 0.77.3 ; Brave pour les GUI | voir S13 |
| 2026-11-05 | Agents Wazuh via MSI 4.14.9 + enrôlement authd (noms = hostnames) | Matcher la version du manager ; enrôlement auto |
| 2026-11-05 | Clients Velociraptor via binaire `.exe` + `service install` (pas le MSI stock) | Le MSI stock n'embarque pas notre `client.config.yaml` ; l'exe + `--config` pointe sur notre serveur |
| 2026-11-08 | Events Kerberos témoins via `net use /user:` (pas `runas /netonly` en SSH) | `runas /netonly` ouvre une fenêtre invisible en SSH ; `net use` authentifie dans la session courante |
| 2026-11-08 | Robustesse du manager au boot : drop-in `Restart=on-failure` (+ `After=wazuh-indexer`) conseillé | Il perd parfois la course de démarrage et finit `failed` malgré `enable` |
| 2026-11-11 | Kali : carte **VMnet2** (Custom: Specific virtual network), **install offline** depuis l'ISO | Kali sur Host-only/VMnet1 ne joignait rien ; l'ISO installer embarque les outils, pas besoin d'Internet |
| 2026-11-11 | **Sysmon aussi sur le DC01** (avant baseline) | Meilleure détection côté DC pour les scénarios 4/5 |

---

## 7. Journal des sessions (le plus récent en haut)

### S15 (suite) + Install Kali — 2026-11-09 → 11 — Kali opérationnelle, partie Kerberos de S15 bouclée (✅)
- **Install Kali :**
  - 🖥️ VMware — VM `PurpleAD-Kali` déjà créée (31/10) ; tentative de recréation via computer use interrompue (« .vmx already exists », fenêtres VMware empilées, computer use peu fiable pour ça) → Amine a **fini l'install à la main**.
  - 🖥️ Kali — install offline depuis l'ISO : réseau manuel (IP 10.10.10.50/24, passerelle vide, DNS 10.10.10.10, domaine vide, miroir = Non), GRUB sur `/dev/sda`. Au 1er essai, VM éteinte avant la fin → boucle PXE « OS not found » ; refaite jusqu'au bout.
  - 🖥️ Kali — vérifs : IP `10.10.10.50/24` OK ; outils présents (`nxc`, `impacket-GetNPUsers/GetUserSPNs/getTGT`, `bloodhound-python`) ; `systemctl enable --now ssh`.
  - **Piège réseau :** Kali ne joignait pas le DC (`Destination Host Unreachable`) car sa carte n'était pas sur **VMnet2** → corrigé (Custom: Specific virtual network → VMnet2), `ip link down/up`, puis `nslookup dc01.purplelab.local` OK.
- **S15 — partie Kali (Kerberos) :**
  - 🖥️ SIEM — `logall`/`logall_json` → `yes`, restart manager. `agent_control -l` : DC01 (001) **Active** ; CLIENT01/02 **Disconnected** (VM non démarrées).
  - 🖥️ Kali — `nxc smb 10.10.10.10 -u pentest_fake -p 'Wrong123!'` + `impacket-getTGT purplelab.local/Administrateur:'Wrong123!'` → échecs voulus.
  - 🖥️ SIEM — `archives.json` : **4625=1, 4771=1, 4776=1** → ingestion OK. `logall` remis à `no`.
- **Reste :** canaux Sysmon/PS sur **CLIENT02** ; **redémarrer CLIENT01/02** (Disconnected) ; Sysmon sur le DC ; snapshot `DC-ADDS-clean` ; puis phase 3 (vulns) + snapshot `clean-baseline` ; S16.

### S15 — 2026-11-06 → 08 — Validation de l'ingestion + Velociraptor à blanc (✅ périmètre Windows)
- **Fait :**
  - 🖥️ SIEM — `systemctl enable` des 5 services ; `<logall>`/`<logall_json>` → `yes` (archivage temporaire).
  - 🖥️ CLIENT01 — ajout des canaux `Microsoft-Windows-Sysmon/Operational` + `Microsoft-Windows-PowerShell/Operational`, `Restart-Service WazuhSvc`.
  - 🖥️ CLIENT01 — events témoins : `whoami` (4688), `Write-Output 'S15-test-scriptblock'` (4104), `Test-NetConnection 445` (Sysmon 3) ; `net use \\dc01…\SYSVOL /user:PURPLELAB\Administrateur` pour 4768/4769.
  - 🖥️ SIEM — `archives.json` : 4768/4769 sur 001, 4688/4104/Sysmon 1-3 sur 002 → tous > 0.
  - 🖥️ Velociraptor — collecte `Windows.System.Pslist` sur CLIENT01 + chasse `Windows.EventLogs.EvtxHunter` `IocRegex=S15-test-scriptblock` → retrouve le 4104. Captures `docs/images/s15-ingestion/` (01→07).
- **Livrable :** section « Validation de l'ingestion » dans `docs/02-telemetrie.md` + 7 captures, committées (commit `5f2b716`). (Piège git : upload web avait mis les fichiers dans `docs/docs/` → corrigé par `git mv`. Un `.git` parasite traînait dans `C:\Users\amine` → renommé.)
- **Incidents résolus :** manager `failed` au boot → `systemctl start` ; `runas /netonly` via SSH inopérant → `net use`. Détails au §1.

### S14 — 2026-11-05 → 06 — Agents Wazuh + clients Velociraptor déployés (✅)
- 🖥️ Hôte → DC01/CLIENT01/CLIENT02 — MSI Wazuh **4.14.9** + enrôlement → 3 agents `Active` (001/002/003). Clients Velociraptor (binaire `.exe` décompressé du `.exe.gz` + `client.config.yaml`, `service install`) → 3 en ligne GUI `:8889`.
- **Incidents :** commandes Windows sur le SIEM ; `msiexec /q` silencieux ; CLIENT02 enrôlé « CLIENT01 » (Duplicate) → `agent-auth -A CLIENT02` ; DC01 `Never connected` → restart ; download Velociraptor 9 octets (URL `.exe` au lieu de `.exe.gz`) ; `scp` sans `mkdir` préalable. Détails §1.

### S13 — 2026-11-05 — Wazuh all-in-one + serveur Velociraptor sur le SIEM (✅)
- Install Ubuntu 24.04.5 (IP .100, LV `/` 77 Go), **Wazuh 4.14** (dépôt figé), **Velociraptor 0.77.3** (hash API + GPG, GUI `:8889`). Captures `docs/images/s13-siem/` (01→06, committées).

### S11 — 2026-11-04 — Sysmon SwiftOnSecurity sur CLIENT01/02 (✅)
- `Sysmon64.exe` 15.22 + SwiftOnSecurity `1836897`, `<ProcessAccess include>` vide → pas d'ID 10. Journal 256 Mo. Copie figée `config/sysmon/`.

### S07 — 2026-11-03 — Clients Windows 11 joints au domaine (✅)
- Win 11 (compte local `amin`), OpenSSH + `sshd-any`, IP .21/.22, `Add-Computer purplelab.local`. mdp Administrateur réinitialisé. (NB : Velociraptor remonte « Enterprise Evaluation 26H2 » — à vérifier vs « Pro ».)

### S10 — 2026-11-02 — PowerShell Script Block + Module Logging (✅ DC01) — posé en S09. Durcissement à prévoir : désactiver PowerShell v2.
### S09 — 2026-11-02 — GPO d'audit avancé (✅ DC01) — `PURPLELAB - Audit avance`, 11 sous-catégories, cmdline 4688, Security 512 Mo.
### S08 — 2026-11-02 — Documentation des 5 faiblesses du DC (doc only).
### S06 — 2026-10-31→11-01 — Promotion du DC (✅, reste snapshot).
### S05 / S04 — 2026-10-31 — Snapshots reportés / 5 VM créées.

**Les 5 faiblesses (phase 3, à poser plus tard) :** #1 mdp faibles + `LockoutThreshold 0` (`j.dupont`, `m.martin`, `a.roux` ; leurres `l.bernard`/`s.petit`, T1110.003) ; #2 `svc-sql` + SPN `MSSQLSvc/sql01…:1433` + RC4 (T1558.003) ; #3 `a.roux` `DONT_REQ_PREAUTH` (T1558.004) ; #4 `svc-web` délégation contrainte + transition de protocole vers `cifs/DC01` (T1550.002) ; #5 `j.dupont` → `Helpdesk` → `GenericAll` sur `svc-web` → DC (T1087).

---

## 8. Points ouverts / à vérifier
- [x] VMnet2 fonctionnel (SSH DC + clients + SIEM + Kali)
- [ ] Confirmer DHCP VMnet2 désactivé
- [ ] Snapshot `DC-ADDS-clean` (après Sysmon DC)
- [x] Sysmon SwiftOnSecurity sur CLIENT01/02 — S11
- [x] Wazuh + serveur Velociraptor sur le SIEM — S13
- [x] Agents Wazuh + clients Velociraptor sur DC + postes — S14
- [x] `systemctl enable` des services SIEM — S15 (⚠️ drop-in `Restart=on-failure` conseillé, §1)
- [x] **S15 complet** : ingestion Windows (4768/4769/4688/4104/Sysmon 1-3) + Velociraptor + Kerberos Kali (4625/4771/4776) ✅
- [x] `logall`/`logall_json` remis à `no`
- [x] **Installer Kali** (10.10.10.50) — ✅ faite, VMnet2, outils présents, SSH
- [ ] **Redémarrer CLIENT01/02** (actuellement `Disconnected`) + relancer `WazuhSvc` si besoin
- [ ] Canaux Sysmon/PowerShell `ossec.conf` : faits sur CLIENT01, **à faire sur CLIENT02**
- [ ] **Sysmon sur le DC01** (décidé : oui) — avant le snapshot baseline
- [ ] CLIENT02 : bloc `enrollment` de `ossec.conf` contient encore `CLIENT01` (cosmétique)
- [ ] Vérifier l'édition Windows 11 des clients (Velociraptor : « Enterprise Evaluation 26H2 » ; S07 : « Pro »)
- [ ] Mettre Kali à jour (`apt full-upgrade` via NAT temporaire) — optionnel avant campagne
- [ ] Désactiver PowerShell v2 (postes + DC)
- [x] Captures `docs/images/` S13 + S15 committées ; `architecture.png`/`.svg` présents
- [ ] (opt.) Scénario #6 BadSuccessor : serveur Server 2025

---

## 9. Procédure de mise à jour de ce fichier
En fin de session (Projet claude.ai **ou** Claude Code) :
1. Mettre à jour la date, la session en cours et le **TL;DR** (§0).
2. Ajouter l'entrée de session en haut du §7 (fait / en attente / pièges), chaque étape préfixée par la machine cible.
3. Mettre à jour les états (§3, §4, §5), ajouter les décisions (§6) et les pièges (§1), cocher le §8.
4. Garder **une seule version** : si modifié côté Claude Code (`docs/CONTEXTE.md`), recopier dans le Projet claude.ai, et inversement.
