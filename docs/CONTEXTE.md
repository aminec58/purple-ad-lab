# CONTEXTE — Lab AD Purple Team (purple-ad-lab)

> **Doc de passation unique** entre les conversations Claude (Projet claude.ai) et **Claude Code**.
> Source de vérité de l'état du lab. À relire en début de session, à mettre à jour en fin de session (procédure en §9).

**Dernière mise à jour :** 2026-11-04 — **S11 (Sysmon SwiftOnSecurity sur CLIENT01/02) — ✅ installé, vérifié et committé**

---

## 0. TL;DR (à lire en premier)

- **Quoi :** lab Active Directory vulnérable, orienté Purple Team (attaque → détection → chasse → remédiation → rejeu), pour GitHub + CV.
- **Où on en est :** DC `DC01` promu, forêt **`purplelab.local`** opérationnelle. **CLIENT01 (10.10.10.21) et CLIENT02 (10.10.10.22) installés (Win 11 Pro), renommés et joints au domaine.** GPO `PURPLELAB - Audit avance` (audit avancé + PowerShell 4103/4104) **appliquée et vérifiée effective sur les deux postes**. **Sysmon 15.22 (config SwiftOnSecurity non modifiée) installé sur les deux clients (S11)** : services `Sysmon64` + `SysmonDrv` Running, événements 1/3/11/12/13/22 constatés, journal 256 Mo. Tout s'administre en **SSH depuis l'hôte** : DC `10.10.10.10` (`PURPLELAB\Administrateur`), clients `10.10.10.21/.22` (compte local `amin`).
- **Prochaine action :** S08 — install **Kali (10.10.10.50)** + **SIEM Ubuntu (10.10.10.100)**, IP statiques. Puis snapshot `DC-ADDS-clean` (toujours en attente) et suite phase 2 (Wazuh + Velociraptor sur SIEM, agents sur les clients, **validation de l'ingestion** dont Sysmon).
- **Règle d'or :** l'AD reste *propre* tant que la télémétrie (audit, Sysmon, Wazuh) n'est pas en place et vérifiée. Les vulnérabilités se posent **après**.

---

## 1. Pour Claude Code — lire avant d'agir

### Environnement
| Élément | Valeur |
|---|---|
| Hôte | PC Windows d'Amine (`laptop-m5uslr30`), 32 Go RAM, **VMware Workstation Pro 17** |
| Dossier des VM | `C:\LAB-AD\<nom-VM>\` |
| ISO | `C:\Users\amine\Downloads\` (Server : `SERVER_EVAL_x64FRE_fr-fr.iso`) |
| Cache d'outils (hôte) | `C:\LAB-AD\_tools\<outil>\` — téléchargés sur l'hôte (Internet) puis `scp` vers les VM (ex. Sysmon → `C:\Sysmon\` sur les clients) |
| Réseau lab | **VMnet2 host-only**, `10.10.10.0/24`, adressage statique, **pas d'Internet**. L'hôte a une IP sur VMnet2 et joint les VM (SSH OK vers DC + clients) |
| Dépôt GitHub | `aminec58/purple-ad-lab` (public, licence MIT, branche `main`), clone local `C:\Users\amine\purple-ad-lab`. Commits uniquement au nom d'Amine (pas de co-auteur Claude). |
| Suivi des tâches | Plane — workspace `cyber_RT`, projet « Lab AD Purple Team », identifiant **ADPT** |

### Accès d'administration du lab (SSH depuis l'hôte)
| Machine | Commande | Compte |
|---|---|---|
| DC01 | `ssh "PURPLELAB\Administrateur@10.10.10.10"` | Administrateur du domaine |
| CLIENT01 | `ssh amin@10.10.10.21` | compte local `amin` |
| CLIENT02 | `ssh amin@10.10.10.22` | compte local `amin` |
- Shell SSH par défaut = **cmd** → taper `powershell` en début de session (ou poser `DefaultShell` = PowerShell dans `HKLM:\SOFTWARE\OpenSSH`, fait sur CLIENT01).
- **Déploiement multi-postes :** préférer une boucle `foreach` **lancée depuis l'hôte** (`ssh amin@$ip "<cmd>"` + `scp`) plutôt que coller dans une session SSH (évite les caractères mangés). Mot de passe demandé à chaque appel (pas de clé SSH pour l'instant).
- **Secret hors dépôt :** le mdp de l'Administrateur du domaine a été **réinitialisé** (perdu à la saisie de l'install) → conservé dans le gestionnaire de mots de passe d'Amine, **pas** ici ni dans le dépôt.
- SSH = accès d'admin → bruit dans les logs (sshd, logons type 3) à connaître pour ne pas le confondre avec une attaque en phase 4.

### Ce que Claude Code peut / ne peut pas faire
- ✅ Écrire et maintenir le dépôt : README, scripts (`.ps1`, `.sh`), règles Wazuh/Sigma, requêtes VQL Velociraptor, schéma d'archi.
- ✅ Générer les scripts qu'Amine exécute **lui-même** dans les VM (souvent via SSH depuis l'hôte).
- ❌ **Aucun accès direct aux VM** (réseau host-only isolé). Toute action dans une VM = commande fournie à Amine, qui renvoie la sortie. La **prise de contrôle (computer use)** voit l'écran de l'hôte mais **ne peut pas piloter l'intérieur d'une VM** (la console VMware n'accepte pas les clics/frappes injectés, elle attend un vrai clic de capture / Ctrl+G) → inutile pour agir dans une VM.
- ❌ Ne jamais committer de secrets réels (mot de passe DSRM/Administrateur, clés d'enrôlement Wazuh/Velociraptor) ni de loot d'attaque (hashes, tickets, dumps, zips BloodHound) — le `.gitignore` du dépôt les bloque déjà, le respecter. Les mots de passe *volontairement faibles* des comptes vulnérables sont OK (c'est le but du lab), documentés comme tels.

### Conventions
- Langue : **français** (docs, commits, commentaires). Réponses et scripts **concis**.
- **Chaque tâche/bloc de commandes donné à Amine commence par la machine cible, avec le nom VMware** (colonne « VM (VMware) » du §3), ex. `🖥️ PurpleAD-DC`, `🖥️ PurpleAD-Kali`, ou `🖥️ Hôte Windows` pour ce qui se fait dans VMware Workstation / sur le PC.
- Une session de travail = un identifiant `Sxx`, journalisé en §7.
- Commits : style `type: description` en français (ex. `docs: déploiement du DC01 (purplelab.local)`), **sans ligne `Co-Authored-By` Claude**.
- Snapshots :
  - **de travail** : `<VM>-<étape>` (ex. `DC-pre-ADDS`, `DC-ADDS-clean`), pris avant chaque étape risquée ;
  - **baseline finale** : `clean-baseline-<date>` sur chaque VM, juste avant la 1re attaque (voir décision S05).
- **Arborescence RÉELLE du dépôt** (scaffold du 27/10 — s'y conformer, ne pas en inventer une autre) :
  ```
  purple-ad-lab/
  ├── README.md                       # archi, prérequis, télémétrie, tableau récap scénarios, avancement (cases à cocher)
  ├── LICENSE                         # MIT
  ├── .gitignore                      # bloque secrets, loot d'attaque, images de VM
  ├── docs/
  │   ├── CONTEXTE.md                 # ce fichier (copie du doc de passation)
  │   ├── 00-architecture.md          # réseau, machines, faiblesses introduites sur le DC
  │   ├── 01-deploiement-infra.md     # ordre d'install + dimensionnement ; ← y ajouter une section par VM déployée (DC01 d'abord)
  │   ├── 02-telemetrie.md            # audit avancé, PowerShell logging, Sysmon, validation ingestion (bloquant)
  │   ├── 03-scenarios/               # 01-password-spraying … 05-path-to-da (gabarit 5 étapes, statut ⬜)
  │   └── images/                     # captures + architecture.png (à produire)
  ├── config/
  │   ├── ad/setup-vulns.ps1          # pose des 5 faiblesses (phase 3 uniquement)
  │   ├── gpo/audit-policy.md         # sous-catégories d'audit activées + setup-audit-gpo.ps1 (S09)
  │   ├── sysmon/                     # sysmonconfig-export.xml (SwiftOnSecurity figée) + README.md (S11)
  │   ├── velociraptor/  wazuh/decoders/   # vides (.gitkeep) — versions ASSAINIES uniquement
  ├── detection/
  │   ├── sigma/  wazuh-rules/        # vides
  ├── hunting/velociraptor/           # vide — requêtes VQL
  ├── attack/scripts/                 # vide — commandes d'attaque reproductibles
  └── remediation/hardening-ad.md     # durcissement par scénario
  ```
- Images : **`docs/images/`** (pas `docs/img/`).
- Tenir à jour la section **« Avancement »** du README (cases à cocher) et le **tableau des scénarios** (colonnes `_à compléter_`).

### Pièges déjà rencontrés (ne pas reproduire)
- **Install Windows Server :** la 1re ligne proposée = **Core** (sans GUI). Pour la GUI, choisir « (expérience de bureau) » — à la souris ça clique mal sans VMware Tools → utiliser **↓ puis Entrée**. Impossible de convertir Core → GUI après coup (depuis Server 2016).
- **Install Windows 11 :** choisir l'édition **Pro** (pas Famille — impossible de joindre un domaine sinon).
- **Boucle d'install Win 11** (« l'ordinateur a redémarré de manière inattendue ») : sur le dialogue, **Maj+F10** → `regedit` → `HKLM\SYSTEM\Setup\Status\ChildCompletion\setup.exe` passer de **1 à 3** → OK. Au reboot, **ne pas** appuyer de touche au « Press any key to boot from CD » (laisser booter le disque). Sinon le setup recommence et re-crashe.
- **Boot sur ISO (UEFI) :** le « Press any key » dure ~5 s et n'est pris que si la VM a le clavier. Méthode fiable : **VM → Power → Power On to Firmware → Boot Manager → CDROM**, puis Entrée.
- **OOBE Win 11 sans Internet (host-only) :** l'OOBE réclame réseau + compte Microsoft. Sur les builds récents (24H2+/26xxx), `OOBE\BYPASSNRO` a disparu. Méthode fiable : à l'écran réseau, **Maj+F10** → `start ms-cxh:localonly` (ouvre direct la création d'un compte local). Repli : `reg add HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\OOBE /v BypassNRO /t REG_DWORD /d 1 /f` puis `shutdown /r /t 0`.
- **OpenSSH sur les clients :** `Add-WindowsCapability -Online -Name OpenSSH.Server~~~~0.0.1.0` **télécharge depuis Windows Update** → passer la carte en **NAT** le temps de l'install, puis retour VMnet2 (changement de carte **depuis la console VMware**). Exige PowerShell **admin** (« opération nécessite une élévation » sinon).
- **SSH client qui timeout = pare-feu**, pas le réseau : la règle OpenSSH par défaut n'est active que pour Domaine/Privé, or réseau non identifié = **Public**. Créer une règle `-Profile Any` : `New-NetFirewallRule -Name sshd-any -DisplayName "sshd Any" -Enabled True -Direction Inbound -Protocol TCP -Action Allow -LocalPort 22 -Profile Any`.
- **SSH qui timeout juste après démarrage d'une VM :** attendre la fin du boot (vécu en S11 sur CLIENT01, 2e essai OK).
- **Collage SSH qui mange des caractères :** vécu plusieurs fois (le `22` de `-LocalPort 22` perdu, un `*` parasite devant `$if`, un `s` parasite en S11). Si une commande collée casse, la **retaper** ; relancer la ligne d'assignation `$if = ...` dans chaque nouvelle session PowerShell.
- **Le DC doit être démarré** avant toute install/jonction de client : si `ping 10.10.10.10` / `Resolve-DnsName` timeout alors que l'hôte SSH vers le client, c'est souvent que **la VM PurpleAD-DC est éteinte/suspendue** (vécu en S07).
- **Ne jamais changer l'IP / le réseau d'une VM depuis une session SSH** : la session coupe et la VM peut devenir injoignable (cas vécu : IP 10.10.10.10 posée sur une carte encore en NAT/VMnet8). Faire ces changements depuis la console VMware.
- **`Install-ADDSForest` redémarre tout seul** : attendre le reboot (3-5 min) avant zone inverse/PTR, sinon erreur DNS 9901 (zone AD-intégrée impossible avant que l'AD soit actif). Vérifier `Get-Service NTDS, DNS, ADWS` = Running avant de continuer.
- **scp/ssh depuis PowerShell :** guillemets autour de toute la cible (`"PURPLELAB\Administrateur@10.10.10.10:C:/..."`), sinon `@` est interprété par PowerShell.
- **Reset d'un mdp en clair :** `ConvertTo-SecureString "<mdp>" -AsPlainText -Force` (pas `-AsSecureString`, qui sert à *saisir* au clavier).
- Sans passerelle, le profil réseau peut rester « Public » après reboot → `Restart-Service NlaSvc -Force`.

### Bruit connu dans la télémétrie (ne pas confondre avec une attaque)
- **Sysmon ID 8 (CreateRemoteThread) `CtrlRoutine` :** source `<unknown process>` (PID SYSTEM protégé, très probablement `csrss.exe`) → cible `powershell.exe`/console, `StartModule` = `KERNELBASE.dll`, `StartFunction` = **`CtrlRoutine`**. C'est le gestionnaire Ctrl+C / fermeture de console injecté par Windows → **bénin**. Vu sur CLIENT01 en S11 (04/11 08:40, après un Ctrl+C). À exclure dans les règles Wazuh (filtre `StartFunction = CtrlRoutine` + `StartModule` KERNELBASE).
- **SSH d'administration :** sshd + logons type 3 (voir plus haut).

---

## 2. Objectif et critère de réussite

5 scénarios (+ 1 optionnel, voir §5), chacun en **boucle complète** :
1. Attaque depuis Kali (commandes exactes)
2. Détection : ce que Wazuh voit / rate, et pourquoi
3. Chasse : hypothèse + requête Velociraptor
4. Remédiation : règle Sigma/Wazuh manquante + durcissement AD
5. Rejeu

**Un scénario n'est « fini » que si, au rejeu, la détection se déclenche ET la remédiation bloque/limite l'attaque.**

**Livrable final :** README GitHub = schéma d'archi, prérequis, tableau récap par scénario (attaque / MITRE / détection Wazuh / requête Velociraptor / règle ajoutée / remédiation).

---

## 3. Architecture figée

| VM (VMware) | Hostname (dans l'OS) | IP | OS | Rôle |
|---|---|---|---|---|
| PurpleAD-DC | DC01 | 10.10.10.10 | Windows Server 2022 éval (FR), build 20348 | AD DS + DNS, volontairement vulnérable (plus tard) |
| PurpleAD-CLIENT01 | CLIENT01 | 10.10.10.21 | Windows 11 Pro (build 26300) | Poste joint — **Sysmon ✅** ; agent Wazuh + client Velociraptor à venir |
| PurpleAD-CLIENT02 | CLIENT02 | 10.10.10.22 | Windows 11 Pro (build 26300) | idem |
| PurpleAD-Kali | kali | 10.10.10.50 | Kali 2026.3 | Attaque |
| PurpleAD-SIEM | siem | 10.10.10.100 | Ubuntu Server 24.04.3 | Wazuh + serveur Velociraptor |

- Domaine : **`purplelab.local`**, NetBIOS **`PURPLELAB`**, niveau fonctionnel forêt/domaine 2016 (`Windows2016Domain`).
- DNS de toutes les machines → 10.10.10.10 ; le DC pointe sur 127.0.0.1. Pas de passerelle.
- Zone inverse `10.10.10.in-addr.arpa` (AD-intégrée, réplication Forest) + PTR DC01.
- Pas de redirecteur DNS (host-only). NAT temporaire uniquement pour installs/mises à jour.
- DC = source de temps de référence (`w32tm /reliable:yes`) ; Kerberos tolère 5 min d'écart.
- **Accès admin au DC :** OpenSSH Server installé (pendant une phase NAT) → `ssh "PURPLELAB\Administrateur"@10.10.10.10`. Documenté comme accès d'administration du lab (bruit dans les logs à connaître).
- **Sysmon (clients) :** `Sysmon64.exe` **15.22** (Sysinternals, signature Authenticode Valid) + `sysmonconfig-export.xml` (SwiftOnSecurity, commit `1836897`, récupéré le 2026-11-04) déposés dans `C:\Sysmon\`, installés via `Sysmon64.exe -accepteula -i`. Journal `Microsoft-Windows-Sysmon/Operational` porté à **256 Mo**. **Pas d'ID 10 (ProcessAccess)** : bloc `<ProcessAccess onmatch="include">` vide dans la config SwiftOnSecurity → accès LSASS **non journalisés** (voir décision 2026-11-04). Pas de Sysmon sur le DC (non prévu par le brief). Copie figée + README : `config/sysmon/`.
- **Note scénario #6 (BadSuccessor) :** nécessiterait l'ajout d'un **DC ou serveur membre Windows Server 2025** (les dMSA, support de l'attaque, n'existent pas sur 2022). VM non créée — à décider en fin de projet.

### Ressources et état des VM
Toutes dans `C:\LAB-AD\<nom>\`, carte réseau **Custom : VMnet2 (Host-only)**, ISO monté, « Connect at power on ».
⚠️ Si les onglets VMware sont fermés : rouvrir les VM via **File → Open → `C:\LAB-AD\<nom>\<nom>.vmx`** (ou Library, F9).

| VM | RAM | vCPU | Disque | ISO | Particularités | OS installé / état |
|---|---|---|---|---|---|---|
| PurpleAD-DC | 4 Go | 2 | 60 Go NVMe | SERVER_EVAL_x64FRE_fr-fr.iso | UEFI ; recréée le 31/10 (ancienne en Core supprimée) | ✅ Server 2022, DC promu (édition Core/GUI à confirmer) |
| PurpleAD-CLIENT01 | 4 Go | 2 | 64 Go NVMe | 26300…CLIENT (Win 11) | vTPM + chiffrement « TPM files » (clé dans le Credential Manager de l'hôte) | ✅ Win 11 Pro, **joint** (CLIENT01 / 10.10.10.21), OpenSSH + règle pare-feu, **Sysmon** |
| PurpleAD-CLIENT02 | 4 Go | 2 | 64 Go NVMe | idem | idem | ✅ Win 11 Pro, **joint** (CLIENT02 / 10.10.10.22), OpenSSH + règle `sshd-any`, **Sysmon** |
| PurpleAD-Kali | 4 Go | 2 | 40 Go SCSI | kali-linux-2026.3-installer-amd64.iso | Guest OS = Debian 12 | ⏳ (S08) |
| PurpleAD-SIEM | 8 Go | 4 | 80 Go SCSI | ubuntu-24.04.3-live-server-amd64.iso | Guest OS = Ubuntu 64-bit | ⏳ (S08) |

24 Go alloués sur 32 : tout tourne en parallèle. Disques thin-provisioned (split).

---

## 4. Roadmap

| Phase | Session | Contenu | État |
|---|---|---|---|
| 1 — Infra | S04 | Création des 5 VM sur VMnet2 | ✅ |
| | S05 | Snapshots baseline | ⏸️ reporté (décision §6) |
| | S06 | Install Server 2022 + promotion DC : AD DS + DNS `purplelab.local` | ✅ (reste snapshot) |
| | S07 | Install Windows 11 Pro sur CLIENT01/02 + jonction au domaine | ✅ |
| | **S08** | **Install Kali (10.10.10.50) + SIEM Ubuntu (10.10.10.100), IP statiques** | ⏳ prochaine |
| 2 — Télémétrie | S09 | GPO audit avancé + PowerShell logging (`config/gpo/setup-audit-gpo.ps1`) | ✅ DC + clients |
| | S10 | Vérif PowerShell Script Block (4104) + Module Logging (4103) | ✅ DC + clients |
| | S11 | Sysmon 15.22 config SwiftOnSecurity sur CLIENT01/02 | ✅ |
| | S12+ | Wazuh + Velociraptor sur SIEM ; agents Wazuh/Velociraptor sur les clients (et DC) ; **vérifier l'ingestion** (Security, PowerShell, Sysmon ; dont 4771/4625/4776 depuis Kali) | ⏳ |
| 3 — Vulnérabilisation | — | Comptes faibles, SPN, compte sans pré-auth, délégation mal réglée → `clean-baseline-<date>` | ⏳ |
| 4 — Scénarios | — | 5 boucles complètes (§5) | ⏳ |
| 4bis — Extension (opt.) | — | Scénario #6 BadSuccessor : ajout d'un DC/serveur Server 2025 + boucle complète | ⏳ optionnel, fin de projet |
| 5 — Livrable | — | README final | ⏳ |

Numéros de session indicatifs (les S09/S10/S11 de télémétrie ont été faits avant S08), à ajuster.

---

## 5. Scénarios

| # | Attaque | Outil | MITRE | Fichier | État |
|---|---|---|---|---|---|
| 1 | Password spraying | CrackMapExec / nxc | T1110.003 | `docs/03-scenarios/01-password-spraying.md` | ⏳ |
| 2 | AS-REP roasting | Impacket GetNPUsers / Rubeus | T1558.004 | `docs/03-scenarios/02-asrep-roasting.md` | ⏳ |
| 3 | Kerberoasting | Rubeus / Impacket GetUserSPNs | T1558.003 | `docs/03-scenarios/03-kerberoasting.md` | ⏳ |
| 4 | Pass-the-Hash + latéral | Mimikatz + CrackMapExec | T1550.002 | `docs/03-scenarios/04-pass-the-hash.md` | ⏳ — **écart de détection prévu : pas de Sysmon ID 10 (LSASS)** → remédiation = règle ProcessAccess lsass |
| 5 | Chemin vers Domain Admin | BloodHound / SharpHound | T1087 | `docs/03-scenarios/05-path-to-da.md` | ⏳ |
| 6 | BadSuccessor (abus dMSA) | SharpSuccessor / Rubeus / PowerShell | T1098 / T1078 | `docs/03-scenarios/06-badsuccessor.md` | ⏳ **optionnel — nécessite un DC Server 2025** |

**Scénario #4 — note détection (S11) :** avec la config SwiftOnSecurity d'origine, le dump LSASS par Mimikatz (`sekurlsa::logonpasswords`) ne produit **aucun** Sysmon ID 10. Étape « Détection » = constater l'angle mort ; étape « Remédiation » = créer `config/sysmon/sysmonconfig-purplelab.xml` (SwiftOnSecurity + `<ProcessAccess onmatch="include">` sur `TargetImage` = `C:\Windows\system32\lsass.exe`, filtré sur `GrantedAccess` typiques de Mimikatz : 0x1010, 0x1410, 0x1438, 0x143a, 0x1fffff…), recharger par `Sysmon64.exe -c <fichier>` + règle Wazuh associée ; rejeu → ID 10 + alerte.

**Scénario #6 — notes de cadrage (ne pas démarrer avant la fin des 5 de base) :**
- **Pré-requis infra :** dMSA = fonctionnalité **Windows Server 2025** uniquement. Il faut ajouter au lab un DC (ou serveur membre selon la variante) **Server 2025**. Préférer un **nouveau serveur dédié** plutôt que remonter `DC01` (ne pas casser la baseline S06 déjà validée).
- **Principe :** abus du lien de migration dMSA (`msDS-ManagedAccountPrecededByLink` / `msDS-DelegatedMSAState`) : un principal ayant `CreateChild` (ou write) sur une OU peut créer un dMSA et le faire « succéder » à un compte privilégié (jusqu'à Domain Admin), héritant de ses accès via Kerberos.
- **Détection à travailler :** SACL + **4662** sur les attributs dMSA, **5137/5136** (création/modif dMSA), événements d'auth dMSA (**2946**). À valider dans Wazuh.
- **Remédiation :** auditer et verrouiller `CreateChild`/write sur les OU ; tiering ; surveiller les créations de dMSA.
- **À revérifier le moment venu :** état du correctif Microsoft. Si patché → documenter « exploitable sur 2025 non patché / détecté + bloqué après patch » (bon livrable Purple Team en soi).

---

## 6. Décisions prises (et pourquoi)

| Date | Décision | Raison |
|---|---|---|
| 2026-10 | VMware Workstation Pro, réseau host-only VMnet2 | Isolement total du lab vulnérable |
| 2026-10 | Plan `10.10.10.0/24`, IP statiques | Reproductibilité, pas de dépendance au DHCP |
| 2026-10-27 | Scaffold du dépôt GitHub (docs numérotées, config/detection/hunting/attack/remediation, .gitignore anti-secrets) | Structure fixée dès le départ |
| 2026-10-31 | Snapshot baseline reporté (S05) | VM encore vides ; la baseline = état figé juste avant la 1re attaque (OS + AD + clients joints + agents + télémétrie vérifiée + vulnérabilités en place) |
| 2026-10-31 | Domaine `purplelab.local` / `PURPLELAB`, niveau 2016 | Niveau max proposé par Server 2022 |
| 2026-10-31 | Hostname `DC01` fixé **avant** promotion | Renommer un DC après coup est pénible |
| 2026-10-31 | Vulnérabilités posées **après** la télémétrie | Baseline propre + création des faiblesses visible dans les logs |
| 2026-10-31 | Pas de redirecteur DNS | Réseau sans Internet |
| 2026-10-31 | Chaque tâche préfixée par le nom VMware de la machine cible | Demande d'Amine : savoir sans ambiguïté où exécuter |
| 2026-11-01 | Administration du DC en SSH depuis l'hôte | Confort (copier-coller, sortie lisible) ; documenté comme accès admin du lab |
| 2026-11-02 | PowerShell logging **gardé dans la GPO combinée S09** (Option A), pas de GPO dédiée | Déjà posé et vérifié en S09 ; éviter un doublon |
| 2026-11-03 | Ajout d'un **scénario #6 optionnel « BadSuccessor »** (abus dMSA) au backlog | Technique récente (2025), bonne valeur CV/GitHub ; mais nécessite un DC Server 2025 → à faire **en fin de projet**, via un serveur 2025 dédié, après les 5 scénarios de base |
| 2026-11-03 | Clients en **Windows 11 Pro** + **OpenSSH + règle pare-feu `sshd-any` (Profile Any)** | Pro requis pour la jonction ; SSH pour l'admin, règle Any car réseau « Public » |
| 2026-11-03 | Mot de passe Administrateur du domaine **réinitialisé** (perdu à l'install) → gardé hors dépôt | Débloquer la jonction ; ne pas exposer de secret réel |
| 2026-11-04 | Sysmon déployé **depuis l'hôte** (download sur l'hôte → `scp` → install via `ssh`), dans `C:\Sysmon\` | Clients sans Internet ; boucle hôte = pas de collage dans SSH |
| 2026-11-04 | **Config SwiftOnSecurity non modifiée** (Option A — appliquée par défaut, réversible via `Sysmon64.exe -c`) ; donc **pas d'ID 10 LSASS** | L'angle mort LSASS devient l'écart de détection documenté du scénario 4, et la règle ProcessAccess sa remédiation (vraie boucle Purple Team) |
| 2026-11-04 | Journal Sysmon/Operational porté à **256 Mo** | Éviter la rotation avant l'arrivée de l'agent Wazuh |
| 2026-11-04 | Commits **au seul nom d'Amine**, sans co-auteur Claude | Demande d'Amine |

---

## 7. Journal des sessions (le plus récent en haut)

### S11 — 2026-11-04 — Sysmon SwiftOnSecurity sur CLIENT01/02 (✅)
- **Fait :**
  - 🖥️ Hôte Windows — téléchargement dans `C:\LAB-AD\_tools\sysmon\` de `Sysmon.zip` (Sysinternals, **15.22**) + `sysmonconfig-export.xml` (SwiftOnSecurity, `master` = commit `1836897`) ; `Get-AuthenticodeSignature Sysmon64.exe` = **Valid** ; `Select-String` confirme que `<ProcessAccess onmatch="include">` est **vide** (l. 472-474) → pas d'ID 10.
  - 🖥️ Hôte Windows — boucle `foreach` sur .21/.22 : `mkdir C:\Sysmon` → `scp` binaire + config → `Sysmon64.exe -accepteula -i C:\Sysmon\sysmonconfig-export.xml` → `wevtutil sl … /ms:268435456`.
  - **Vérifs OK (les 2 postes) :** `Sysmon64` + `SysmonDrv` **Running** ; événements constatés après `whoami` + `nslookup` : IDs **1, 3, 4, 11, 12, 13, 16, 22** (+ un ID 8 sur CLIENT01). Taille du journal = **268435456** (confirmée).
  - ID 8 de CLIENT01 analysé : `CtrlRoutine` injecté par csrss dans powershell après un Ctrl+C → **bénin**, consigné en §1 « Bruit connu ».
  - Dépôt : `config/sysmon/sysmonconfig-export.xml` (copie figée) + `config/sysmon/README.md` (version, commit source, limite LSASS), `.gitkeep` retiré ; section Sysmon de `docs/02-telemetrie.md` rédigée ; ce fichier recopié dans `docs/CONTEXTE.md`.
- **Incidents :** 1er `ssh` vers .21 en timeout (VM pas encore démarrée), 2e passage OK ; un `s` parasite au collage (sans effet).
- **Reste :** ingestion Sysmon par Wazuh à valider en S12+ ; décider Sysmon sur le DC.

### S07 — 2026-11-03 — Clients Windows 11 joints au domaine (✅ CLIENT01 + CLIENT02)
- **Fait :**
  - Install **Win 11 Pro** sur les 2 VM (compte local `amin`), VMware Tools.
  - **OpenSSH Server** installé sur chaque client (passe NAT pour le download WU, retour VMnet2) + **règle pare-feu `sshd-any` (Profile Any)** — sans elle le SSH timeout (réseau « Public »).
  - IP statiques **10.10.10.21 / 10.10.10.22**, DNS → 10.10.10.10 (cartes sur VMnet2).
  - `Rename-Computer` → `CLIENT01` / `CLIENT02`, puis `Add-Computer -DomainName purplelab.local` (compte `PURPLELAB\Administrateur`).
  - **Vérifs OK (les 2 postes) :** `(Get-ComputerInfo).CsDomain` = purplelab.local ; GPO appliquées depuis DC01 = `Default Domain Policy` + **`PURPLELAB - Audit avance`** ; sur CLIENT01 confirmé *effectif* : `auditpol` Création du processus = Réussite (4688), `EnableScriptBlockLogging = 1`.
- **Incidents résolus :** mdp Administrateur du domaine perdu (mauvaise saisie à l'install) → **réinitialisé** via `Set-ADAccountPassword` depuis le DC (gardé hors dépôt) ; jonction CLIENT02 bloquée tant que **la VM DC était éteinte** (ping/DNS timeout) → démarrage du DC puis OK ; plusieurs collages SSH ayant mangé des caractères (`22`, `*$if`) → retape.
- **Note computer use :** la prise de contrôle voit l'écran de l'hôte mais **ne peut pas piloter l'intérieur d'une VM** (console VMware n'accepte pas l'entrée injectée) → inutile pour agir dans une VM.
- **Reste :** session utilisateur *domaine* à ouvrir plus tard sur les postes (là, connecté en compte local `amin` → partie « Utilisateurs » du gpresult = N/A, normal) ; agents (Sysmon/Wazuh/Velociraptor) en phase 2.

### 2026-11-03 — Planification : scénario #6 BadSuccessor ajouté au backlog
- **Nature :** planification uniquement, aucune action sur le lab.
- **Fait :** scénario #6 « BadSuccessor (abus dMSA) » ajouté au §5 (statut ⏳ optionnel) avec notes de cadrage (pré-requis Server 2025, principe, détection 4662/5136/5137/2946, remédiation, vérif correctif MS) ; ligne « 4bis — Extension (opt.) » ajoutée à la roadmap §4 ; décision consignée au §6 ; note infra au §3 ; tâche créée dans Plane.
- **Décision clé :** à faire **en fin de projet**, après les 5 scénarios de base, via un **serveur Server 2025 dédié** (ne pas remonter `DC01` pour préserver la baseline S06).
- **Reste :** rien à faire tant que les 5 scénarios de base ne sont pas bouclés. Fichier `docs/03-scenarios/06-badsuccessor.md` à créer le moment venu.

### S10 — 2026-11-02 — PowerShell Script Block + Module Logging (✅ vérifiée sur DC01)
- **Constat :** ces réglages étaient **déjà posés en S09** dans la GPO `PURPLELAB - Audit avance`. S10 = vérification, pas de nouvelle pose (**Option A** retenue : garder le combiné S09, pas de GPO PowerShell dédiée).
- **Vérifs OK (DC01) :** `ScriptBlockLogging\EnableScriptBlockLogging = 1`, `ModuleLogging\EnableModuleLogging = 1`, `ModuleLogging\ModuleNames` = `* = *` ; test `Write-Output` → **4103 + 4104** présents dans `Microsoft-Windows-PowerShell/Operational`. (Reconfirmé effectif sur les clients en S07.)
- **Reste :** 4103/4104 à constater sur CLIENT01/02 après jonction (`gpresult /r` — GPO liée à la racine, donc héritée) ; durcissement à prévoir : désactiver **PowerShell v2** (contourne le Script Block Logging) ; `EnableScriptBlockInvocationLogging` laissé à 0 (4105/4106 trop bruyants).

### S09 — 2026-11-02 — GPO d'audit avancé (✅ validée sur DC01)
- **Fait :**
  - Script `config/gpo/setup-audit-gpo.ps1` (idempotent) : GPO `PURPLELAB - Audit avance` {E1A71355-B60E-447D-A3EB-7A9D71590B57}, liée racine domaine + OU Domain Controllers (ordre 1). Audit avancé via `audit.csv` (11 sous-catégories, GUID → indépendant de la langue), `SCENoApplyLegacyAuditPolicy`, cmdline 4688, Script Block + Module Logging, journal Security 512 Mo. `config/gpo/audit-policy.md` + `docs/02-telemetrie.md` mis à jour.
  - 🖥️ Hôte Windows — `scp` du script vers le DC ; 🖥️ PurpleAD-DC — exécution → version GPO 7.
  - **Vérifs OK (DC01) :** auditpol = 11 sous-catégories conformes ; 4768/4769 (klist), 4688 avec cmdline, 4624, 4104.
- **Reste :** 4771/4625/4776 à valider depuis Kali ; GPO à constater sur CLIENT01/02 après jonction (`gpresult /r`) ; SACL pour 5136 en phase 3.
- **Pièges :** sous PowerShell, `scp "PURPLELAB\Administrateur"@IP:...` casse sur `@` → mettre **toute la cible entre guillemets** : `"PURPLELAB\Administrateur@10.10.10.10:C:/..."`.

### S08 — 2026-11-02 — Documentation des faiblesses introduites sur le DC (doc only)
- **Nature :** documentation **uniquement** — aucune faiblesse posée (phase 3 non entamée). Les faiblesses se créeront après la télémétrie vérifiée (phase 2).
- **Fait :**
  - `docs/00-architecture.md` — section « Faiblesses introduites sur le DC » développée : encadré d'avertissement (pose en phase 3, après télémétrie vérifiée ; mdp volontairement faibles documentés, aucun secret réel), tableau récap (5 faiblesses / compte-objet / scénario / MITRE), puis détail par faiblesse (pourquoi exploitable, commande PowerShell d'introduction en réf. « phase 3 », événement de détection attendu, renvoi vers le durcissement).
  - `remediation/hardening-ad.md` — complété (⬜ → rédigé) : un durcissement concret par faiblesse — #1 politique MDP + verrouillage ; #2 gMSA / AES only / retrait SPN ; #3 réactivation pré-auth + AES ; #4 cadrage de la délégation contrainte de `svc-web` (retrait transition de protocole + `msDS-AllowedToDelegateTo`) + comptes non délégables ; #5 nettoyage ACL + tiering + moindre privilège.
  - `README.md` — colonne « Remédiation » du tableau des scénarios renseignée (synthèse).
  - Ce fichier **copié dans le dépôt** (`docs/CONTEXTE.md`).
  - Doc **alignée sur le script réel** `config/ad/setup-vulns.ps1` (poussé entre-temps sur `main`) après constat d'écarts : noms de comptes, SPN `sql01`, délégation **contrainte** sur `svc-web`, cible du `GenericAll` = `svc-web` (pas un DA).
- **Les 5 faiblesses documentées (alignées sur `config/ad/setup-vulns.ps1`) :** #1 mdp faibles + `LockoutThreshold 0` (`j.dupont`, `m.martin`, `a.roux` ; leurres `l.bernard`/`s.petit`, T1110.003) ; #2 `svc-sql` + SPN `MSSQLSvc/sql01...:1433` + RC4 forcé (T1558.003) ; #3 `a.roux` `DONT_REQ_PREAUTH` (T1558.004) ; #4 `svc-web` délégation **contrainte + transition de protocole** vers `cifs/DC01` (T1550.002) ; #5 `j.dupont` → `Helpdesk` → `GenericAll` sur `svc-web` → DC (T1087).
- **Reste :** phases 1→2 (clients, Kali/SIEM, télémétrie + validation ingestion) **avant** toute vulnérabilisation ; snapshot `clean-baseline-<date>` juste après la pose des faiblesses (phase 3).

### S06 — 2026-10-31 → 2026-11-01 — Promotion du DC (✅ validée, reste snapshot)
- **Fait :**
  - 1re install de Server 2022 en **Core** par erreur (ligne par défaut) → VM supprimée puis **recréée** (UEFI, NVMe 60 Go, VMnet2, ISO fr-fr).
  - OpenSSH Server installé sur le DC (pendant une phase en NAT, IP 192.168.159.147) ; IP statique 10.10.10.10/24, DNS 127.0.0.1, hostname DC01 ; carte repassée sur VMnet2.
  - 🖥️ PurpleAD-DC — `Install-ADDSForest purplelab.local / PURPLELAB / WinThreshold` → succès.
  - 🖥️ PurpleAD-DC — après reboot : zone inverse `10.10.10.0/24` (Forest) + PTR DC01 + `w32tm /reliable:yes` → OK.
  - **Vérifs OK :** NTDS/DNS/ADWS Running ; `Get-ADDomain` = purplelab.local / PURPLELAB / Windows2016Domain ; SRV `_ldap._tcp.dc._msdcs` → dc01 (10.10.10.10) ; PTR 10.10.10.10 → DC01.purplelab.local ; partages **SYSVOL** et **NETLOGON** présents.
  - `dcdiag /q` : 2 échecs **non bloquants** — `SystemLog` (arrêts sshd + arrêt non propre 12:51 dus à la coupure SSH/reboot, disparaissent sous 24 h) et `DFSREvent` (avertissements classiques à l'init SYSVOL d'un DC neuf).
  - Section « DC01 » rédigée pour `docs/01-deploiement-infra.md` (spécs, étapes, vérifs, problèmes rencontrés, accès admin) — à committer par Amine.
- **Reste :** 🖥️ Hôte snapshot `DC-ADDS-clean` ; confirmer l'édition installée (Core ou GUI) et ajuster la doc ; cocher partiellement « Infra déployée » dans le README.
- **Pièges :** voir §1 « Pièges déjà rencontrés ».

### S05 — 2026-10-31 — Snapshots baseline : reportés
- Décision : **ne pas** snapshoter maintenant (VM vides). Baseline à faire juste avant la 1re attaque, nommée `clean-baseline-<date>` sur chaque VM.

### S04 — 2026-10-31 — Déploiement des 5 VM
- 5 VM créées dans VMware Workstation Pro 17 (voir §3), ISO montés, OS non installés, carte réseau = Custom VMnet2 (Host-only), VMnet2 créé par Amine.

---

## 8. Points ouverts / à vérifier
- [x] VMnet2 fonctionnel depuis l'hôte (SSH vers DC + clients OK) — reste à confirmer DHCP VMnet2 désactivé
- [x] Vérif SYSVOL/NETLOGON
- [ ] Snapshot `DC-ADDS-clean`
- [ ] Confirmer l'édition de Server installée sur le DC (Core / Expérience de bureau)
- [ ] Committer la section DC01 dans `docs/01-deploiement-infra.md` + ajouter une section « Clients » (CLIENT01/02) (+ captures dans `docs/images/`)
- [ ] README : remplacer « Windows 10/11 » par « Windows 11 Pro » ; schéma `docs/images/architecture.png` à produire
- [x] Copier ce fichier dans le dépôt (`docs/CONTEXTE.md`) — recopié en S11
- [x] Constater 4103/4104 (PowerShell) + audit avancé sur CLIENT01/02 après jonction (`gpresult /r`) — S07
- [x] Sysmon SwiftOnSecurity sur CLIENT01/02 — S11
- [x] Committer `config/sysmon/` (config figée + README) + section Sysmon de `docs/02-telemetrie.md` — S11
- [ ] (décision) Sysmon aussi sur le DC ? Non prévu par le brief — utile pour scénarios 4/5 ; à trancher avant la baseline
- [ ] Désactiver PowerShell v2 sur postes + DC (durcissement télémétrie)
- [ ] (opt.) Scénario #6 BadSuccessor : décider en fin de projet si on ajoute un serveur Server 2025 ; créer alors `docs/03-scenarios/06-badsuccessor.md`

---

## 9. Procédure de mise à jour de ce fichier
En fin de session (Projet claude.ai **ou** Claude Code) :
1. Mettre à jour la date, la session en cours et le **TL;DR** (§0).
2. Ajouter l'entrée de session en haut du §7 (fait / en attente / pièges), chaque étape préfixée par la machine cible.
3. Mettre à jour les états (§3, §4, §5), ajouter les décisions (§6) et les pièges (§1), cocher le §8.
4. Garder **une seule version** : si le fichier a été modifié côté Claude Code (`docs/CONTEXTE.md`), recopier dans le Projet claude.ai, et inversement.
