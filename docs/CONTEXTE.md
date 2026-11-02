# CONTEXTE — Lab AD Purple Team (purple-ad-lab)

> **Doc de passation unique** entre les conversations Claude (Projet claude.ai) et **Claude Code**.
> Source de vérité de l'état du lab. À relire en début de session, à mettre à jour en fin de session (procédure en §9).

**Dernière mise à jour :** 2026-11-02 — **S09 (GPO d'audit avancé + PowerShell logging) — ✅ validée sur DC01**

---

## 0. TL;DR (à lire en premier)

- **Quoi :** lab Active Directory vulnérable, orienté Purple Team (attaque → détection → chasse → remédiation → rejeu), pour GitHub + CV.
- **Où on en est :** DC `DC01` promu, forêt **`purplelab.local`** opérationnelle (AD DS + DNS, zone inverse, PTR, NTP, SYSVOL/NETLOGON partagés). Administré en **SSH depuis l'hôte** (`ssh "PURPLELAB\Administrateur"@10.10.10.10`). Section « DC01 » rédigée pour `docs/01-deploiement-infra.md` (à committer par Amine). **GPO `PURPLELAB - Audit avance` en place** (S09 : audit avancé Kerberos/logon/comptes/4688 + cmdline + PowerShell 4103/4104), validée sur DC01.
- **Prochaine action :** 🖥️ Hôte snapshot `DC-ADDS-clean` → S07 (clients Windows 11 + jonction au domaine) → section « Clients » dans `docs/01-deploiement-infra.md`.
- **Règle d'or :** l'AD reste *propre* tant que la télémétrie (audit, Sysmon, Wazuh) n'est pas en place et vérifiée. Les vulnérabilités se posent **après**.

---

## 1. Pour Claude Code — lire avant d'agir

### Environnement
| Élément | Valeur |
|---|---|
| Hôte | PC Windows d'Amine, 32 Go RAM, **VMware Workstation Pro 17** |
| Dossier des VM | `C:\LAB-AD\<nom-VM>\` |
| ISO | `C:\Users\amine\Downloads\` (Server : `SERVER_EVAL_x64FRE_fr-fr.iso`) |
| Réseau lab | **VMnet2 host-only**, `10.10.10.0/24`, adressage statique, **pas d'Internet**. L'hôte a une IP sur VMnet2 et joint les VM (SSH OK vers le DC) |
| Dépôt GitHub | `aminec58/purple-ad-lab` (public, licence MIT, branche `main`) — état au 2026-11-01 : 1 seul commit `3c9d9dd` « Initial scaffold » (27/10) |
| Suivi des tâches | Plane — workspace `cyber_RT`, projet « Lab AD Purple Team », identifiant **ADPT** |

### Ce que Claude Code peut / ne peut pas faire
- ✅ Écrire et maintenir le dépôt : README, scripts (`.ps1`, `.sh`), règles Wazuh/Sigma, requêtes VQL Velociraptor, schéma d'archi.
- ✅ Générer les scripts qu'Amine exécute **lui-même** dans les VM (souvent via SSH depuis l'hôte).
- ❌ **Aucun accès direct aux VM** (réseau host-only isolé). Toute action dans une VM = commande fournie à Amine, qui renvoie la sortie.
- ❌ Ne jamais committer de secrets réels (mot de passe DSRM/Administrateur, clés d'enrôlement Wazuh/Velociraptor) ni de loot d'attaque (hashes, tickets, dumps, zips BloodHound) — le `.gitignore` du dépôt les bloque déjà, le respecter. Les mots de passe *volontairement faibles* des comptes vulnérables sont OK (c'est le but du lab), documentés comme tels.

### Conventions
- Langue : **français** (docs, commits, commentaires). Réponses et scripts **concis**.
- **Chaque tâche/bloc de commandes donné à Amine commence par la machine cible, avec le nom VMware** (colonne « VM (VMware) » du §3), ex. `🖥️ PurpleAD-DC`, `🖥️ PurpleAD-Kali`, ou `🖥️ Hôte Windows` pour ce qui se fait dans VMware Workstation / sur le PC.
- Une session de travail = un identifiant `Sxx`, journalisé en §7.
- Commits : style `type: description` en français (ex. `docs: déploiement du DC01 (purplelab.local)`).
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
  │   ├── 00-architecture.md          # réseau, machines, faiblesses introduites sur le DC
  │   ├── 01-deploiement-infra.md     # ordre d'install + dimensionnement ; ← y ajouter une section par VM déployée (DC01 d'abord)
  │   ├── 02-telemetrie.md            # audit avancé, PowerShell logging, Sysmon, validation ingestion (bloquant)
  │   ├── 03-scenarios/               # 01-password-spraying … 05-path-to-da (gabarit 5 étapes, statut ⬜)
  │   └── images/                     # captures + architecture.png (à produire)
  ├── config/
  │   ├── ad/setup-vulns.ps1          # pose des 5 faiblesses (phase 3 uniquement)
  │   ├── gpo/audit-policy.md         # sous-catégories d'audit activées + setup-audit-gpo.ps1 (S09)
  │   ├── sysmon/  velociraptor/  wazuh/decoders/   # vides (.gitkeep) — versions ASSAINIES uniquement
  ├── detection/
  │   ├── sigma/  wazuh-rules/        # vides
  ├── hunting/velociraptor/           # vide — requêtes VQL
  ├── attack/scripts/                 # vide — commandes d'attaque reproductibles
  └── remediation/hardening-ad.md     # durcissement par scénario (statut ⬜)
  ```
- Images : **`docs/images/`** (pas `docs/img/`).
- Tenir à jour la section **« Avancement »** du README (cases à cocher) et le **tableau des scénarios** (colonnes `_à compléter_`).

### Pièges déjà rencontrés (ne pas reproduire)
- **Install Windows Server :** la 1re ligne proposée = **Core** (sans GUI). Pour la GUI, choisir « (expérience de bureau) » — à la souris ça clique mal sans VMware Tools → utiliser **↓ puis Entrée**. Impossible de convertir Core → GUI après coup (depuis Server 2016).
- **Boot sur ISO (UEFI) :** le « Press any key » dure ~5 s et n'est pris que si la VM a le clavier. Méthode fiable : **VM → Power → Power On to Firmware → Boot Manager → CDROM**, puis Entrée.
- **Ne jamais changer l'IP / le réseau d'une VM depuis une session SSH** : la session coupe et la VM peut devenir injoignable (cas vécu : IP 10.10.10.10 posée sur une carte encore en NAT/VMnet8). Faire ces changements depuis la console VMware.
- **`Install-ADDSForest` redémarre tout seul** : attendre le reboot (3-5 min) avant zone inverse/PTR, sinon erreur DNS 9901 (zone AD-intégrée impossible avant que l'AD soit actif). Vérifier `Get-Service NTDS, DNS, ADWS` = Running avant de continuer.
- **scp/ssh depuis PowerShell :** guillemets autour de toute la cible (`"PURPLELAB\Administrateur@10.10.10.10:C:/..."`), sinon `@` est interprété par PowerShell.
- Sans passerelle, le profil réseau peut rester « Public » après reboot → `Restart-Service NlaSvc -Force`.

---

## 2. Objectif et critère de réussite

5 scénarios, chacun en **boucle complète** :
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
| PurpleAD-CLIENT01 | CLIENT01 | 10.10.10.21 | Windows 11 | Poste joint — Sysmon + agent Wazuh + client Velociraptor |
| PurpleAD-CLIENT02 | CLIENT02 | 10.10.10.22 | Windows 11 | idem |
| PurpleAD-Kali | kali | 10.10.10.50 | Kali 2026.3 | Attaque |
| PurpleAD-SIEM | siem | 10.10.10.100 | Ubuntu Server 24.04.3 | Wazuh + serveur Velociraptor |

- Domaine : **`purplelab.local`**, NetBIOS **`PURPLELAB`**, niveau fonctionnel forêt/domaine 2016 (`Windows2016Domain`).
- DNS de toutes les machines → 10.10.10.10 ; le DC pointe sur 127.0.0.1. Pas de passerelle.
- Zone inverse `10.10.10.in-addr.arpa` (AD-intégrée, réplication Forest) + PTR DC01.
- Pas de redirecteur DNS (host-only). NAT temporaire uniquement pour installs/mises à jour.
- DC = source de temps de référence (`w32tm /reliable:yes`) ; Kerberos tolère 5 min d'écart.
- **Accès admin au DC :** OpenSSH Server installé (pendant une phase NAT) → `ssh "PURPLELAB\Administrateur"@10.10.10.10`. Documenté comme accès d'administration du lab (bruit dans les logs à connaître).

### Ressources et état des VM
Toutes dans `C:\LAB-AD\<nom>\`, carte réseau **Custom : VMnet2 (Host-only)**, ISO monté, « Connect at power on ».
⚠️ Le 31/10 au soir, les onglets VMware ont été fermés : rouvrir les VM via **File → Open → `C:\LAB-AD\<nom>\<nom>.vmx`** (ou Library, F9).

| VM | RAM | vCPU | Disque | ISO | Particularités | OS installé |
|---|---|---|---|---|---|---|
| PurpleAD-DC | 4 Go | 2 | 60 Go NVMe | SERVER_EVAL_x64FRE_fr-fr.iso | UEFI ; **recréée le 31/10** (l'ancienne, installée en Core par erreur, supprimée) | ✅ Server 2022 — édition (Core / Expérience de bureau) à confirmer |
| PurpleAD-CLIENT01 | 4 Go | 2 | 64 Go NVMe | 26300…CLIENT (Win 11) | vTPM + chiffrement « TPM files » (clé dans le Credential Manager de l'hôte) | ⏳ |
| PurpleAD-CLIENT02 | 4 Go | 2 | 64 Go NVMe | idem | idem | ⏳ |
| PurpleAD-Kali | 4 Go | 2 | 40 Go SCSI | kali-linux-2026.3-installer-amd64.iso | Guest OS = Debian 12 | ⏳ |
| PurpleAD-SIEM | 8 Go | 4 | 80 Go SCSI | ubuntu-24.04.3-live-server-amd64.iso | Guest OS = Ubuntu 64-bit | ⏳ |

24 Go alloués sur 32 : tout tourne en parallèle. Disques thin-provisioned (split).

---

## 4. Roadmap

| Phase | Session | Contenu | État |
|---|---|---|---|
| 1 — Infra | S04 | Création des 5 VM sur VMnet2 | ✅ |
| | S05 | Snapshots baseline | ⏸️ reporté (décision §6) |
| | S06 | Install Server 2022 + promotion DC : AD DS + DNS `purplelab.local` | ✅ (reste snapshot) |
| | **S07** | **Install Windows 11 sur CLIENT01/02 + jonction au domaine** | ⏳ prochaine |
| | S08 | Install Kali + SIEM (Ubuntu), IP statiques | ⏳ |
| 2 — Télémétrie | S09 | GPO audit avancé + PowerShell logging (`config/gpo/setup-audit-gpo.ps1`) | ✅ DC01 (clients à la jonction) |
| | S10+ | Wazuh + Velociraptor sur SIEM ; Sysmon SwiftOnSecurity sur les clients ; **vérifier l'ingestion** (dont 4771/4625/4776 depuis Kali) | ⏳ |
| 3 — Vulnérabilisation | — | Comptes faibles, SPN, compte sans pré-auth, délégation mal réglée → `clean-baseline-<date>` | ⏳ |
| 4 — Scénarios | — | 5 boucles complètes (§5) | ⏳ |
| 5 — Livrable | — | README final | ⏳ |

Numéros S07+ indicatifs, à ajuster.

---

## 5. Scénarios

| # | Attaque | Outil | MITRE | Fichier | État |
|---|---|---|---|---|---|
| 1 | Password spraying | CrackMapExec / nxc | T1110.003 | `docs/03-scenarios/01-password-spraying.md` | ⏳ |
| 2 | AS-REP roasting | Impacket GetNPUsers / Rubeus | T1558.004 | `docs/03-scenarios/02-asrep-roasting.md` | ⏳ |
| 3 | Kerberoasting | Rubeus / Impacket GetUserSPNs | T1558.003 | `docs/03-scenarios/03-kerberoasting.md` | ⏳ |
| 4 | Pass-the-Hash + latéral | Mimikatz + CrackMapExec | T1550.002 | `docs/03-scenarios/04-pass-the-hash.md` | ⏳ |
| 5 | Chemin vers Domain Admin | BloodHound / SharpHound | T1087 | `docs/03-scenarios/05-path-to-da.md` | ⏳ |

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
| 2026-11-01 | Doc de déploiement réalisée = **sections ajoutées dans `docs/01-deploiement-infra.md`** (une par VM), captures dans `docs/images/` | Respecter la numérotation existante du scaffold |

---

## 7. Journal des sessions (le plus récent en haut)

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
- [x] VMnet2 fonctionnel depuis l'hôte (SSH vers 10.10.10.10 OK) — reste à confirmer DHCP VMnet2 désactivé
- [x] Vérif SYSVOL/NETLOGON
- [ ] Snapshot `DC-ADDS-clean`
- [ ] Confirmer l'édition de Server installée sur le DC (Core / Expérience de bureau)
- [ ] Committer la section DC01 dans `docs/01-deploiement-infra.md` (+ captures dans `docs/images/`)
- [ ] README : remplacer « Windows 10/11 » par « Windows 11 » pour les clients ; schéma `docs/images/architecture.png` à produire
- [x] Copier ce fichier dans le dépôt (`docs/CONTEXTE.md`) pour que Claude Code le trouve en local — fait en S08

---

## 9. Procédure de mise à jour de ce fichier
En fin de session (Projet claude.ai **ou** Claude Code) :
1. Mettre à jour la date, la session en cours et le **TL;DR** (§0).
2. Ajouter l'entrée de session en haut du §7 (fait / en attente / pièges), chaque étape préfixée par la machine cible.
3. Mettre à jour les états (§3, §4, §5), ajouter les décisions (§6) et les pièges (§1), cocher le §8.
4. Garder **une seule version** : si le fichier a été modifié côté Claude Code (`docs/CONTEXTE.md`), recopier dans le Projet claude.ai, et inversement.
