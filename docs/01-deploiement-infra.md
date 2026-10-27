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
