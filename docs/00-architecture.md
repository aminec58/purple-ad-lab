# Architecture

## Réseau
- Hyperviseur : VMware Workstation Pro
- Segment : **host-only** isolé, `10.10.10.0/24`
- **DHCP VMware désactivé** (le DC assure DNS ; adressage statique)
- Domaine : `purplelab.local`

## Machines

| VM       | Rôle                                    | OS                  | IP           |
|----------|-----------------------------------------|---------------------|--------------|
| DC       | AD DS + DNS (vulnérable)                | Windows Server 2022 | 10.10.10.10  |
| CLIENT01 | Poste joint                             | Windows 10/11       | 10.10.10.21  |
| CLIENT02 | Poste joint                             | Windows 10/11       | 10.10.10.22  |
| KALI     | Attaque                                 | Kali Linux          | 10.10.10.50  |
| SIEM     | Wazuh + Velociraptor                    | Ubuntu Server       | 10.10.10.100 |

## Faiblesses introduites sur le DC (matière des scénarios)
- Mots de passe faibles
- Comptes de service avec SPN (Kerberoasting)
- Délégation Kerberos mal réglée
- Un compte sans pré-authentification Kerberos (AS-REP roasting)

> Schéma à exporter dans `images/architecture.png`.
