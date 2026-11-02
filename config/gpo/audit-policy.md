# Politique d'audit (GPO)

GPO **`PURPLELAB - Audit avance`**, créée par [`setup-audit-gpo.ps1`](setup-audit-gpo.ps1) (S09).
Liée à la racine `purplelab.local` (postes) **et** à l'OU `Domain Controllers` (ordre 1).

## Audit avancé (Advanced Audit Policy Configuration)

| Catégorie | Sous-catégorie | Réglage | Événements | Scénarios |
|---|---|---|---|---|
| Account Logon | Credential Validation | Réussite + Échec | 4776 | 1, 4 |
| Account Logon | Kerberos Authentication Service | Réussite + Échec | 4768, 4771 | 1, 2 |
| Account Logon | Kerberos Service Ticket Operations | Réussite + Échec | 4769 | 3 |
| Logon/Logoff | Logon | Réussite + Échec | 4624, 4625 | 1, 4 |
| Logon/Logoff | Logoff | Réussite | 4634 | — |
| Logon/Logoff | Account Lockout | Réussite | 4625 (verrouillé) | 1 (rejeu) |
| Logon/Logoff | Special Logon | Réussite | 4672 | 4, 5 |
| Detailed Tracking | Process Creation | Réussite | 4688 | tous |
| Account Management | User Account Management | Réussite + Échec | 4720, 4738, 4740 | 2, 3 |
| Account Management | Security Group Management | Réussite + Échec | 4728, 4732, 4756 | 5 |
| DS Access | Directory Service Changes | Réussite | 5136 (nécessite une SACL) | 5 |

## Autres paramètres de la GPO
- « Force audit policy subcategory settings » (`SCENoApplyLegacyAuditPolicy = 1`).
- « Include command line in process creation events » (`ProcessCreationIncludeCmdLine_Enabled = 1`).
- PowerShell : Script Block Logging (4104) + Module Logging `*` (4103).
- Journal Security : 512 Mo.
