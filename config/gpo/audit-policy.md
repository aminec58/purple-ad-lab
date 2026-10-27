# Politique d'audit (GPO)

Audit avancé (Advanced Audit Policy Configuration) :

| Catégorie                     | Sous-catégorie                  | Réglage          |
|-------------------------------|---------------------------------|------------------|
| Account Logon                 | Kerberos Authentication Service | Réussite + Échec |
| Account Logon                 | Kerberos Service Ticket Ops     | Réussite + Échec |
| Logon/Logoff                  | Logon                           | Réussite + Échec |
| Account Management            | User Account Management         | Réussite + Échec |
| Detailed Tracking             | Process Creation (4688)         | Réussite         |

- Activer « Include command line in process creation events ».
- PowerShell : Script Block Logging + Module Logging.
