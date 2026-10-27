# Durcissement Active Directory

Mesures de remédiation par scénario (à remplir au fur et à mesure).

| Scénario           | Durcissement AD                                                        | Statut |
|--------------------|------------------------------------------------------------------------|--------|
| Password spraying  | Politique de MDP robuste, lockout, MFA/alerte sur rafales d'échecs     | ⬜     |
| AS-REP roasting    | Supprimer « ne pas exiger la pré-auth Kerberos » sur les comptes       | ⬜     |
| Kerberoasting      | Comptes de service en gMSA, mots de passe longs, chiffrement AES       | ⬜     |
| Pass-the-Hash      | Tiering administratif, LAPS, Protected Users, restriction NTLM         | ⬜     |
| Chemin → DA        | Réduire les chemins BloodHound, nettoyer ACL/délégations excessives    | ⬜     |
