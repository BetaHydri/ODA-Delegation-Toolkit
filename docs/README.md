# ODA Delegation Toolkit — Documentation

**🌐 Language:** English · [Deutsch](README.de.md)

In-depth guidance for delegating least-privilege permissions to a Group Managed Service Account (gMSA) for the Microsoft **On-Demand Assessment (ODA)** AD Assessment — without Domain Admin or Enterprise Admin credentials.

## Guides

| Document | Language | Description |
| -------- | -------- | ----------- |
| [ODA-Delegation-Guide.md](ODA-Delegation-Guide.md) | English | Complete least-privilege delegation guide — WMI/SCM/NTFS/AD rights, AGDLP group nesting, DCOM/WinRM/Firewall, and the Just-In-Time (JIT) delegation model |
| [ODA-Delegation-Guide.de.md](ODA-Delegation-Guide.de.md) | Deutsch | Vollständige Anleitung zur Least-Privilege-Delegation — WMI/SCM/NTFS/AD-Rechte, AGDLP-Gruppenverschachtelung, DCOM/WinRM/Firewall und das Just-In-Time-(JIT-)Delegationsmodell |
| [ODA-MultiForest-Setup-Leitfaden.docx](ODA-MultiForest-Setup-Leitfaden.docx) | Deutsch | Step-by-step setup of ODA AD & AD Security for multiple AD forests — Azure side (Engage Center Connector, one LAW per forest, RBAC) and on-prem collector side (Arc, AMA, gMSA, GPO, tasks) |
| [ODA-JIT-EnterpriseAdmin-Konzept.docx](ODA-JIT-EnterpriseAdmin-Konzept.docx) | Deutsch | Concept for just-in-time Enterprise Admin of the assessment gMSA — end-of-collection signals, grace period, scheduled tasks, multiple forests |
| [ODA-JIT-Deployment.md](ODA-JIT-Deployment.md) | English | Deploying the JIT scripts (FullEA) on the Tier-0 host per forest — required files, executor gMSA, rights, ports, configuration, trial run, operations |
| [PAM-Trust-Shadow-Principals.md](PAM-Trust-Shadow-Principals.md) | English | Built-in PIM trust (PAM trust) and shadow principals — time-bound memberships, SID filtering, step-by-step setup between an admin forest and production forests, impact on ODA-JIT |
| [PAM-Trust-Shadow-Principals.de.md](PAM-Trust-Shadow-Principals.de.md) ([Word](PAM-Trust-Shadow-Principals.de.docx)) | Deutsch | PIM-Trust (PAM-Trust) und Shadow Principals mit Bordmitteln — zeitgebundene Mitgliedschaften, SID-Filterung, Einrichtung zwischen Admin- und Produktions-Forests, Bedeutung für ODA-JIT |
| [ODA-JIT-Deployment.de.md](ODA-JIT-Deployment.de.md) ([Word](ODA-JIT-Deployment.de.docx)) | Deutsch | Bereitstellung der JIT-Skripte (FullEA) auf dem Tier-0-Host je Forest — benötigte Dateien, Ausführer-gMSA, Rechte, Ports, Konfiguration, Probelauf, Betrieb |

For the scripts and quick-start usage, see the project [README](../README.md) ([Deutsch](../README.de.md)).
