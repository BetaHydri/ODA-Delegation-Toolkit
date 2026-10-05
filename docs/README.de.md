# ODA Delegation Toolkit — Dokumentation

**🌐 Sprache:** [English](README.md) · Deutsch

Ausführliche Anleitung zur Delegation von Least-Privilege-Berechtigungen an ein Group Managed Service Account (gMSA) für das Microsoft **On-Demand Assessment (ODA)** AD Assessment — ohne Domänen-Admin- oder Enterprise-Admin-Anmeldedaten.

## Anleitungen

| Dokument | Sprache | Beschreibung |
| -------- | ------- | ------------ |
| [ODA-Delegation-Guide.de.md](ODA-Delegation-Guide.de.md) | Deutsch | Vollständige Anleitung zur Least-Privilege-Delegation — WMI/SCM/NTFS/AD-Rechte, AGDLP-Gruppenverschachtelung, DCOM/WinRM/Firewall und das Just-In-Time-(JIT-)Delegationsmodell |
| [ODA-Delegation-Guide.md](ODA-Delegation-Guide.md) | English | Complete least-privilege delegation guide — WMI/SCM/NTFS/AD rights, AGDLP group nesting, DCOM/WinRM/Firewall, and the Just-In-Time (JIT) delegation model |
| [ODA-MultiForest-Setup-Leitfaden.docx](ODA-MultiForest-Setup-Leitfaden.docx) | Deutsch | Schritt-für-Schritt-Setup für ODA AD & AD Security in mehreren AD-Forests — Azure-Seite (Engage Center Connector, ein LAW je Forest, RBAC) und Collector-Seite on-prem (Arc, AMA, gMSA, GPO, Aufgaben) |
| [ODA-JIT-EnterpriseAdmin-Konzept.docx](ODA-JIT-EnterpriseAdmin-Konzept.docx) | Deutsch | Konzept für Just-in-Time-Enterprise-Admin des Assessment-gMSA — Ende-Signale der Sammlung, Karenzzeit, geplante Aufgaben, mehrere Forests |
| [ODA-JIT-Deployment.de.md](ODA-JIT-Deployment.de.md) ([Word](ODA-JIT-Deployment.de.docx)) | Deutsch | Bereitstellung der JIT-Skripte (FullEA) auf dem Tier-0-Host je Forest — benötigte Dateien, Ausführer-gMSA, Rechte, Ports, Konfiguration, Probelauf, Betrieb |
| [ODA-JIT-Deployment.md](ODA-JIT-Deployment.md) | English | Deploying the JIT scripts (FullEA) on the Tier-0 host per forest — required files, executor gMSA, rights, ports, configuration, trial run, operations |
| [PAM-Trust-Shadow-Principals.de.md](PAM-Trust-Shadow-Principals.de.md) ([Word](PAM-Trust-Shadow-Principals.de.docx)) | Deutsch | PIM-Trust (PAM-Trust) und Shadow Principals mit Bordmitteln — zeitgebundene Mitgliedschaften, SID-Filterung, Einrichtung zwischen Admin- und Produktions-Forests, Bedeutung für ODA-JIT |
| [PAM-Trust-Shadow-Principals.md](PAM-Trust-Shadow-Principals.md) | English | Built-in PIM trust (PAM trust) and shadow principals — time-bound memberships, SID filtering, step-by-step setup between an admin forest and production forests, impact on ODA-JIT |

Für die Skripte und die Schnellstart-Nutzung siehe die Projekt-[README](../README.de.md) ([English](../README.md)).
