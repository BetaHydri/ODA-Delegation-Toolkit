# Azure-Hilfsskripte

**🌐 Sprache:** [English](README.md) · Deutsch

Azure-seitiges Hilfsskript für das ODA-JIT-Setup (Weg D im [Projekt-README](../README.de.md#unterstützte-wege)).

## Copy-ODAJitDataCollectionRules.ps1

Erstellt die Azure-Monitor-**Datensammlungsregeln (DCRs)** und Zuordnungen zum Rechner, die eine **zweite ODA-Instanz auf demselben Arc-Rechner** benötigt.

### Wann wird es benötigt?

Die ODA-Registrierung legt je Assessment-Typ eine DCR für den Arc-Rechner an (`ad-dcr-rule`, `adsecurity-dcr-rule`). Jede DCR hat ein **festes Dateimuster** (das Arbeitsverzeichnis der Instanz, z. B. `C:\Assessments\ADAssessment\*.assessmentadrecs`) und **einen** Ziel-Log-Analytics-Workspace.

Läuft eine zweite ODA-Instanz (z. B. die FullEA-/JIT-Instanz) auf **demselben** Arc-Rechner mit **eigenem Arbeitsverzeichnis und eigenem Workspace**, überwacht keine DCR dieses Verzeichnis. Die Aufgaben laufen und schreiben Ergebnisdateien, der Azure Monitor Agent sammelt sie aber nicht ein, und der neue Workspace bleibt leer.

Nicht nötig, wenn jede ODA-Instanz einen eigenen Collector (eigenen Arc-Rechner) hat: Dieser Rechner bekommt seine DCRs von der Registrierung.

### Was es macht

1. Liest die vorhandenen Quell-DCRs (nur lesend).
2. Klont jede unter neuem Namen und ändert **nur** das Dateimuster (neues Arbeitsverzeichnis) und den Ziel-Workspace. Streams, Datenfluss, Ausgabetabelle, Transformation und Data Collection Endpoint bleiben identisch.
3. Ordnet jede neue DCR dem Arc-Rechner zu. Bestehende Zuordnungen bleiben unberührt.
4. Prüft, dass die Transformation mit der Quelle identisch ist, die Zuordnung existiert und die Zieltabellen im neuen Workspace vorhanden sind.

| Quell-DCR | Neue DCR | Neue Zuordnung |
| --------- | -------- | -------------- |
| `ad-dcr-rule` | `ad-<suffix>-dcr-rule` | `ad-<suffix>-dcr-assoc` |
| `adsecurity-dcr-rule` | `adsecurity-<suffix>-dcr-rule` | `adsecurity-<suffix>-dcr-assoc` |

`<suffix>` ist standardmäßig `jit` (`-NameSuffix`). Das Skript schreibt nicht, wenn ein Zielname gleich einem Quellnamen ist.

### Voraussetzungen

- PowerShell 7 und Azure CLI, angemeldet mit `az login` (das Skript liest nur das Token; der `az`-Subscription-Kontext wird nicht geändert).
- Monitoring Contributor auf Ressourcengruppe und Arc-Rechner sowie Leserechte auf dem Ziel-Workspace.
- Arbeitsverzeichnis, Aufgaben und Workspace der zweiten Instanz existieren bereits (siehe [Schritt 5 des Bereitstellungsleitfadens](../docs/ODA-JIT-Deployment.de.md#schritt-5--konfiguration-anlegen)).

### Verwendung

```powershell
# Nur Vorschau: liest die Quellen, zeigt, was geschrieben würde
.\Copy-ODAJitDataCollectionRules.ps1 -SubscriptionId <subscription-id> `
    -ResourceGroup RG-ODA -ArcMachineName ODA-COL-A `
    -TargetWorkspaceName LAW-ODA-B -WorkingDirectory C:\Assessments-FullEA -WhatIf

# Anlegen (idempotent: erneutes Ausführen aktualisiert dieselben Ressourcen)
.\Copy-ODAJitDataCollectionRules.ps1 -SubscriptionId <subscription-id> `
    -ResourceGroup RG-ODA -ArcMachineName ODA-COL-A `
    -TargetWorkspaceName LAW-ODA-B -WorkingDirectory C:\Assessments-FullEA

# Nur entfernen, was dieses Skript angelegt hat (Quell-DCRs bleiben unberührt)
.\Copy-ODAJitDataCollectionRules.ps1 -SubscriptionId <subscription-id> `
    -ResourceGroup RG-ODA -ArcMachineName ODA-COL-A `
    -TargetWorkspaceName LAW-ODA-B -WorkingDirectory C:\Assessments-FullEA -Remove
```

| Parameter | Bedeutung |
| --------- | --------- |
| `-SubscriptionId`, `-ResourceGroup` | Subscription und Ressourcengruppe der Quell-DCRs und des Arc-Rechners |
| `-ArcMachineName` | Arc-fähiger Collector (`Microsoft.HybridCompute/machines`) |
| `-TargetWorkspaceName`, `-TargetWorkspaceResourceGroup` | Workspace der zweiten Instanz (Ressourcengruppe standardmäßig `-ResourceGroup`) |
| `-WorkingDirectory` | Arbeitsverzeichnis der zweiten Instanz (wie bei `Add-ADAssessmentTask -WorkingDirectory`) |
| `-NameSuffix` | Namensbestandteil der neuen Ressourcen (Standard `jit`) |
| `-Remove` | Vom Skript angelegte Zuordnungen und DCRs löschen |
| `-WhatIf` | Zeigt die Änderungen, ohne zu schreiben |

### Nach dem Anlegen

Der Agent liest nur Zeilen, die **nach** dem Wirksamwerden der DCR geschrieben werden. Ein Lauf, der vor den DCRs endete, wird nicht erfasst. Daher einen neuen ODA-Lauf starten, 10-15 Minuten warten und den Ziel-Workspace abfragen:

```kusto
ADAssessmentRecommendation | where TimeGenerated > ago(2h) | take 10
```

### Vom Skript behandelte Falle

Die `transformKql` der ODA-DCRs enthält vier geschützte Leerzeichen (U+00A0). Die Ausgabe von `az monitor` und `az rest` läuft durch die Konsolen-Codepage und verliert sie stillschweigend, wodurch aus `extend rowData = ...` das ungültige `extendrowData=...` wird. Das Skript ruft daher die ARM-REST-API direkt mit UTF-8-Bytes auf und vergleicht die Transformation nach dem Schreiben unter Beachtung der Groß-/Kleinschreibung.

### Weiterführend

- [Bereitstellungsleitfaden, Schritt 5](../docs/ODA-JIT-Deployment.de.md#schritt-5--konfiguration-anlegen) - die zusätzlichen DCRs, das resultierende Layout und der Datenfluss Collector, DCE, DCR, Workspace ([English](../docs/ODA-JIT-Deployment.md#step-5--create-the-configuration))
