# Web Inventory Reporter

Scannt eine Liste von Domains, erstellt Screenshots und generiert professionelle Reports (HTML, Excel, CSV).

## Setup

```bash
pip install -r requirements.txt
playwright install chromium
```

## Konfiguration

Alle Einstellungen werden in `config.ini` vorgenommen:

```ini
[general]
domains_file = domains.txt      # Standard-Domainliste

[author]
name  = Your Name
email = your@email.com

[titles]
main_title       = Your Name – Web Inventory Report
subtitle         = Automatisierte Website-Übersicht
sheet_inventory  = Web Inventory
sheet_summary    = Zusammenfassung

[colors]
primary  = af001d   # Akzentfarbe (Hex, ohne #)
dark     = 333333
white    = ffffff
light_bg = f5f5f5
border   = dee2e6
```

## Verwendung

```bash
# Domainliste aus config.ini verwenden
python main.py

# Eigene Domainliste übergeben
python main.py my_domains.txt
```

Die Domainliste enthält pro Zeile einen Hostnamen (Kommentare mit `#`):

```
example.com
example.org
```

## Output

| Datei | Beschreibung |
|---|---|
| `output/report.html` | Visueller Report (Karten-/Tabellenansicht), Base64-Bilder eingebettet |
| `output/report.xlsx` | Formatierter Excel-Report mit Thumbnails |
| `output/report.csv` | Rohdaten |
| `output/screenshots/` | Vollständige Screenshots (PNG, 1280×800 Viewport) |
| `output/thumbnails/` | 16:10 Thumbnails (320×200px) |
| `output/logs/scan.log` | Scan-Protokoll |

## Features

### Daten pro Host
- HTTP-Statuscode mit Farbcodierung (2xx grün, 3xx gelb, 4xx/5xx rot)
- Ladezeit in Sekunden (farblich: <1.5s grün, <3s gelb, >3s rot)
- SSL-Zertifikat Ablaufdatum
- Finale URL nach Redirects
- Seitentitel
- Screenshot + 16:10 Thumbnail

### HTML Report
- Umschaltbar zwischen Karten-Grid und Tabelle
- Base64-eingebettete Bilder (portabel, eine Datei)
- Zusammenfassungs-Statistiken im Header
- Responsive Layout

### Excel Report
- Farbiger Header, konfigurierbar via `config.ini`
- Zebra-Streifen, korrekt verankerte Thumbnails
- Eingefrorene Kopfzeile, Autofilter
- Status-Farbcodierung
- Zusammenfassung mit Top-10 langsamsten Hosts und SSL-Ablaufdaten

### CSV
- Saubere Rohdaten ohne Bild-Pfade
