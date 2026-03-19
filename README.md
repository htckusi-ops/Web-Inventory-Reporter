# Web Inventory Reporter

Scannt eine Liste von Domains, erstellt Screenshots und generiert professionelle Reports im SRG SSR Corporate Design.

## Setup

```bash
pip install -r requirements.txt
playwright install chromium
```

## Run

```bash
python main.py domains.txt
```

Die Datei `domains.txt` enthält pro Zeile einen Hostnamen (Kommentare mit `#`):

```
srgssr.ch
srf.ch
rts.ch
rsi.ch
```

## Output

| Datei | Beschreibung |
|---|---|
| `output/report.html` | Visueller Report (Karten-/Tabellenansicht), Base64-Bilder eingebettet |
| `output/report.xlsx` | Formatierter Excel-Report mit Thumbnails |
| `output/report.csv` | Rohdaten |
| `output/screenshots/` | Vollständige Screenshots (PNG, 1280×800 Viewport) |
| `output/thumbnails/` | 16:10 Thumbnails (480×300px) |
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
- SRG SSR Branding (`#af001d` Rot, `#333333` Grau)
- Umschaltbar zwischen Karten-Grid und Tabelle
- Base64-eingebettete Bilder (portabel, eine Datei)
- Zusammenfassungs-Statistiken im Header
- Responsive Layout

### Excel Report
- Header im SRG-Rot mit weisser Schrift
- Zebra-Streifen, korrekt verankerte Thumbnails
- Eingefrorene Kopfzeile, Autofilter
- Status-Farbcodierung

### CSV
- Saubere Rohdaten ohne Bild-Pfade

## Farbschema

Aus dem offiziellen SRG SSR Design Guidelines Manual:

| Farbe | Hex | RGB |
|---|---|---|
| SRG Rot | `#af001d` | 175, 0, 30 |
| SRG Grau | `#333333` | 51, 51, 51 |