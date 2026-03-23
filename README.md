![Banner](assets/banner.png)
# Web Inventory Reporter

Browser-basierter Website-Scanner (Playwright/Chromium) mit professionellen Reports in HTML, Excel, CSV und JSON.

## Setup

```bash
pip install -r requirements.txt
playwright install chromium
```

## Konfiguration

Alle Einstellungen in `config.ini`:

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

[scan]
workers          = 4        # Parallele Browser-Instanzen
goto_timeout     = 15000    # ms bis Seitenladeabbruch
page_timeout     = 30000    # ms generelles Page-Timeout
ssl_timeout      = 5        # Sekunden für SSL-Verbindung
screenshot_delay = 1500     # ms Wartezeit vor Screenshot (Cookie-Banner verschwinden lassen)
card_width       = 240      # Minimale Kartenbreite in der HTML-Ansicht (px)
```

## Verwendung

```bash
# Domainliste aus config.ini verwenden
python main.py

# Eigene Domainliste übergeben
python main.py my_domains.txt
```

Domainliste: ein Hostname pro Zeile, Kommentare mit `#`:

```
example.com
# example.org   ← wird übersprungen
sub.example.net
```

## Output

| Datei | Beschreibung |
|---|---|
| `output/report.html` | Visueller Report (Karten-/Tabellenansicht), alle Bilder eingebettet (portabel) |
| `output/report.xlsx` | Formatierter Excel-Report mit Thumbnails, Zusammenfassung, Conditional Formatting |
| `output/report.csv` | Rohdaten (alle Felder, kein Binardata) |
| `output/report.json` | KI-lesbarer JSON-Report mit Metadaten und vollständigen Host-Infos |
| `output/screenshots/` | Vollständige Screenshots (PNG, 1280×800 Viewport) |
| `output/thumbnails/` | 16:10 Thumbnails (320×200 px, JPEG) |
| `output/logs/scan.log` | Scan-Protokoll |
| `output/last_scan.json` | Vorheriger Scan für Delta-Vergleich |

## Features

### Daten pro Host

| Feld | Beschreibung |
|---|---|
| `status` | HTTP-Statuscode (2xx/3xx/4xx/5xx) |
| `scan_state` | Technischer Status: `ok` / `dns_failed` / `tls_failed` / `timeout` / `connection_refused` / `blocked` / `error` |
| `load_time` | Ladezeit in Sekunden |
| `ssl_expiry` | SSL-Zertifikat Ablaufdatum (aus Browser-TLS-Handshake) |
| `cert_subject_cn` | Zertifikats-Subject (Common Name) |
| `cert_san` | Subject Alternative Names (SAN) |
| `cms` | Erkanntes CMS: WordPress, Joomla, Drupal, TYPO3, Shopify, Wix u.a. |
| `cdn` | CDN/Hoster: Cloudflare, CloudFront, Fastly, Akamai, Vercel, Netlify u.a. |
| `ip` | Aufgelöste IP-Adresse |
| `reverse_dns` | Reverse-DNS-Hostname |
| `nameservers` | Autoritative Nameserver der Domain |
| `asn` / `asn_name` | ASN-Nummer und Provider-Name (via Team Cymru DNS) |
| `hosting_country` | Ländercode des Providers |
| `registrar` | Domain-Registrar (via WHOIS) |
| `domain_expiry` | Domain-Ablaufdatum (via WHOIS) |
| `redirect_chain` | Alle Zwischenumleitungen mit Statuscodes |
| `security_headers` | Score + Präsenz von HSTS, CSP, X-Frame-Options u.a. |
| `delta` | Änderung seit letztem Scan: `new` / `changed` / `unchanged` |
| `scan_time` | ISO-Zeitstempel des Scans |

### HTML Report

- **Karten- und Tabellenansicht** umschaltbar
- **Klickbare Filter**: Klick auf IP, Nameserver, CDN-Badge oder ASN in einer Kachel filtert alle Hosts mit demselben Wert
- **Mehrere Filter gleichzeitig**: z.B. IP + CDN kombinieren (AND-Logik)
- Aktive Filter als Chips mit individuellem ×-Button; „Alle aufheben" löscht alle auf einmal
- Suche, Statusfilter, CMS-Filter kombinierbar mit den Klick-Filtern
- Delta-Hervorhebung (neu / geändert)
- Security-Header-Tooltip per Mouse-over
- Cookie-Banner werden vor dem Screenshot ausgeblendet
- Base64-eingebettete Bilder (eine portable Datei)

### Excel Report

- Preview-Thumbnail in **Spalte A** (links) für schnellen Überblick
- 25 Datenspalten, eingefrorene Kopfzeile, Autofilter
- Zebra-Streifen, Status-Farbcodierung, Ladezeit-Conditional-Formatting
- Zusammenfassungs-Sheet: Statistiken, Top-10 langsamste Hosts, SSL-Ablaufdaten, Fehler-Hosts

### CSV

Alle Felder als Rohdaten, keine Bilder, direkt in Excel/R/Python importierbar.

### JSON (KI-lesbar)

```json
{
  "meta": {
    "generated_at": "...",
    "tool": "Web Inventory Reporter",
    "scan_method": "Browser-basierter Check (Playwright/Chromium)",
    "total_hosts": 42,
    "summary": { "status_2xx": 38, "avg_load_s": 1.4, ... }
  },
  "hosts": [
    {
      "host": "example.com",
      "ip": "93.184.216.34",
      "asn": "AS15133",
      "asn_name": "EDGECAST",
      "cdn": "CloudFront",
      "scan_state": "ok",
      "ssl_expiry": "31.12.2025",
      "cert_subject_cn": "example.com",
      ...
    }
  ]
}
```

---

[GitHub Repository](https://github.com/htckusi-ops/Web-Inventory-Reporter/tree/main)
