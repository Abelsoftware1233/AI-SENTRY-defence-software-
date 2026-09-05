# SENTRY — AI Defense Console

Compleet systeem tegen misdragende AI: bot/scraper-detectie, een
prompt-injectie firewall, een honeypot-systeem en een token-bucket
rate limiter. Client-side dashboard + echte server-middleware +
deployment-tooling.

## Structuur

```
ai-defense-suite/
├── index.html                       Dashboard UI
├── script.js                        Client-side detectielogica (echt, geen mock-data)
├── backend/
│   ├── app.py                       FastAPI backend: serveert dashboard + /api/*
│   └── requirements.txt
├── server-middleware/
│   ├── rate_limiter.js              Express token-bucket middleware
│   ├── prompt_firewall.py           Heuristische injectie-scanner (bron van waarheid)
│   ├── honeypot_middleware.js       Honeypot + scraper-header detectie
│   ├── tls_fingerprint.js           JA3/TLS-laag fingerprinting (optioneel, zie nginx.conf)
│   └── trust_engine.js              Combineert ALLE signalen tot één score (meerdere-lagen-verdediging)
└── deploy/
    ├── deploy.sh                    Installatiescript — draai dit zelf op je server
    ├── nginx.conf                   Reverse proxy template (SSL via certbot)
    └── ai-defense.service           systemd unit template
```

## Lokaal testen (zonder server)

Open `index.html` direct in een browser om alleen het dashboard met
de client-side modules te zien draaien (mouse-entropy, headless-
fingerprint, honeypot, prompt-scanner-preview, rate-limiter-simulatie).

Voor de échte backend erbij (server-side firewall-enforcement,
honeypot-logging):

```bash
cd backend
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
uvicorn app:app --reload --port 8000
```

Ga naar `http://127.0.0.1:8000`.

## Deployen op je eigen server

Vereist: een Ubuntu/Debian-server met root-toegang, en een DNS
A-record dat je domein (standaard `botnet.abelsoftware123.com` —
pas aan naar je eigen domein) naar het IP van die server wijst.

```bash
# Kopieer dit hele project naar de server, bv. via git of scp:
scp -r ai-defense-suite user@jouw-server:/opt/ai-defense-suite

# Log in op de server en draai:
cd /opt/ai-defense-suite
chmod +x deploy/deploy.sh
sudo ./deploy/deploy.sh
```

Het script vraagt om het domein en de systeemgebruiker, en regelt
daarna zelf: venv + dependencies, systemd-service, nginx reverse
proxy, en optioneel een Let's Encrypt-certificaat via certbot.

Na afloop:

```bash
systemctl status ai-defense       # service-status
journalctl -u ai-defense -f       # live logs
```

## Gecombineerde verdediging (trust_engine.js)

De losse checks (honeypot, scraper-headers, TLS-fingerprint, rate
limiter) zetten elk hun bevinding op het request-object. `trust_engine.js`
telt die op tot één score per client en blokkeert pas onder een
drempel — zo moet een aanvaller ALLE signalen tegelijk vervalsen in
plaats van er telkens één. Voorbeeld uit de eigen tests van dit project:

- Alleen een scraper-user-agent + ontbrekende header → score 65,
  nog altijd toegelaten (geen enkel signaal is doorslaggevend).
- Diezelfde scraper-user-agent + een honeypot-hit → score 0,
  geblokkeerd (combinatie van signalen duwt onder de drempel).

Koppel de middleware in deze volgorde zodat elke laag zijn bevindingen
al gezet heeft voordat de trust-engine ze samenvoegt:

```js
app.use(scraperHeaderCheck());     // zet req.scraperFlags
app.use(tlsFingerprintCheck());    // zet req.tlsFingerprint
app.use(trustEngine({ minScoreToAllow: 30 }));
app.post('/contact', formHoneypotCheck(), handler); // zet req.honeypotTriggered vóór trustEngine als je 'm hiervóór plaatst
```

**JA3/TLS-fingerprinting vereist een aangepaste nginx-build**
(`nginx-ja3-module` of vergelijkbaar) — dat compileert `deploy.sh`
niet automatisch, omdat het geen standaard apt-pakket is. Zonder die
module blijft dit signaal simpelweg "onbekend" (geen valse straf) in
plaats van een harde vereiste. Zie de commentaren in
`tls_fingerprint.js` en `deploy/nginx.conf` voor de exacte stappen.

## Belangrijk om te weten

- **Client-side rate limiting en de prompt-scanner-preview in
  `script.js` zijn illustratief, niet afdwingbaar.** Een gebruiker
  bestuurt zijn eigen browser en kan client-side JS aanpassen.
  Echte afdwinging gebeurt in `server-middleware/` en `backend/app.py`,
  die serverside draaien en dus niet te omzeilen zijn door de client.
- **`prompt_firewall.py` is regel-gebaseerd (heuristiek), geen AI-
  model.** Dat is een bewuste keuze: voorspelbaar, snel, geen externe
  afhankelijkheden, en makkelijk uit te breiden met eigen patronen
  zodra je nieuwe aanvalspogingen in je logs ziet.
- **De honeypot-log en rate-limiter-state in `app.py` zijn in-memory.**
  Voor productie met meerdere workers/instances vervang je dit door
  Redis of een database — anders heeft elke worker zijn eigen los-
  staande state. Zie de commentaren in `rate_limiter.js` voor een
  kant-en-klaar Redis-voorbeeld.
- **Dit is verdediging in de diepte, geen garantie.** Elke laag apart
  (mouse-entropy, headers, TLS-fingerprint) is voor een gemotiveerde
  aanvaller met genoeg tijd te vervalsen — geen enkel gedragssignaal
  is fundamenteel onnabootsbaar, want de aanvaller schrijft uiteindelijk
  ook maar software die output produceert. Wat `trust_engine.js` toevoegt
  is dat alle signalen tegelijk moeten kloppen, wat de kosten voor de
  aanvaller verhoogt, maar "ondoordringbaar" is dit systeem niet en kan
  geen enkel zelfgebouwd systeem beloven — ook grote commerciële
  aanbieders (Cloudflare, DataDome) formuleren hun eigen producten nooit
  in die termen.
- **Wat hier bewust niet in zit:** adversarial image-perturbatie
  (Nightshade/Glaze-stijl "poison pill" images om beeldherkennings-
  modellen te saboteren). Dat vereist het genereren van gradient-
  based aanvallen tegen ML-classifiers — een aanval-primitief tegen
  AI-systemen, ongeacht het defensieve doel. In plaats daarvan levert
  dit project het honeypot/trap-systeem (onzichtbare velden en
  scraper-headerdetectie), wat hetzelfde defensieve doel dient zonder
  die grens over te gaan.
