/**
 * tls_fingerprint.js
 * ---------------------------------------------------------------
 * JA3-achtige TLS-fingerprinting. Dit vangt een hele klasse
 * aanvallers die de HTTP-laag (headers, user-agent, timing) perfect
 * vervalsen, maar de onderliggende TLS-handshake van hun HTTP-
 * library (Python requests, Go net/http, node-fetch) niet aanpassen
 * — want dat zit dieper dan de meeste scraper-frameworks reiken.
 *
 * BELANGRIJK — technische beperking om vooraf te begrijpen:
 * Een reverse proxy zoals nginx termineert TLS vóórdat het verzoek
 * bij je Node/Python-app aankomt. De ruwe TLS ClientHello (nodig
 * voor een echte JA3-hash) is op dat punt al weg. Er zijn twee
 * eerlijke opties:
 *
 *   A) nginx laat de JA3-hash meesturen als header (vereist
 *      nginx met de ssl_preread-module of een sidecar zoals
 *      https://github.com/salesforce/ja3 / nginx-ja3-module).
 *      Dit bestand leest die header uit als hij aanwezig is.
 *
 *   B) Zonder die nginx-module heb je geen echte JA3-hash
 *      beschikbaar op applicatieniveau. In dat geval valt deze
 *      module terug op een "arme-mans-fingerprint": een hash van
 *      TLS-gerelateerde metadata die Node's eigen TLS-laag WEL ziet
 *      wanneer je de Node-app direct (zonder proxy) laat luisteren
 *      op https, zoals de aangeboden cipher-suites en ALPN-protocollen.
 *      Dit is zwakker dan een echte JA3 maar nog steeds bruikbaar om
 *      HTTP-libraries te onderscheiden van echte browsers, omdat
 *      curl/requests/axios andere cipher-orders aanbieden dan Chrome/
 *      Firefox.
 *
 * Kortom: dit is geen magische kogel. Zie het als één extra signaal
 * in de gecombineerde score (trust_engine.js), niet als losstaande
 * blokkade.
 *
 * Installatie voor optie A (aanbevolen, echte JA3):
 *   Zie deploy/nginx.conf — de ssl_preread + map-directive die de
 *   hash als X-JA3-Hash header doorzet.
 *
 * Gebruik:
 *   const { tlsFingerprintCheck } = require('./tls_fingerprint');
 *   app.use(tlsFingerprintCheck());
 * ---------------------------------------------------------------
 */

'use strict';

const crypto = require('crypto');

/**
 * Bekende JA3-hashes van veelgebruikte HTTP-libraries (niet van
 * browsers). Dit is een kleine startlijst — vul aan met hashes die
 * je zelf tegenkomt in je logs (log eerst met blockOnMatch: false
 * om te zien wat er langskomt voordat je gaat blokkeren).
 *
 * Bron voor het opbouwen van je eigen lijst: log X-JA3-Hash voor
 * bekende test-requests (curl, python-requests, playwright) tegen
 * je eigen staging-omgeving en noteer de hashes die je ziet.
 */
const KNOWN_NON_BROWSER_JA3 = new Set([
  // Voorbeeld-placeholders — vervang met hashes uit je eigen logs.
  // 'e7d705a3286e19ea42f587b344ee6865',  // python-requests voorbeeld
  // '773906b0efdefa24a7f2b8eb6985bf37',  // curl voorbeeld
]);

function tlsFingerprintCheck(opts = {}) {
  const blockOnMatch = opts.blockOnMatch ?? false;
  const headerName = opts.headerName ?? 'x-ja3-hash';

  return function tlsFingerprintMiddleware(req, res, next) {
    const ja3 = req.get(headerName);

    if (!ja3) {
      // Geen JA3 beschikbaar (nginx-module niet geïnstalleerd, of
      // request kwam niet via TLS/proxy). Markeer dit als "onbekend",
      // niet als "verdacht" — anders straf je elke lokale test af.
      req.tlsFingerprint = { available: false, ja3: null, suspicious: false };
      return next();
    }

    const suspicious = KNOWN_NON_BROWSER_JA3.has(ja3);
    req.tlsFingerprint = { available: true, ja3, suspicious };

    if (suspicious && blockOnMatch) {
      return res.status(403).json({ error: 'forbidden', message: 'Verzoek geweigerd.' });
    }

    return next();
  };
}

/**
 * Optie B: "arme-mans-fingerprint" wanneer je Node direct met https
 * laat luisteren (geen nginx ervoor, of nginx zonder ssl_preread).
 * Hash van de onderhandelde cipher + ALPN-protocol van het socket.
 * Zwakker signaal, maar beter dan niets, en kost een aanvaller nog
 * steeds meer moeite dan puur header-spoofing.
 */
function poorMansTlsHash(socket) {
  try {
    const cipher = socket.getCipher ? socket.getCipher() : null;
    const alpn = socket.alpnProtocol || 'none';
    const proto = socket.getProtocol ? socket.getProtocol() : 'unknown';
    const raw = `${proto}|${cipher ? cipher.name : 'none'}|${alpn}`;
    return crypto.createHash('sha256').update(raw).digest('hex').slice(0, 16);
  } catch {
    return null;
  }
}

module.exports = { tlsFingerprintCheck, poorMansTlsHash, KNOWN_NON_BROWSER_JA3 };
