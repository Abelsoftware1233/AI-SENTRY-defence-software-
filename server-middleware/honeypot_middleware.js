/**
 * honeypot_middleware.js
 * ---------------------------------------------------------------
 * Server-side afhandeling van honeypot-triggers en verdachte
 * scraper-headers. Werkt samen met het onzichtbare formulierveld
 * in index.html (#honeypot-field, name="website_url").
 *
 * Twee lagen:
 *   1. formHoneypotCheck   — blokkeert POSTs waarin het honeypot-
 *      veld is ingevuld (alleen bots vullen een onzichtbaar veld in).
 *   2. scraperHeaderCheck  — vlagt requests met bekende scraper-
 *      /library-user-agents en ontbrekende headers die een echte
 *      browser altijd meestuurt (Accept-Language, Accept, etc).
 *
 * Gebruik:
 *   const { formHoneypotCheck, scraperHeaderCheck, getFlaggedClients } = require('./honeypot_middleware');
 *
 *   app.use(scraperHeaderCheck());          // past op alle routes
 *   app.post('/contact', formHoneypotCheck(), handler); // op formulier-routes
 * ---------------------------------------------------------------
 */

'use strict';

// In-memory log van gevlagde clients. Voor productie: vervang door
// een echte datastore (Postgres/Redis) zodat dit persistent is en
// query-baar over meerdere server-instances.
const flaggedClients = new Map();

function flagClient(key, reason, meta = {}) {
  const existing = flaggedClients.get(key) || { hits: 0, reasons: [] };
  existing.hits += 1;
  existing.lastSeen = new Date().toISOString();
  existing.reasons.push({ reason, at: existing.lastSeen, ...meta });
  flaggedClients.set(key, existing);
  return existing;
}

function getFlaggedClients() {
  return Array.from(flaggedClients.entries()).map(([key, data]) => ({ key, ...data }));
}

/**
 * Honeypot-veldcheck voor formulier-POSTs.
 * Verwacht dat de body een veld "website_url" bevat (of pas
 * fieldName aan zodat het overeenkomt met je honeypot-input).
 */
function formHoneypotCheck(opts = {}) {
  const fieldName = opts.fieldName ?? 'website_url';

  return function honeypotMiddleware(req, res, next) {
    const value = req.body?.[fieldName];

    if (value && String(value).trim().length > 0) {
      const key = req.ip || 'unknown';
      flagClient(key, 'honeypot_field_filled', { field: fieldName, ua: req.get('user-agent') });

      // Ook zichtbaar maken voor trust_engine.js, zodat dit meetelt in
      // de gecombineerde score i.p.v. alleen hier los te blokkeren.
      req.honeypotTriggered = true;

      // Bewust een generieke 200 terugsturen i.p.v. een expliciete 403:
      // zo leert een scraper niet dat hij ontdekt is, en stopt hij niet
      // per se met scrapen op een manier die makkelijker te detecteren is.
      // Pas dit gedrag aan naar wat bij jouw dreigingsmodel past.
      return res.status(200).json({ status: 'ok', message: 'Bedankt voor je bericht.' });
    }

    return next();
  };
}

/**
 * Detecteert bekende scraper/library user-agents en browsers die
 * headers missen die een echte browser altijd meestuurt.
 * Vlagt (logt), blokkeert standaard niet — pas blockOnFlag aan
 * als je hard wil blokkeren i.p.v. alleen loggen/monitoren.
 */
const KNOWN_SCRAPER_UA_PATTERNS = [
  /python-requests/i,
  /scrapy/i,
  /curl\//i,
  /wget/i,
  /^Go-http-client/i,
  /axios\/\d/i, // legitiem in server-naar-server verkeer, verdacht als "browser"-bezoeker
  /HeadlessChrome/i,
  /PhantomJS/i,
  /^$/, // lege user-agent
];

function scraperHeaderCheck(opts = {}) {
  const blockOnFlag = opts.blockOnFlag ?? false;

  return function scraperHeaderMiddleware(req, res, next) {
    const ua = req.get('user-agent') || '';
    const reasons = [];

    if (KNOWN_SCRAPER_UA_PATTERNS.some((p) => p.test(ua))) {
      reasons.push('known_scraper_user_agent');
    }
    if (!req.get('accept-language')) {
      reasons.push('missing_accept_language');
    }
    if (!req.get('accept')) {
      reasons.push('missing_accept_header');
    }

    // Altijd zichtbaar maken voor trust_engine.js, ongeacht of we hier
    // zelf al blokkeren — de gecombineerde engine wil élk signaal zien,
    // ook een enkele mineure vlag die op zichzelf niet genoeg is.
    req.scraperFlags = reasons;

    if (reasons.length > 0) {
      const key = req.ip || 'unknown';
      flagClient(key, reasons.join(','), { ua, path: req.path });

      if (blockOnFlag && reasons.length >= 2) {
        return res.status(403).json({ error: 'forbidden', message: 'Verzoek geweigerd.' });
      }
    }

    return next();
  };
}

module.exports = {
  formHoneypotCheck,
  scraperHeaderCheck,
  getFlaggedClients,
  flagClient,
};
