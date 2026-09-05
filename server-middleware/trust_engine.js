/**
 * trust_engine.js
 * ---------------------------------------------------------------
 * Combineert ALLE beschikbare signalen (rate-limiter-status,
 * honeypot-hits, scraper-headers, TLS-fingerprint, en optioneel
 * client-gerapporteerde gedragssignalen) tot één trust-score per
 * client, in plaats van elk signaal los te laten blokkeren.
 *
 * WAAROM dit beter is dan losse checks:
 * Een aanvaller die weet dat je op user-agent checkt, spoft de
 * user-agent. Weet hij dat je op timing checkt, randomiseert hij
 * de timing. Maar ALLE signalen tegelijk perfect vervalsen — een
 * gespoofte browser-UA, mét geloofwaardige TLS-fingerprint, mét
 * menselijke timing, mét een geldige honeypot-negatie — kost
 * significant meer moeite dan elk signaal apart omzeilen. Dit is
 * het "meerdere lagen"-principe: niet onbreekbaar, maar wel duurder
 * om te doorbreken naarmate je meer onafhankelijke signalen combineert.
 *
 * Gebruik:
 *   const { trustEngine, getTrustRecord } = require('./trust_engine');
 *   app.use(scraperHeaderCheck());   // zet req.scraperFlags
 *   app.use(tlsFingerprintCheck());  // zet req.tlsFingerprint
 *   app.use(trustEngine({ minScoreToAllow: 40 }));
 *
 * De engine verwacht dat eerdere middleware (honeypot_middleware.js,
 * tls_fingerprint.js) hun bevindingen op het request-object zetten;
 * hij leest die uit en telt ze bij elkaar op tot één beslissing.
 * ---------------------------------------------------------------
 */

'use strict';

// Persistente trust-records per client-sleutel (IP, of eigen keyFn).
// In-memory hier; voor productie met meerdere instances: Redis/DB,
// zodat een client niet ontsnapt door een andere server-instance
// te raken.
const trustRecords = new Map();

function getTrustRecord(key) {
  if (!trustRecords.has(key)) {
    trustRecords.set(key, {
      score: 100,
      history: [],
      firstSeen: Date.now(),
      lastSeen: Date.now(),
    });
  }
  return trustRecords.get(key);
}

function adjustTrust(key, delta, reason) {
  const record = getTrustRecord(key);
  record.score = Math.max(0, Math.min(100, record.score + delta));
  record.lastSeen = Date.now();
  record.history.push({ delta, reason, at: record.lastSeen, scoreAfter: record.score });
  if (record.history.length > 50) record.history.shift();
  return record;
}

/**
 * Weegfactoren per signaaltype. Pas aan op basis van wat je in de
 * praktijk ziet — deze startwaarden zijn een redelijk uitgangspunt,
 * geen wet van Meden en Perzen.
 */
const WEIGHTS = {
  honeypotTriggered: -70,      // vrijwel zeker een bot
  scraperUserAgent: -25,
  missingAcceptLanguage: -10,
  missingAccept: -10,
  tlsSuspicious: -30,
  tlsUnavailable: 0,           // neutraal — geen ondersteuning is geen schuld
  rateLimitHit: -15,
  cleanRequestReward: +1,      // langzaam herstel bij normaal gedrag
};

function trustEngine(opts = {}) {
  const minScoreToAllow = opts.minScoreToAllow ?? 30;
  const keyFn = opts.keyFn ?? ((req) => req.ip || 'unknown');
  const onReject = opts.onReject;

  return function trustEngineMiddleware(req, res, next) {
    const key = keyFn(req);
    const record = getTrustRecord(key);

    // Signalen uitlezen die eerdere middleware op req heeft gezet.
    // Elke ontbrekende bron wordt overgeslagen (geen valse straf voor
    // een middleware die niet is aangehaakt).
    const reasons = [];

    if (req.honeypotTriggered) {
      adjustTrust(key, WEIGHTS.honeypotTriggered, 'honeypot_triggered');
      reasons.push('honeypot_triggered');
    }

    if (Array.isArray(req.scraperFlags)) {
      if (req.scraperFlags.includes('known_scraper_user_agent')) {
        adjustTrust(key, WEIGHTS.scraperUserAgent, 'scraper_user_agent');
        reasons.push('scraper_user_agent');
      }
      if (req.scraperFlags.includes('missing_accept_language')) {
        adjustTrust(key, WEIGHTS.missingAcceptLanguage, 'missing_accept_language');
        reasons.push('missing_accept_language');
      }
      if (req.scraperFlags.includes('missing_accept_header')) {
        adjustTrust(key, WEIGHTS.missingAccept, 'missing_accept_header');
        reasons.push('missing_accept_header');
      }
    }

    if (req.tlsFingerprint) {
      if (req.tlsFingerprint.suspicious) {
        adjustTrust(key, WEIGHTS.tlsSuspicious, 'tls_suspicious');
        reasons.push('tls_suspicious');
      }
    }

    if (reasons.length === 0) {
      // Schoon verzoek: langzaam vertrouwen laten herstellen zodat
      // een client die ooit één keer een vals-positief kreeg niet
      // permanent gestraft blijft.
      adjustTrust(key, WEIGHTS.cleanRequestReward, 'clean_request');
    }

    req.trustScore = record.score;
    req.trustReasons = reasons;

    if (record.score < minScoreToAllow) {
      if (onReject) return onReject(req, res, record);

      return res.status(403).json({
        error: 'forbidden',
        message: 'Verzoek geweigerd op basis van gecombineerde vertrouwenssignalen.',
        trust_score: record.score,
      });
    }

    return next();
  };
}

/**
 * Client-gerapporteerde gedragssignalen (mouse-entropy, timing-CV
 * uit script.js) kunnen NOOIT los vertrouwd worden — de client kan
 * liegen. Gebruik deze functie alleen om een trust-score verder
 * te VERLAGEN op basis van server-side bevestigde combinaties, nooit
 * om 'm te verhogen op basis van alleen client-beweringen.
 *
 * Concreet: als de client zelf claimt "ik ben een bot-achtig
 * patroon" (via een optioneel eigen beacon-endpoint dat script.js
 * kan aanroepen), heeft dat wel waarde — een bot die zich verraadt
 * heeft geen reden om te liegen in zijn eigen nadeel. Maar een
 * claim van "ik ben menselijk" vanuit de client mag nooit score
 * verhogen, want dat is precies wat een aanvaller zou vervalsen.
 */
function applyClientReportedSignal(key, { mouseVarianceTooLow, timingTooRegular }) {
  if (mouseVarianceTooLow) {
    adjustTrust(key, -20, 'client_reported_low_mouse_entropy');
  }
  if (timingTooRegular) {
    adjustTrust(key, -15, 'client_reported_regular_timing');
  }
  // Bewust: geen positieve tak hier. Zie docstring hierboven.
}

module.exports = {
  trustEngine,
  getTrustRecord,
  adjustTrust,
  applyClientReportedSignal,
  WEIGHTS,
};
