#!/usr/bin/env bash
#
# deploy.sh — installeert SENTRY AI Defense Console op een Ubuntu/Debian-server.
#
# Dit script:
#   1. Installeert benodigde systeempakketten (python3-venv, nginx, certbot).
#   2. Zet een Python venv op in backend/venv en installeert requirements.txt.
#   3. Kopieert deploy/ai-defense.service naar systemd en start de service.
#   4. Kopieert deploy/nginx.conf naar sites-available/sites-enabled.
#   5. Vraagt of je certbot wilt draaien voor een echt SSL-certificaat.
#
# UITVOEREN:
#   chmod +x deploy/deploy.sh
#   sudo ./deploy/deploy.sh
#
# Je wordt gevraagd om het domein te bevestigen (default: botnet.abelsoftware123.com)
# en de systeemgebruiker waaronder de service moet draaien.
#
# Dit script voert niets automatisch op afstand uit — jij draait het zelf,
# op de server waar je dit project naartoe hebt gekopieerd.
# ---------------------------------------------------------------------------

set -euo pipefail

# ---------- kleur helpers ----------
c_green() { echo -e "\033[0;32m$1\033[0m"; }
c_yellow() { echo -e "\033[0;33m$1\033[0m"; }
c_red() { echo -e "\033[0;31m$1\033[0m"; }

if [[ $EUID -ne 0 ]]; then
  c_red "Dit script moet als root (of met sudo) draaien, omdat het systeempakketten"
  c_red "installeert en systemd/nginx configureert."
  echo "Gebruik: sudo ./deploy/deploy.sh"
  exit 1
fi

# ---------- pad-detectie ----------
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
APP_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"

echo ""
c_green "=== SENTRY AI Defense Console — deploy.sh ==="
echo "Projectmap gedetecteerd op: $APP_DIR"
echo ""

# ---------- invoer ----------
DEFAULT_DOMAIN="botnet.abelsoftware123.com"
read -rp "Domeinnaam voor deze service [$DEFAULT_DOMAIN]: " DOMAIN
DOMAIN="${DOMAIN:-$DEFAULT_DOMAIN}"

DEFAULT_USER="${SUDO_USER:-www-data}"
read -rp "Systeemgebruiker waaronder de service moet draaien [$DEFAULT_USER]: " SERVICE_USER
SERVICE_USER="${SERVICE_USER:-$DEFAULT_USER}"

echo ""
c_yellow "Let op: dit script gaat ervan uit dat het DNS A-record voor $DOMAIN"
c_yellow "al naar het IP-adres van deze server wijst. Zonder dat werkt certbot niet."
read -rp "Doorgaan met deployment voor domein '$DOMAIN' onder gebruiker '$SERVICE_USER'? [y/N] " CONFIRM
if [[ "${CONFIRM,,}" != "y" ]]; then
  echo "Deployment geannuleerd."
  exit 0
fi

# ---------- 1. systeempakketten ----------
c_green "\n[1/5] Systeempakketten installeren..."
apt-get update -y
apt-get install -y python3 python3-venv python3-pip nginx curl

# ---------- 2. python venv + dependencies ----------
c_green "\n[2/5] Python venv opzetten in backend/venv..."
cd "$APP_DIR/backend"

if [[ ! -d "venv" ]]; then
  python3 -m venv venv
  echo "venv aangemaakt."
else
  echo "venv bestaat al, wordt hergebruikt."
fi

# shellcheck disable=SC1091
source venv/bin/activate
pip install --upgrade pip
pip install -r requirements.txt
deactivate

echo "Python-dependencies geïnstalleerd."

# ---------- eigenaarschap ----------
c_green "\n[2b/5] Eigenaarschap van de projectmap instellen op '$SERVICE_USER'..."
chown -R "$SERVICE_USER":"$SERVICE_USER" "$APP_DIR"

# ---------- 3. systemd service ----------
c_green "\n[3/5] systemd service installeren..."
SERVICE_FILE="/etc/systemd/system/ai-defense.service"

sed -e "s|__APP_DIR__|$APP_DIR|g" \
    -e "s|__USER__|$SERVICE_USER|g" \
    "$SCRIPT_DIR/ai-defense.service" > "$SERVICE_FILE"

systemctl daemon-reload
systemctl enable ai-defense
systemctl restart ai-defense

sleep 1
if systemctl is-active --quiet ai-defense; then
  c_green "ai-defense.service draait."
else
  c_red "ai-defense.service is NIET gestart. Bekijk de logs met:"
  c_red "  journalctl -u ai-defense -n 50 --no-pager"
  exit 1
fi

# ---------- 4. nginx config ----------
c_green "\n[4/5] nginx configureren voor $DOMAIN..."
NGINX_AVAILABLE="/etc/nginx/sites-available/$DOMAIN"
NGINX_ENABLED="/etc/nginx/sites-enabled/$DOMAIN"

sed "s|__DOMAIN__|$DOMAIN|g" "$SCRIPT_DIR/nginx.conf" > "$NGINX_AVAILABLE"

if [[ ! -e "$NGINX_ENABLED" ]]; then
  ln -s "$NGINX_AVAILABLE" "$NGINX_ENABLED"
fi

# De config verwijst naar SSL-certificaten die nog niet bestaan als je
# nog geen certbot hebt gedraaid. Zonder geldig cert faalt nginx -t.
# Daarom eerst een tijdelijke HTTP-only config testen, dan certbot draaien.
if [[ ! -d "/etc/letsencrypt/live/$DOMAIN" ]]; then
  c_yellow "Nog geen SSL-certificaat gevonden voor $DOMAIN."
  c_yellow "Er wordt eerst een tijdelijke HTTP-only config geplaatst zodat"
  c_yellow "certbot de acme-challenge kan uitvoeren."

  cat > "$NGINX_AVAILABLE" <<EOF
server {
    listen 80;
    listen [::]:80;
    server_name $DOMAIN;

    location /.well-known/acme-challenge/ {
        root /var/www/html;
    }

    location / {
        proxy_pass http://127.0.0.1:2323;
        proxy_set_header Host \$host;
        proxy_set_header X-Real-IP \$remote_addr;
    }
}
EOF

  nginx -t && systemctl reload nginx

  read -rp "Nu certbot draaien om een echt SSL-certificaat aan te vragen voor $DOMAIN? [y/N] " RUN_CERTBOT
  if [[ "${RUN_CERTBOT,,}" == "y" ]]; then
    apt-get install -y certbot python3-certbot-nginx
    certbot --nginx -d "$DOMAIN" --redirect --agree-tos -m "admin@$DOMAIN" -n || {
      c_red "certbot is mislukt. Controleer of het DNS A-record van $DOMAIN naar dit"
      c_red "server-IP wijst en probeer daarna handmatig: certbot --nginx -d $DOMAIN"
    }
    # Na succesvolle certbot-run overschrijven we met de volledige HTTPS-config
    sed "s|__DOMAIN__|$DOMAIN|g" "$SCRIPT_DIR/nginx.conf" > "$NGINX_AVAILABLE"
  else
    c_yellow "Overgeslagen. De site draait voorlopig alleen over HTTP (poort 80)."
    c_yellow "Draai later handmatig: certbot --nginx -d $DOMAIN"
  fi
else
  c_green "Bestaand SSL-certificaat gevonden voor $DOMAIN, hergebruikt."
fi

nginx -t
systemctl reload nginx

# ---------- 5. afronding ----------
c_green "\n[5/5] Deployment voltooid."
echo ""
echo "-----------------------------------------------------------"
echo " Service:      systemctl status ai-defense"
echo " Logs:         journalctl -u ai-defense -f"
echo " Nginx config: $NGINX_AVAILABLE"
echo " App-map:      $APP_DIR"
echo " Draait onder: $SERVICE_USER"
echo ""
if [[ -d "/etc/letsencrypt/live/$DOMAIN" ]]; then
  echo " Bereikbaar op: https://$DOMAIN"
else
  echo " Bereikbaar op: http://$DOMAIN  (nog geen SSL — draai certbot om HTTPS te activeren)"
fi
echo "-----------------------------------------------------------"
