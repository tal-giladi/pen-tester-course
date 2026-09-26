FROM nginx:1.27-alpine

# Self-signed cert whose SANs include legacy.northwind.lab — the name that exists
# ONLY in the certificate, so students learn to pivot on cert SANs. LAB-only cert.
RUN apk add --no-cache openssl && mkdir -p /etc/nginx/certs && \
    openssl req -x509 -newkey rsa:2048 -nodes -days 825 \
      -keyout /etc/nginx/certs/northwind.key \
      -out /etc/nginx/certs/northwind.crt \
      -subj "/CN=www.northwind.lab/O=Northwind Retail (LAB)" \
      -addext "subjectAltName=DNS:www.northwind.lab,DNS:shop.northwind.lab,DNS:legacy.northwind.lab"

COPY default.conf /etc/nginx/conf.d/default.conf
COPY html/ /usr/share/nginx/html/
EXPOSE 80 443
