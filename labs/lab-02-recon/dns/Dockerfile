FROM internetsystemsconsortium/bind9:9.20

# Two configs are baked in; docker-compose picks which one each nameserver uses by
# mounting it over /etc/bind/named.conf. Zone file is shared.
COPY db.northwind.lab /etc/bind/db.northwind.lab
COPY named.ns1.conf /etc/bind/named.ns1.conf
COPY named.ns2.conf /etc/bind/named.ns2.conf
