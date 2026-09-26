# Recon workstation for lab-02. Tools are baked in at BUILD time (when the image has
# Internet); at RUN time it lives on the isolated network with no egress — so it can
# reach the lab's DNS/web but never the real Internet.
FROM alpine:3.20
RUN apk add --no-cache bind-tools curl openssl bash nmap
CMD ["sh", "-c", "echo 'recon workstation up (dig/curl/openssl/nmap). resolver 10.13.0.53'; sleep infinity"]
