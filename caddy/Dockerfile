# Point d'entrée HTTPS + application web Element, dans une seule image.
FROM caddy:2.11.2

# Element Web 1.12.33 (licence AGPL-3.0), téléchargé une seule fois, à la construction de l'image.
# L'empreinte SHA-256 garantit que le fichier est exactement celui publié par Element :
# si le fichier a été modifié, la construction échoue.
ADD --checksum=sha256:04e180516430381d5f5e528ea345a435784bba26f76a84f106a623febd3fcd67 \
    https://github.com/element-hq/element-web/releases/download/v1.12.33/element-v1.12.33.tar.gz \
    /tmp/element.tar.gz
RUN mkdir -p /srv/element \
    && tar -xzf /tmp/element.tar.gz -C /srv/element --strip-components=1 \
    && rm /tmp/element.tar.gz /srv/element/config.sample.json

COPY Caddyfile /etc/caddy/Caddyfile
