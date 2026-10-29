# Image Synapse officielle (AGPL-3.0) + notre module de sécurité.
FROM matrixdotorg/synapse:v1.164.1

COPY securite_messagerie /modules/securite_messagerie
COPY homeserver.yaml.modele log.config demarrer.py /config-modele/
ENV PYTHONPATH=/modules

ENTRYPOINT ["python", "/config-modele/demarrer.py"]
