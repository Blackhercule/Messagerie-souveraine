# Console de sécurité : petite application Flask, exécutée sans privilèges.
FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1
WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY console ./console
COPY wsgi.py .

# Même identifiant que l'utilisateur de Synapse (991) : les deux lisent/écrivent le dossier /journal.
RUN groupadd --gid 991 console && useradd --uid 991 --gid 991 --no-create-home console \
    && mkdir -p /donnees /journal && chown 991:991 /donnees /journal
USER 991

EXPOSE 8000
CMD ["gunicorn", "--bind", "0.0.0.0:8000", "--workers", "1", "--threads", "4", "--forwarded-allow-ips", "*", "wsgi:app"]
