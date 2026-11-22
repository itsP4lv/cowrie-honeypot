FROM python:3.12-slim
WORKDIR /app
RUN pip install --no-cache-dir flask==3.1.* maxminddb==2.* gunicorn==23.*
# Géoloc DB-IP + carte + drapeaux, téléchargés une fois au build.
# GEO_MONTH sert à forcer la mise à jour : docker compose build --build-arg GEO_MONTH=$(date +%Y-%m) panel
ARG GEO_MONTH=initial
COPY fetch_assets.py .
RUN echo "assets $GEO_MONTH" && python fetch_assets.py /app/assets
# Utilisateur sans privilèges : même en cas de faille dans le panel, pas de root dans le conteneur.
RUN useradd --system --uid 10001 --no-create-home panel && mkdir -p /state /bans && chown panel /state /bans
COPY *.py ./
COPY static/ static/
ENV COWRIE_DATA=/data PANEL_ASSETS=/app/assets PANEL_STATE=/state PANEL_BANS=/bans PYTHONUNBUFFERED=1
USER panel
EXPOSE 8080
# Un seul processus (un seul thread d'ingestion), plusieurs threads pour les requêtes.
CMD ["gunicorn", "--bind", "0.0.0.0:8080", "--workers", "1", "--threads", "8", "--timeout", "60", "--access-logfile", "-", "app:app"]
