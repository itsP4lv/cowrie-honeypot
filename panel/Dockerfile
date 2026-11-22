FROM python:3.12-slim
WORKDIR /app
RUN pip install --no-cache-dir flask==3.1.* maxminddb==2.*
# Géoloc DB-IP + carte + drapeaux, téléchargés une fois au build.
# GEO_MONTH sert à forcer la mise à jour : docker compose build --build-arg GEO_MONTH=$(date +%Y-%m) panel
ARG GEO_MONTH=initial
COPY fetch_assets.py .
RUN echo "assets $GEO_MONTH" && python fetch_assets.py /app/assets
COPY app.py .
ENV COWRIE_DATA=/data PANEL_ASSETS=/app/assets
EXPOSE 8080
CMD ["python", "app.py"]
