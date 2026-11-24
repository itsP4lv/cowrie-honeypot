FROM python:3.12-slim
# Utilisateur sans privilèges, aucune dépendance externe (bibliothèque standard uniquement)
RUN useradd --system --uid 10002 --no-create-home redishp && mkdir -p /var/log/redis-hp && chown redishp /var/log/redis-hp
WORKDIR /app
COPY redis_honeypot.py .
ENV PYTHONUNBUFFERED=1 REDIS_HP_PORT=6379 REDIS_HP_LOG_DIR=/var/log/redis-hp
USER redishp
EXPOSE 6379
CMD ["python", "-I", "redis_honeypot.py"]
