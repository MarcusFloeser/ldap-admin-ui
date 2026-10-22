FROM python:3.12-slim
 
ENV PYTHONUNBUFFERED=1 PIP_NO_CACHE_DIR=1
WORKDIR /app
 
COPY requirements.txt .
RUN pip install -r requirements.txt
 
COPY app.py .
COPY static ./static
COPY templates ./templates
COPY locales ./locales

# COPY übernimmt die Rechte vom Host; ohne das kann der Nicht-Root-Benutzer die Dateien evtl. nicht lesen
RUN chmod -R a+rX /app
 
# Nicht als root laufen
RUN useradd --system --uid 10001 app
USER app
 
EXPOSE 8080

LABEL org.opencontainers.image.source="https://github.com/marcusfloeser/ldap-admin-ui"
 
# Wichtig: genau 1 Worker, denn die Sitzungen liegen im Arbeitsspeicher des Prozesses.
# Parallelität kommt über Threads.

CMD ["gunicorn", "--bind", "0.0.0.0:8080", "--workers", "1", "--threads", "8", \
     "--access-logfile", "-", "app:app"]
