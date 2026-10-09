FROM python:3.12.12-slim-bookworm
WORKDIR /app
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1 DATA_DIR=/data PORT=8501
RUN apt-get update && apt-get install -y --no-install-recommends curl git tini \
    && rm -rf /var/lib/apt/lists/*
COPY requirements.txt requirements-team.txt ./
RUN pip install --no-cache-dir -r requirements.txt -r requirements-team.txt
COPY . .
RUN mkdir -p /data
EXPOSE 8501
HEALTHCHECK --interval=15s --timeout=5s --start-period=30s --retries=3 \
    CMD curl --fail http://localhost:8501/_stcore/health || exit 1
ENTRYPOINT ["/usr/bin/tini", "--"]
CMD ["python", "-m", "shipper.supervisor"]
