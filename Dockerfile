# Uma imagem, três papéis (api | worker-analysis | worker-ai), escolhidos pelo comando.
FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1

WORKDIR /app

# Dependências primeiro: camada reaproveitada enquanto o pyproject não muda.
COPY pyproject.toml README.md ./
COPY sentinela/__init__.py sentinela/__init__.py
RUN pip install --upgrade pip && pip install . && pip uninstall -y sentinela

COPY . .
RUN pip install --no-deps . \
    && useradd --create-home --uid 1000 sentinela \
    && chmod +x docker/entrypoint.sh

USER sentinela
EXPOSE 8000

HEALTHCHECK --interval=15s --timeout=3s --retries=5 \
  CMD python -c "import urllib.request,sys; sys.exit(0 if urllib.request.urlopen('http://localhost:8000/health').status==200 else 1)" || exit 1

ENTRYPOINT ["docker/entrypoint.sh"]
CMD ["api"]
