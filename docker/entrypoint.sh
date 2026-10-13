#!/bin/sh
set -e

case "$1" in
  api)
    alembic upgrade head
    exec uvicorn sentinela.api.app:app --host 0.0.0.0 --port 8000 --workers "${API_WORKERS:-2}"
    ;;
  worker-analysis)
    exec celery -A sentinela.worker.tasks worker --queues=analysis --concurrency="${WORKER_CONCURRENCY:-2}" --loglevel=info --hostname=analysis@%h
    ;;
  worker-ai)
    # Uma tarefa por vez: o gargalo é o modelo, não a CPU do worker.
    exec celery -A sentinela.worker.tasks worker --queues=ai --concurrency="${WORKER_CONCURRENCY:-1}" --loglevel=info --hostname=ai@%h
    ;;
  *)
    exec "$@"
    ;;
esac
