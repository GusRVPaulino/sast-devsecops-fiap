"""Configuração por variáveis de ambiente (prefixo SENTINELA_)."""

from __future__ import annotations

from functools import lru_cache

from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_prefix="SENTINELA_", env_file=".env", extra="ignore")

    database_url: str = "sqlite:///./sentinela.db"
    redis_url: str = "redis://localhost:6379/0"
    # inline: a API processa na própria requisição (útil em dev/testes).
    # queue:  a API só enfileira; workers Celery processam (produção/Compose).
    execution_mode: str = "inline"

    ai_enabled: bool = True
    ollama_url: str = "http://localhost:11434"
    ollama_model: str = "llama3"
    ollama_timeout: float = 60.0

    use_bandit: bool = True
    api_token: str | None = None  # se definido, POST/PATCH exigem header X-API-Token
    github_token: str | None = None
    max_upload_mb: int = 20


@lru_cache
def get_settings() -> Settings:
    return Settings()
