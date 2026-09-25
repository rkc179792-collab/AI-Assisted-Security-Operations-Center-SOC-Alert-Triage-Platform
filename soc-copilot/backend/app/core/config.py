from pydantic_settings import BaseSettings


class Settings(BaseSettings):
    """Runtime configuration, loaded from environment variables."""

    app_name: str = "soc-copilot"
    debug: bool = False

    database_url: str = "postgresql://soc:soc@localhost:5432/soc_copilot"
    redis_url: str = "redis://localhost:6379/0"

    # Webhook shared secrets, keyed by source name.
    # Set these to unique values per source in production.
    webhook_secrets: dict[str, str] = {
        "wazuh": "change-me-wazuh",
        "suricata": "change-me-suricata",
        "zeek": "change-me-zeek",
        "generic": "change-me-generic",
    }

    # Threat intel API keys (all optional — the pipeline degrades gracefully).
    virustotal_api_key: str | None = None
    abuseipdb_api_key: str | None = None

    # Slack incoming webhook URL. Notifications are skipped entirely when unset.
    slack_webhook_url: str | None = None

    # LLM provider selection: "openai", "anthropic", or "ollama".
    llm_provider: str = "ollama"
    llm_model: str = "llama3.1:8b"
    llm_base_url: str = "http://localhost:11434"

    class Config:
        env_file = ".env"


settings = Settings()
