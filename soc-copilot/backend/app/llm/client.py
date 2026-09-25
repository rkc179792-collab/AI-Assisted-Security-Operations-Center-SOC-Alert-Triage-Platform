import httpx
import structlog

from app.core.config import settings


log = structlog.get_logger()


async def generate(prompt: str, system: str | None = None) -> str:
    """Send a prompt to the configured LLM provider and return the text."""

    match settings.llm_provider:
        case "ollama":
            return await _ollama(prompt, system)
        case "openai":
            return await _openai(prompt, system)
        case _:
            log.warning("llm.unknown_provider", provider=settings.llm_provider)
            return "[llm unavailable]"


async def _ollama(prompt: str, system: str | None) -> str:
    payload = {
        "model": settings.llm_model,
        "prompt": prompt,
        "system": system or "",
        "stream": False,
    }
    async with httpx.AsyncClient(timeout=120.0) as client:
        resp = await client.post(f"{settings.llm_base_url}/api/generate", json=payload)
        resp.raise_for_status()
        return resp.json().get("response", "").strip()


async def _openai(prompt: str, system: str | None) -> str:
    # Left as an exercise — wire up your preferred OpenAI-compatible endpoint.
    raise NotImplementedError("Configure an OpenAI-compatible client here.")
