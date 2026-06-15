"""LLM provider interface + factory."""

from __future__ import annotations

from collections.abc import AsyncIterator
from typing import Protocol

from ..core.config import get_settings


class LLMUnavailable(RuntimeError):
    """Raised when an LLM is requested but no provider is configured."""


class LLMProvider(Protocol):
    name: str

    async def complete(self, prompt: str, max_tokens: int = 512) -> str: ...

    def stream(self, prompt: str, max_tokens: int = 512) -> AsyncIterator[str]: ...


class NoLLMProvider:
    """Headless provider — never errors, returns a clear rule-based summary."""

    name = "none"

    async def complete(self, prompt: str, max_tokens: int = 512) -> str:
        return (
            "[LLM disabled — install with `pip install mitiphy[llm]` and set "
            "MITIPHY_LLM_PROVIDER=llamacpp + MITIPHY_LLM_MODEL_PATH to enable.]"
        )

    async def stream(self, prompt: str, max_tokens: int = 512) -> AsyncIterator[str]:
        text = await self.complete(prompt, max_tokens)
        yield text


class LlamaCppProvider:
    """Loads a local gguf model via llama-cpp-python."""

    name = "llamacpp"

    def __init__(self, model_path: str) -> None:
        try:
            from llama_cpp import Llama  # type: ignore[import-not-found]
        except ImportError as exc:
            raise LLMUnavailable(
                "llama-cpp-python not installed; install 'mitiphy[llm]'."
            ) from exc
        if not model_path:
            raise LLMUnavailable("MITIPHY_LLM_MODEL_PATH is empty.")
        self._llm = Llama(model_path=model_path, n_ctx=4096, verbose=False)

    async def complete(self, prompt: str, max_tokens: int = 512) -> str:
        out = self._llm(prompt, max_tokens=max_tokens, echo=False)
        return out["choices"][0]["text"]  # type: ignore[index]

    async def stream(self, prompt: str, max_tokens: int = 512) -> AsyncIterator[str]:
        for chunk in self._llm(prompt, max_tokens=max_tokens, stream=True, echo=False):
            yield chunk["choices"][0]["text"]  # type: ignore[index]


class OllamaProvider:
    """HTTP client against an Ollama daemon."""

    name = "ollama"

    def __init__(self, endpoint: str, model: str) -> None:
        self.endpoint = endpoint.rstrip("/")
        self.model = model

    async def complete(self, prompt: str, max_tokens: int = 512) -> str:
        import httpx

        async with httpx.AsyncClient(timeout=60.0) as c:
            r = await c.post(
                f"{self.endpoint}/api/generate",
                json={"model": self.model, "prompt": prompt, "stream": False, "options": {"num_predict": max_tokens}},
            )
            r.raise_for_status()
            return r.json().get("response", "")

    async def stream(self, prompt: str, max_tokens: int = 512) -> AsyncIterator[str]:
        import json

        import httpx

        async with httpx.AsyncClient(timeout=None) as c:
            async with c.stream(
                "POST",
                f"{self.endpoint}/api/generate",
                json={"model": self.model, "prompt": prompt, "stream": True, "options": {"num_predict": max_tokens}},
            ) as r:
                async for line in r.aiter_lines():
                    if not line.strip():
                        continue
                    try:
                        evt = json.loads(line)
                    except json.JSONDecodeError:
                        continue
                    chunk = evt.get("response", "")
                    if chunk:
                        yield chunk


def get_provider() -> LLMProvider:
    s = get_settings()
    if s.llm_provider == "llamacpp":
        return LlamaCppProvider(s.llm_model_path)
    if s.llm_provider == "ollama":
        return OllamaProvider(s.llm_endpoint or "http://127.0.0.1:11434", s.llm_model_path or "llama3.1:8b")
    return NoLLMProvider()
