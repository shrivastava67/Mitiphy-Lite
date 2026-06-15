"""LLM provider abstraction.

Three modes:
  - none: no LLM, purely rule-based summarization.
  - llamacpp: llama-cpp-python loading a local gguf.
  - ollama: HTTP client against an Ollama daemon.

Default = "none" so Lite remains usable without downloading a 4.7 GB model.
"""

from .base import LLMProvider, LLMUnavailable, get_provider

__all__ = ["LLMProvider", "LLMUnavailable", "get_provider"]
