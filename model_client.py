from __future__ import annotations

import json
import os
import urllib.error
import urllib.request
from types import SimpleNamespace
from typing import Any

import ollama


class ModelClientError(RuntimeError):
    """Raised when a configured model provider cannot complete a request."""


def _tool_calls_from_openai(message: dict[str, Any]) -> list[Any]:
    calls = []
    for call in message.get("tool_calls") or []:
        function = call.get("function", {})
        try:
            arguments = json.loads(function.get("arguments") or "{}")
        except json.JSONDecodeError as exc:
            raise ModelClientError(f"Invalid tool arguments from model: {exc}") from exc
        calls.append(SimpleNamespace(
            id=call.get("id"),
            function=SimpleNamespace(
                name=function.get("name", ""),
                arguments=arguments,
            )
        ))
    return calls


def _normalize_message(message: dict[str, Any]) -> dict[str, Any]:
    role = message["role"]
    normalized = {"role": role, "content": message.get("content") or ""}
    if role == "assistant" and message.get("tool_calls"):
        normalized["tool_calls"] = [
            {
                "id": getattr(call, "id", None) or f"call_{index}",
                "type": "function",
                "function": {
                    "name": call.function.name,
                    "arguments": json.dumps(call.function.arguments or {}),
                },
            }
            for index, call in enumerate(message["tool_calls"])
        ]
    if role == "tool" and message.get("tool_call_id"):
        normalized["tool_call_id"] = message["tool_call_id"]
    return normalized


class GeminiClient:
    """Small OpenAI-compatible Gemini client using only the Python standard library."""

    def __init__(self, api_key: str, model: str, timeout: int = 120) -> None:
        self.api_key = api_key
        self.model = model
        self.timeout = timeout

    def chat(self, *, model: str, messages: list[dict], tools: list[dict]) -> Any:
        del model
        system = next((m["content"] for m in messages if m["role"] == "system"), "")
        payload_messages = [
            _normalize_message(message)
            for message in messages
            if message["role"] != "system"
        ]
        payload = {
            "model": self.model,
            "messages": payload_messages,
            "tools": tools,
            "tool_choice": "auto",
        }
        if system:
            payload["messages"].insert(0, {"role": "system", "content": system})

        request = urllib.request.Request(
            "https://generativelanguage.googleapis.com/v1beta/openai/chat/completions",
            data=json.dumps(payload).encode("utf-8"),
            headers={
                "Content-Type": "application/json",
                "Authorization": f"Bearer {self.api_key}",
            },
            method="POST",
        )
        try:
            with urllib.request.urlopen(request, timeout=self.timeout) as response:
                data = json.load(response)
        except (urllib.error.HTTPError, urllib.error.URLError, TimeoutError) as exc:
            details = exc.read().decode("utf-8", errors="replace") if isinstance(exc, urllib.error.HTTPError) else str(exc)
            raise ModelClientError(f"Gemini request failed: {details}") from exc

        try:
            message = data["choices"][0]["message"]
        except (KeyError, IndexError, TypeError) as exc:
            raise ModelClientError(f"Unexpected Gemini response: {data}") from exc

        return SimpleNamespace(message=SimpleNamespace(
            content=message.get("content") or "",
            tool_calls=_tool_calls_from_openai(message),
        ))


def create_model_client(provider: str, model: str, timeout: int = 120) -> Any:
    if provider == "ollama":
        return ollama.Client(
            host=os.getenv("OLLAMA_HOST", "http://127.0.0.1:11434"),
            timeout=timeout,
        )
    if provider == "gemini":
        api_key = os.getenv("GEMINI_API_KEY")
        if not api_key:
            raise ModelClientError("GEMINI_API_KEY is required when provider=gemini")
        return GeminiClient(api_key=api_key, model=model, timeout=timeout)
    raise ModelClientError(f"Unsupported model provider: {provider}")
