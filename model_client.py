from __future__ import annotations

import json
import os
import urllib.error
import urllib.request
from types import SimpleNamespace
from typing import Any

from dotenv import load_dotenv
import ollama

load_dotenv()

CURRENT_GEMINI_MODEL = "gemini-3.8-flash"


def normalize_model_name(provider: str, model: str) -> str:
    if provider == "gemini" and model in {"gemini-2.0-flash", "models/gemini-2.0-flash"}:
        return CURRENT_GEMINI_MODEL
    return model


class ModelClientError(RuntimeError):
    """Raised when a configured model provider cannot complete a request."""


def _native_contents(messages: list[dict[str, Any]]) -> tuple[str, list[dict[str, Any]]]:
    system = ""
    contents = []
    call_names: dict[str, str] = {}
    for message in messages:
        role = message["role"]
        if role == "system":
            system += f"{message.get('content') or ''}\n"
            continue
        if role == "tool":
            call_id = message.get("tool_call_id")
            name = call_names.get(call_id) if call_id else "tool"
            name = name or call_id or "tool"
            contents.append({
                "role": "user",
                "parts": [{"functionResponse": {
                    "name": name,
                    "response": {"result": message.get("content") or ""},
                }}],
            })
            continue

        parts = []
        content = message.get("content") or ""
        if content:
            parts.append({"text": content})
        if role == "assistant":
            native_role = "model"
            for index, call in enumerate(message.get("tool_calls") or []):
                call_id = getattr(call, "id", None) or f"call_{index}"
                name = call.function.name
                call_names[call_id] = name
                parts.append({"functionCall": {
                    "name": name,
                    "args": call.function.arguments or {},
                }})
        else:
            native_role = "user"
        contents.append({"role": native_role, "parts": parts or [{"text": ""}]})
    return system.strip(), contents


def _native_tools(tools: list[dict[str, Any]]) -> list[dict[str, Any]]:
    if not tools:
        return []
    return [{"functionDeclarations": [
        {
            "name": tool["function"]["name"],
            "description": tool["function"].get("description", ""),
            "parameters": tool["function"].get("parameters", {}),
        }
        for tool in tools
    ]}]


class GeminiClient:
    """Small native Gemini client using only the Python standard library."""

    def __init__(self, api_key: str, model: str, timeout: int = 120) -> None:
        self.api_key = api_key
        self.model = model
        self.timeout = timeout

    def chat(self, *, model: str, messages: list[dict], tools: list[dict]) -> Any:
        del model
        system, contents = _native_contents(messages)
        payload: dict[str, Any] = {"contents": contents}
        if system:
            payload["systemInstruction"] = {"parts": [{"text": system}]}
        native_tools = _native_tools(tools)
        if native_tools:
            payload["tools"] = native_tools

        request = urllib.request.Request(
            f"https://generativelanguage.googleapis.com/v1beta/models/{self.model}:generateContent",
            data=json.dumps(payload).encode("utf-8"),
            headers={
                "Content-Type": "application/json",
                "x-goog-api-key": self.api_key,
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
            parts = data["candidates"][0]["content"].get("parts", [])
        except (KeyError, IndexError, TypeError) as exc:
            raise ModelClientError(f"Unexpected Gemini response: {data}") from exc

        text_parts = [part["text"] for part in parts if part.get("text")]
        tool_calls = []
        for index, part in enumerate(parts):
            function_call = part.get("functionCall")
            if function_call:
                tool_calls.append(SimpleNamespace(
                    id=f"call_{index}",
                    function=SimpleNamespace(
                        name=function_call.get("name", ""),
                        arguments=function_call.get("args") or {},
                    ),
                ))
        return SimpleNamespace(message=SimpleNamespace(
            content="".join(text_parts),
            tool_calls=tool_calls,
        ))


def create_model_client(provider: str, model: str, timeout: int = 120) -> Any:
    model = normalize_model_name(provider, model)
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
