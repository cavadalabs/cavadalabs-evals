from __future__ import annotations

from typing import Any

# `built_in=False` blocks official use until a pinned, identity-verifying
# adapter and calibration evidence are attached.
ADAPTER_CONTRACT_VERSION = "1.0.0"

TASK_PROFILES: dict[str, dict[str, Any]] = {
    "text-generation": {"inputs": ["text"], "output": "text", "built_in": True},
    "classification": {"inputs": ["text"], "output": "text", "built_in": True},
    "structured-extraction": {"inputs": ["text"], "output": "json", "built_in": True},
    "translation": {"inputs": ["text"], "output": "text", "built_in": True},
    "summarization": {"inputs": ["text"], "output": "text", "built_in": True},
    "rag-retriever": {"inputs": ["text", "retrieval"], "output": "retrieval", "built_in": True},
    "rag-generator": {"inputs": ["text", "retrieval"], "output": "text", "built_in": True},
    "rag-end-to-end": {"inputs": ["text", "retrieval"], "output": "text", "built_in": True},
    "conversation": {"inputs": ["text", "conversation"], "output": "text", "built_in": True},
    "agent": {"inputs": ["text", "tools"], "output": "text", "built_in": False},
    "mcp": {"inputs": ["text", "tools", "mcp"], "output": "text", "built_in": False},
    "image-to-text": {"inputs": ["image"], "output": "text", "built_in": True},
    "text-image-to-text": {"inputs": ["text", "image"], "output": "text", "built_in": True},
    "audio-to-text": {"inputs": ["audio"], "output": "text", "built_in": True},
    "audio-text-to-text": {"inputs": ["text", "audio"], "output": "text", "built_in": True},
    "document-to-text": {"inputs": ["document"], "output": "text", "built_in": False},
    "text-to-image": {"inputs": ["text"], "output": "image", "built_in": False},
    "image-editing": {"inputs": ["text", "image"], "output": "image", "built_in": False},
    "image-retrieval": {"inputs": ["image", "retrieval"], "output": "retrieval", "built_in": False},
    "text-to-audio": {"inputs": ["text"], "output": "audio", "built_in": False},
    "audio-to-audio": {"inputs": ["audio"], "output": "audio", "built_in": False},
    "video-to-text": {"inputs": ["video"], "output": "text", "built_in": False},
    "text-to-video": {"inputs": ["text"], "output": "video", "built_in": False},
    "video-editing": {"inputs": ["text", "video"], "output": "video", "built_in": False},
    "audio-video-to-text": {"inputs": ["audio", "video"], "output": "text", "built_in": False},
    "sandboxed-code": {"inputs": ["text", "code"], "output": "code", "built_in": False},
    "embedding": {"inputs": ["text"], "output": "embedding", "built_in": False},
    "reranking": {"inputs": ["text", "retrieval"], "output": "ranking", "built_in": False},
    "clustering": {"inputs": ["embedding"], "output": "clusters", "built_in": False},
    "semantic-search": {"inputs": ["text", "retrieval"], "output": "ranking", "built_in": False},
    "safety": {"inputs": ["text"], "output": "text", "built_in": True},
    "privacy": {"inputs": ["text"], "output": "text", "built_in": True},
    "fairness": {"inputs": ["text"], "output": "text", "built_in": True},
    "performance": {"inputs": ["text"], "output": "text", "built_in": True},
}


def profile_summary() -> list[dict[str, Any]]:
    return [{"name": name, **value} for name, value in sorted(TASK_PROFILES.items())]
