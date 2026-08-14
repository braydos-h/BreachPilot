"""AI provider adapters.

Chat/generate providers that plug into the ``ModelClient`` seam in
``tools.model_router``. Each adapter exposes an object with a ``chat(**kwargs)``
method returning an Ollama-shaped response (dict for non-stream, iterable of
chunk dicts for stream) so the existing chat closure / telemetry / tool-call
normalization reuse unchanged.

Currently:
- ``chatgpt_provider``: local openai-oauth proxy (``127.0.0.1:10531/v1``)
  backed by the operator's ChatGPT account via browser OAuth.
"""
