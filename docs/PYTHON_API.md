# Python client API

The Python facade normalizes ordinary callables and JSON-like cases into the
same canonical runner and semantic verifier used by the CLI.

## Minimal evaluation

```python
from cavada_eval import evaluate
from cavada_eval.evaluators import exact_match
from cavada_eval.targets import OpenAICompatibleTarget

result = evaluate(
    target=OpenAICompatibleTarget(
        base_url="http://127.0.0.1:8000/v1",
        model="qwen3",
        api_key_env="LOCAL_API_KEY",
    ),
    dataset="data.jsonl",
    prompt="{question}",
    evaluators=[exact_match("answer")],
    output_directory="runs",
)

print(result.path)
print(result.summary)
print(result.verification)
```

`evaluate` accepts one target and one prompt. Use an experiment plan for a
multi-prompt or multi-target matrix.

## Cases and datasets

```python
from cavada_eval.evaluators import EvalCase

cases = [
    EvalCase(
        id="ticket-001",
        input={"question": "How do I reset my password?"},
        expected={"answer": "Use the reset link."},
        metadata={"category": "account"},
        extras={"document_ids": ["help-7"]},
    )
]
```

`input`, `expected`, `metadata`, and `extras` must be finite JSON-like values.
A dataset may be:

- an iterable of mappings or `EvalCase` objects;
- a UTF-8 JSONL or CSV path;
- a zero-argument iterable factory.

Missing IDs are derived deterministically from record content. Explicit or
derived duplicate IDs are rejected before target contact.

```python
def support_dataset():
    yield {
        "id": "ticket-001",
        "question": "How do I reset my password?",
        "answer": "Use the reset link.",
    }
```

## Callable target

A sync or async callable receives the rendered case. Return text or a mapping
with `output` and any observed optional evidence.

```python
async def local_target(request):
    return {
        "output": "Use the reset link.",
        "usage": {"prompt_tokens": 8, "completion_tokens": 5},
        "metadata": {"backend_revision": "dev-7"},
    }
```

Optional response fields are `structured_output`, `usage`, `latency`, `citations`, `retrieval`, `tool_calls`,
`trace`, `metadata`, and `raw`. Structured JSON may be retained in `output`. Do not populate a
field that was not observed. Target exceptions become preserved execution
errors rather than failed model answers.

Pass the callable directly to `evaluate`, or give it a stable identity in a
config file with `factory = "module:callable"`. Config factories execute as
trusted local code.

## Prompt renderers

A prompt may be a format string, chat-message sequence, `PromptVariant`, or a
synchronous callable receiving `EvalCase`.

```python
def render(case):
    return f"Question: {case.input['question']}"
```

Templates can address unambiguous fields from the case ID, input, expected,
metadata, and extras. Unknown or ambiguous fields fail before target contact.
No template engine or expression language is involved; rendering uses Python's
deterministic `str.format_map` behavior.

## Callable evaluator

An evaluator receives the original case and normalized target response. Return
an `EvaluationResult`; do not encode execution errors as a score.

```python
from cavada_eval.evaluators import EvaluationResult

def concise(case, response):
    words = len(response["answer"].split())
    passed = words <= 20
    return EvaluationResult(
        passed=passed,
        score=float(passed),
        metrics={"word_count": float(words)},
        reason="at most 20 words" if passed else "answer exceeded 20 words",
        evidence={"maximum_words": 20},
    )
```

Callable evaluators may also be async. A result keeps `passed`, `score`, named
metrics, reason, error, invalid state, and evidence distinct.

Built-ins in `cavada_eval.evaluators` include `exact_match`,
`normalized_match`, `contains`, `regex_match`, `json_valid`, `json_fields`,
`token_f1_score`, and `retrieval_metrics`. Retrieval evaluation requires the
target to declare the `retrieval` capability and return retrieval evidence.

## Operational controls

`evaluate` exposes `repetitions`, `concurrency`, `timeout_seconds`, `retries`,
`max_cases`, `max_requests`, `max_cost`, `max_tokens`, `rate_limit`,
`external_authorization`, and `resume`. A cost limit is accepted only when an
OpenAI-compatible target has an explicit pricing source and provider usage can
be observed. Cavada never invents token usage or cost.
