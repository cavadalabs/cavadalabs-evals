from __future__ import annotations

import base64
import json
import shutil
import threading
from contextlib import contextmanager
from dataclasses import replace
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any, Iterator

import pytest

from cavada_eval import evaluation
from cavada_eval.artifacts import write_bundle
from cavada_eval.behavior_verify import verify_behavior_run
from cavada_eval.evaluation import (
    ExperimentPlan,
    PromptVariant,
    evaluate,
    materialize_dataset,
    prepare_experiment,
    run_experiment,
    verify_experiment,
)
from cavada_eval.evaluators import EvalCase, EvaluationResult, exact_match, retrieval_metrics
from cavada_eval.protocol import ProtocolError
from cavada_eval.targets import CallableTarget, OpenAICompatibleTarget, RecordedTarget

_RESUME_TARGET_CALLS: list[str] = []


def _run_options(**overrides: Any) -> dict[str, Any]:
    return {
        "concurrency": 1,
        "timeout_seconds": 5.0,
        "retries": 0,
        "repetitions": 1,
        "max_cases": 0,
        "max_requests": 100,
        "max_cost": 0.0,
        "max_tokens": 0,
        "max_elapsed_seconds": 0.0,
        "rate_limit": 0.0,
        "fail_fast": False,
        "resume": False,
        "external_authorization": "",
        **overrides,
    }


def _plan(
    root: Path,
    *,
    prompts: tuple[PromptVariant, ...] = (PromptVariant("baseline", template="{question}"),),
    targets: tuple[Any, ...] | None = None,
    evaluators: tuple[Any, ...] | None = None,
    run: dict[str, Any] | None = None,
) -> ExperimentPlan:
    target = CallableTarget("local", lambda case: {"output": case["input"]}, "local-model", "revision-1")
    return ExperimentPlan(
        name="client-test",
        profile="client",
        seed=42,
        dataset=[{"id": "one", "question": "one", "answer": "one"}, {"id": "two", "question": "two", "answer": "two"}],
        prompts=prompts,
        targets=targets or (target,),
        evaluators=evaluators or (exact_match("answer"),),
        run=run or _run_options(),
        output_directory=root / "runs",
        data_classification="synthetic",
        project_root=root,
    )


@pytest.mark.parametrize("kind", ["iterable", "jsonl", "csv", "factory"])
def test_dataset_sources_materialize_identically(tmp_path: Path, kind: str) -> None:
    rows = [{"id": "one", "question": "q1", "answer": "a1"}, {"id": "two", "question": "q2", "answer": "a2"}]
    source: Any = rows
    if kind == "jsonl":
        source = tmp_path / "data.jsonl"
        source.write_text("".join(json.dumps(row) + "\n" for row in rows), encoding="utf-8")
    elif kind == "csv":
        source = tmp_path / "data.csv"
        source.write_text("id,question,answer\none,q1,a1\ntwo,q2,a2\n", encoding="utf-8")
    elif kind == "factory":
        (tmp_path / "trusted_data.py").write_text(f"def rows():\n    return {rows!r}\n", encoding="utf-8")
        source = "trusted_data:rows"

    cases = materialize_dataset(source, root=tmp_path)

    assert [case.id for case in cases] == ["one", "two"]
    assert all(isinstance(case.input, dict) and isinstance(case.expected, dict) for case in cases)


def test_dataset_factory_rejects_duplicate_ids(tmp_path: Path) -> None:
    (tmp_path / "trusted_data.py").write_text(
        "def rows():\n    yield {'id': 'duplicate', 'question': 'one'}\n    yield {'id': 'duplicate', 'question': 'two'}\n",
        encoding="utf-8",
    )
    with pytest.raises(ProtocolError, match="duplicate case ID: duplicate"):
        materialize_dataset("trusted_data:rows", root=tmp_path)


def test_dataset_source_has_a_finite_case_limit(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(evaluation, "MAX_CLIENT_CASES", 1)
    with pytest.raises(ProtocolError, match="dataset exceeds 1 cases"):
        materialize_dataset([{"id": "one"}, {"id": "two"}])


def test_dataset_factory_supports_relative_package_imports(tmp_path: Path) -> None:
    package = tmp_path / "client_data"
    package.mkdir()
    (package / "__init__.py").write_text("", encoding="utf-8")
    (package / "values.py").write_text("ROWS = [{'id': 'one', 'question': 'Q'}]\n", encoding="utf-8")
    (package / "datasets.py").write_text("from .values import ROWS\ndef rows():\n    return ROWS\n", encoding="utf-8")
    assert materialize_dataset("client_data.datasets:rows", root=tmp_path)[0].id == "one"


@pytest.mark.parametrize(
    ("prompt", "expected_text", "expected_messages"),
    [
        (PromptVariant("static", template="fixed"), "fixed", None),
        (PromptVariant("template", template="Question: {question}"), "Question: Q", None),
        (
            PromptVariant(
                "chat",
                messages=(
                    {"role": "system", "content": "Use {category}"},
                    {"role": "user", "content": "{question}"},
                ),
            ),
            "Q",
            [{"role": "system", "content": "Use support"}, {"role": "user", "content": "Q"}],
        ),
        (PromptVariant("callable", renderer=lambda case: f"Callable: {case.input['question']}"), "Callable: Q", None),
    ],
)
def test_prompt_variants_render_json_like_cases(
    prompt: PromptVariant,
    expected_text: str,
    expected_messages: list[dict[str, str]] | None,
) -> None:
    case = EvalCase("case", {"question": "Q"}, {"answer": "A"}, {"category": "support"})
    assert prompt.render(case) == (expected_text, expected_messages)


def test_prompt_missing_field_is_actionable() -> None:
    with pytest.raises(ProtocolError, match=r"unknown field: customer_name[\s\S]*Available fields"):
        PromptVariant("broken", template="{customer_name}").render(EvalCase("case", {"question": "Q"}))
    with pytest.raises(ProtocolError, match="plain field names"):
        PromptVariant("unsafe", template="{question.__class__}").render(EvalCase("case", {"question": "Q"}))


def test_preflight_rejects_capability_and_request_budget_and_ids_are_deterministic(tmp_path: Path) -> None:
    capability_plan = _plan(tmp_path, evaluators=(retrieval_metrics(required=["doc"]),))
    with pytest.raises(ProtocolError, match=r"requires response.retrieval.*does not declare retrieval"):
        prepare_experiment(capability_plan)

    budget_plan = replace(capability_plan, evaluators=(exact_match("answer"),), run=_run_options(max_requests=1))
    with pytest.raises(ProtocolError, match=r"expands to 2 requests.*exceeds max_requests=1"):
        prepare_experiment(budget_plan)

    valid_plan = replace(budget_plan, run=_run_options(max_requests=2))
    assert [cell.cell_id for cell in prepare_experiment(valid_plan).cells] == [
        cell.cell_id for cell in prepare_experiment(valid_plan).cells
    ]


def test_request_budget_covers_retry_attempts_before_target_execution(tmp_path: Path) -> None:
    calls: list[str] = []

    def target(case: dict[str, Any]) -> dict[str, Any]:
        calls.append(str(case["id"]))
        return {"output": "ok"}

    plan = replace(
        _plan(
            tmp_path,
            targets=(CallableTarget("local", target, "local-model", "revision-1"),),
            run=_run_options(retries=2, max_requests=1),
        ),
        dataset=[{"id": "only", "question": "q", "answer": "ok"}],
    )

    with pytest.raises(ProtocolError, match=r"1 requests \(3 maximum target attempts\).*max_requests=1"):
        run_experiment(plan)
    assert calls == []

    prepared = prepare_experiment(replace(plan, run=_run_options(retries=2, max_requests=3)))
    assert prepared.summary["logical_observations"] == 1
    assert prepared.summary["maximum_target_attempts"] == 3

    responses = tmp_path / "recorded-budget.jsonl"
    responses.write_text(
        '{"case_id":"one","response":{"output":"ok","model":"recorded-model"}}\n'
        '{"case_id":"two","response":{"output":"ok","model":"recorded-model"}}\n',
        encoding="utf-8",
    )
    recorded = replace(
        _plan(
            tmp_path / "recorded",
            targets=(RecordedTarget("recorded", responses, "recorded-model", "revision-1"),),
            run=_run_options(retries=2, max_requests=1),
        ),
        dataset=[
            {"id": "one", "question": "q1", "answer": "ok"},
            {"id": "two", "question": "q2", "answer": "ok"},
        ],
    )
    assert prepare_experiment(recorded).summary["maximum_target_attempts"] == 0


def test_callable_workflow_preserves_raw_evidence_and_verifies(tmp_path: Path) -> None:
    def target(case: dict[str, Any]) -> dict[str, Any]:
        return {
            "output": str(case["input"]).upper(),
            "usage": {"prompt_tokens": 2, "completion_tokens": 1},
            "raw": {"provider_id": f"raw-{case['id']}"},
        }

    def evaluator(case: EvalCase, response: dict[str, Any]) -> EvaluationResult:
        passed = response["answer"] == str(case.expected["answer"])
        return EvaluationResult(passed, float(passed), {"custom": float(passed)}, "custom comparison")

    result = evaluate(
        target=target,
        dataset=[{"id": "one", "question": "hello", "answer": "HELLO"}],
        prompt="{question}",
        evaluators=[evaluator],
        data_classification="synthetic",
        output_directory=tmp_path / "runs",
    )
    run_dir = result.path / result.summary["cells"][0]["run"]
    raw = json.loads((run_dir / "raw_responses.jsonl").read_text(encoding="utf-8"))

    assert result.summary["cells"][0]["pass"] == 1
    assert raw["response"]["raw"] == {"provider_id": "raw-one"}
    assert result.verification["valid"] is True
    assert verify_experiment(result.path)["semantic_valid"] is True

    state_path = result.path / "experiment.json"
    state = json.loads(state_path.read_text(encoding="utf-8"))
    state["cells"][0]["target"] = "tampered-target"
    state_path.write_text(json.dumps(state, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    write_bundle(result.path)
    mutated = verify_experiment(result.path)
    assert mutated["integrity_valid"] is True and mutated["semantic_valid"] is False


def test_experiment_verifier_binds_target_type_to_each_behavior_cell(tmp_path: Path) -> None:
    def target(_case: dict[str, Any]) -> dict[str, Any]:
        return {"output": "one"}

    responses = tmp_path / "recorded.jsonl"
    responses.write_text('{"case_id":"one","response":{"output":"one","model":"local-model"}}\n', encoding="utf-8")
    callable_plan = replace(
        _plan(tmp_path / "callable", targets=(CallableTarget("local", target, "local-model", "revision-1"),)),
        dataset=[{"id": "one", "question": "one", "answer": "one"}],
    )
    recorded_plan = replace(
        _plan(tmp_path / "recorded", targets=(RecordedTarget("local", responses, "local-model", "revision-1"),)),
        dataset=[{"id": "one", "question": "one", "answer": "one"}],
    )
    callable_result = run_experiment(callable_plan)
    recorded_result = run_experiment(recorded_plan)
    callable_run = callable_result.path / callable_result.summary["cells"][0]["run"]
    recorded_run = recorded_result.path / recorded_result.summary["cells"][0]["run"]
    shutil.rmtree(callable_run)
    shutil.copytree(recorded_run, callable_run)
    assert evaluation.verify_behavior_run(callable_run)["valid"] is True
    write_bundle(callable_result.path)

    verification = verify_experiment(callable_result.path)

    assert verification["integrity_valid"] is True
    assert verification["semantic_valid"] is False
    assert any("target configuration differs" in failure for failure in verification["semantic_failures"])


@pytest.mark.parametrize("declared", [False, True], ids=("raised", "declared"))
def test_callable_evaluator_exception_is_error_with_raw_marker(tmp_path: Path, declared: bool) -> None:
    def broken(_case: EvalCase, _response: dict[str, Any]) -> EvaluationResult:
        if declared:
            return EvaluationResult(False, 0.0, error="private evaluator detail")
        raise RuntimeError("private evaluator detail")

    result = evaluate(
        target=lambda _case: {"output": "ok"},
        dataset=[{"id": "one", "question": "q", "answer": "ok"}],
        prompt="{question}",
        evaluators=[broken],
        data_classification="synthetic",
        output_directory=tmp_path / "runs",
        concurrency=1,
    )
    run_dir = result.path / result.summary["cells"][0]["run"]
    case_result = json.loads((run_dir / "case_results.jsonl").read_text(encoding="utf-8"))
    judgment = json.loads((run_dir / "judgments.jsonl").read_text(encoding="utf-8"))

    assert case_result["status"] == "error" and result.summary["cells"][0]["error"] == 1
    assert judgment["status"] == "invalid"
    assert judgment["raw"]["cavada_client_evaluator_status"] == "execution-error"
    assert "wire_body_sha256" in judgment and "private evaluator detail" not in json.dumps(judgment)
    assert result.verification["valid"] is True


@pytest.mark.parametrize(
    "evaluator",
    [
        lambda _case, _response: EvaluationResult(False, 0.0, invalid=True),
        lambda _case, _response: {"passed": True},
    ],
    ids=("declared-invalid", "malformed"),
)
def test_invalid_or_malformed_evaluator_output_remains_invalid(tmp_path: Path, evaluator: Any) -> None:
    result = evaluate(
        target=lambda _case: {"output": "ok"},
        dataset=[{"id": "one", "question": "q", "answer": "ok"}],
        prompt="{question}",
        evaluators=[evaluator],
        data_classification="synthetic",
        output_directory=tmp_path / "runs",
        concurrency=1,
    )
    run_dir = result.path / result.summary["cells"][0]["run"]
    case_result = json.loads((run_dir / "case_results.jsonl").read_text(encoding="utf-8"))
    judgment = json.loads((run_dir / "judgments.jsonl").read_text(encoding="utf-8"))

    assert case_result["status"] == "invalid" and result.summary["cells"][0]["invalid"] == 1
    assert "cavada_client_evaluator_status" not in judgment["raw"]
    assert result.verification["valid"] is True


@contextmanager
def _openai_server() -> Iterator[tuple[str, list[dict[str, Any]]]]:
    calls: list[dict[str, Any]] = []

    class Handler(BaseHTTPRequestHandler):
        def do_POST(self) -> None:  # noqa: N802
            payload = json.loads(self.rfile.read(int(self.headers["Content-Length"])))
            calls.append({"authorization": self.headers.get("Authorization"), "payload": payload, "path": self.path})
            text = payload["messages"][-1]["content"].casefold()
            answer = "one" if "one" in text else "two"
            body = json.dumps(
                {
                    "model": payload["model"],
                    "choices": [{"message": {"content": answer}}],
                    "usage": {"prompt_tokens": 3, "completion_tokens": 1},
                }
            ).encode()
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def log_message(self, _format: str, *_args: object) -> None:
            pass

    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield f"http://127.0.0.1:{server.server_port}/v1", calls
    finally:
        server.shutdown()
        server.server_close()
        thread.join()


def test_two_prompts_by_two_openai_endpoints_produce_verified_paired_matrix(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    opaque_value = "opaque-client-e2e-value"
    monkeypatch.setenv("CLIENT_E2E_KEY", opaque_value)
    prompts = (PromptVariant("baseline", template="{question}"), PromptVariant("structured", template="Answer: {question}"))
    with _openai_server() as (first, first_calls), _openai_server() as (second, second_calls):
        targets = (
            OpenAICompatibleTarget(base_url=first, model="model-one", name="first", api_key_env="CLIENT_E2E_KEY", revision="revision-one"),
            OpenAICompatibleTarget(base_url=second, model="model-two", name="second", api_key_env="CLIENT_E2E_KEY", revision="revision-two"),
        )
        result = run_experiment(_plan(tmp_path, prompts=prompts, targets=targets))

    assert len(result.summary["cells"]) == 4
    assert all(cell["pass"] == 2 and cell["verification"]["valid"] for cell in result.summary["cells"])
    assert len(result.summary["comparisons"]) == 6
    assert all(comparison["cases"] == 2 for comparison in result.summary["comparisons"])
    assert len(first_calls) == len(second_calls) == 4
    assert {call["payload"]["model"] for call in first_calls + second_calls} == {"model-one", "model-two"}
    assert all(call["path"] == "/v1/chat/completions" for call in first_calls + second_calls)
    judge_payloads = [
        row["payload"]
        for path in result.path.glob("cells/*/runs/*/*/requests.jsonl")
        for row in evaluation._jsonl(path)
        if row.get("kind") == "judge"
    ]
    assert all(all(identity not in json.dumps(payload) for identity in ("model-one", "model-two", "revision-one", "revision-two")) for payload in judge_payloads)
    assert all(opaque_value.encode() not in path.read_bytes() for path in result.path.rglob("*") if path.is_file())


def test_openai_retry_preserves_failed_wire_body_and_verifies(tmp_path: Path) -> None:
    failure_body = b'{"error":{"message":"temporary overload"}}'
    calls = 0

    class Handler(BaseHTTPRequestHandler):
        def do_POST(self) -> None:  # noqa: N802
            nonlocal calls
            calls += 1
            payload = json.loads(self.rfile.read(int(self.headers["Content-Length"])))
            if calls == 1:
                body, status = failure_body, 503
            else:
                body = json.dumps(
                    {
                        "model": payload["model"],
                        "choices": [{"message": {"content": "one"}}],
                        "usage": {"prompt_tokens": 1, "completion_tokens": 1},
                    }
                ).encode()
                status = 200
            self.send_response(status)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def log_message(self, _format: str, *_args: object) -> None:
            pass

    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        target = OpenAICompatibleTarget(
            base_url=f"http://127.0.0.1:{server.server_port}/v1",
            model="retry-model",
            name="retry-target",
            revision="revision-one",
        )
        plan = replace(
            _plan(tmp_path, targets=(target,), run=_run_options(retries=1, max_requests=2)),
            dataset=[{"id": "only", "question": "one", "answer": "one"}],
        )
        assert prepare_experiment(plan).summary["maximum_target_attempts"] == 2
        result = run_experiment(plan)
    finally:
        server.shutdown()
        server.server_close()
        thread.join()

    run_dir = result.path / result.summary["cells"][0]["run"]
    raw = json.loads((run_dir / "raw_responses.jsonl").read_text(encoding="utf-8"))
    transport = raw["transport"]
    retry = transport["retry_failures"][0]

    assert calls == 2 and transport["attempts"] == 2
    assert retry["http_status"] == 503 and retry["wire_body_bytes"] == len(failure_body)
    assert base64.b64decode(retry["wire_body_base64"]) == failure_body
    assert verify_behavior_run(run_dir)["valid"] is True
    assert verify_experiment(result.path)["valid"] is True


def test_global_max_cost_blocks_next_cell_and_resume_without_new_request(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("CLIENT_E2E_KEY", "opaque-budget-value")
    prompts = (PromptVariant("first", template="{question}"), PromptVariant("second", template="again {question}"))
    pricing = {
        "currency": "USD",
        "source": "fixed-test-price",
        "effective_at": "2026-01-01T00:00:00Z",
        "input_per_million": 250.0,
        "output_per_million": 250.0,
    }
    with _openai_server() as (endpoint, calls):
        target = OpenAICompatibleTarget(
            base_url=endpoint,
            model="priced-model",
            name="priced",
            api_key_env="CLIENT_E2E_KEY",
            revision="revision-one",
            pricing=pricing,
        )
        plan = replace(
            _plan(tmp_path, prompts=prompts, targets=(target,), run=_run_options(max_cost=0.001)),
            dataset=[{"id": "only", "question": "one", "answer": "one"}],
        )

        with pytest.raises(ProtocolError, match=r"max_cost|budget"):
            run_experiment(plan)
        assert len(calls) == 1
        root = evaluation.resolve_experiment_path(tmp_path / "runs" / "latest")
        assert not (root / "bundle.json").exists()

        with pytest.raises(ProtocolError, match=r"max_cost|budget"):
            run_experiment(plan, resume=True)
        assert len(calls) == 1


def test_interrupted_matrix_resume_skips_completed_cells(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _RESUME_TARGET_CALLS.clear()

    def target(case: dict[str, Any]) -> dict[str, Any]:
        _RESUME_TARGET_CALLS.append(str(case["input"]))
        return {"output": "answer"}

    plan = replace(
        _plan(
            tmp_path,
            prompts=(PromptVariant("first", template="first {question}"), PromptVariant("second", template="second {question}")),
            targets=(CallableTarget("local", target, "local-model", "revision-1"),),
        ),
        dataset=[{"id": "only", "question": "question", "answer": "answer"}],
    )
    canonical_run_cell = evaluation._run_cell
    cells_started = 0

    def interrupt_second(*args: Any, **kwargs: Any) -> Path:
        nonlocal cells_started
        cells_started += 1
        if cells_started == 2:
            raise KeyboardInterrupt
        return canonical_run_cell(*args, **kwargs)

    monkeypatch.setattr(evaluation, "_run_cell", interrupt_second)
    with pytest.raises(KeyboardInterrupt):
        run_experiment(plan)
    monkeypatch.setattr(evaluation, "_run_cell", canonical_run_cell)

    root = evaluation.resolve_experiment_path(tmp_path / "runs" / "latest")
    state = json.loads((root / "experiment.json").read_text(encoding="utf-8"))
    original_run = state["cells"][0]["run"]
    shutil.copytree(root / original_run, root / "attacker-valid-run")
    state["cells"][0]["run"] = "attacker-valid-run"
    evaluation.atomic_json(root / "experiment.json", state)
    calls_before_rejected_resume = list(_RESUME_TARGET_CALLS)
    with pytest.raises(ProtocolError, match="outside its immutable cell directory"):
        run_experiment(plan, resume=True)
    assert _RESUME_TARGET_CALLS == calls_before_rejected_resume
    state["cells"][0]["run"] = original_run
    evaluation.atomic_json(root / "experiment.json", state)

    result = run_experiment(plan, resume=True)

    assert _RESUME_TARGET_CALLS == ["first question", "second question"]
    assert [cell["pass"] for cell in result.summary["cells"]] == [1, 1]
    assert result.verification["valid"] is True


def test_repetitions_are_distinct_verified_cells(tmp_path: Path) -> None:
    plan = replace(
        _plan(tmp_path, run=_run_options(repetitions=2)),
        dataset=[{"id": "only", "question": "one", "answer": "one"}],
    )
    prepared = prepare_experiment(plan)

    assert [cell.repetition for cell in prepared.cells] == [1, 2]
    assert len({cell.cell_id for cell in prepared.cells}) == 2

    result = run_experiment(plan)
    for cell in result.summary["cells"]:
        manifest = json.loads((result.path / cell["run"] / "manifest.json").read_text(encoding="utf-8"))
        assert manifest["parameters"]["repetitions"] == 1
    assert [cell["repetition"] for cell in result.summary["cells"]] == [1, 2]
    assert result.verification["valid"] is True


def test_callable_closure_and_object_state_bind_plan_cell_and_resume(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def make_target(marker: str, *, fail: bool = False) -> Any:
        def target(_case: dict[str, Any]) -> dict[str, Any]:
            if fail:
                raise AssertionError("changed callable must not run during rejected resume")
            return {"output": "answer", "metadata": {"marker": marker}}

        return target

    class StatefulTarget:
        def __init__(self, marker: str) -> None:
            self.marker = marker

        def __call__(self, _case: dict[str, Any]) -> dict[str, Any]:
            return {"output": "answer", "metadata": {"marker": self.marker}}

    prompts = (PromptVariant("first", template="{question}"), PromptVariant("second", template="again {question}"))
    first_callable = make_target("first")
    changed_callable = make_target("changed", fail=True)
    first = replace(
        _plan(tmp_path, prompts=prompts, targets=(CallableTarget("local", first_callable, "local-model", "revision-1"),)),
        dataset=[{"id": "only", "question": "question", "answer": "answer"}],
    )
    changed = replace(first, targets=(CallableTarget("local", changed_callable, "local-model", "revision-1"),))
    object_one = replace(first, targets=(CallableTarget("local", StatefulTarget("one"), "local-model", "revision-1"),))
    object_two = replace(first, targets=(CallableTarget("local", StatefulTarget("two"), "local-model", "revision-1"),))

    assert evaluation._plan_snapshot(first) != evaluation._plan_snapshot(changed)
    assert prepare_experiment(first).cells[0].cell_id != prepare_experiment(changed).cells[0].cell_id
    assert evaluation._plan_snapshot(object_one) != evaluation._plan_snapshot(object_two)
    assert prepare_experiment(object_one).cells[0].cell_id != prepare_experiment(object_two).cells[0].cell_id

    canonical_run_cell = evaluation._run_cell
    cells_started = 0

    def interrupt_second(*args: Any, **kwargs: Any) -> Path:
        nonlocal cells_started
        cells_started += 1
        if cells_started == 2:
            raise KeyboardInterrupt
        return canonical_run_cell(*args, **kwargs)

    monkeypatch.setattr(evaluation, "_run_cell", interrupt_second)
    with pytest.raises(KeyboardInterrupt):
        run_experiment(first)
    monkeypatch.setattr(evaluation, "_run_cell", canonical_run_cell)

    with pytest.raises(ProtocolError, match="resume plan differs"):
        run_experiment(changed, resume=True)
