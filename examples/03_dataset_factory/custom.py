from cavada_eval.evaluators import EvaluationResult


def support_dataset():
    yield {"id": "ticket-001", "question": "What is the support code?", "answer": "SUPPORT-001"}
    yield {"id": "ticket-002", "question": "What is the billing code?", "answer": "BILLING-002"}


def local_target(request):
    answers = {
        "What is the support code?": "SUPPORT-001",
        "What is the billing code?": "BILLING-002",
    }
    return {"output": answers[request["input"]], "usage": {"prompt_tokens": 8, "completion_tokens": 2}}


def support_evaluator(case, response):
    expected = case.expected["answer"]
    passed = response["answer"] == expected
    return EvaluationResult(passed, float(passed), {"exact": float(passed)}, "support code matched" if passed else "support code differed")
