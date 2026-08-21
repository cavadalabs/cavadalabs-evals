# Dataset, target, and evaluator callables

Everything is defined in `custom.py`; Cavada itself is unchanged.

```bash
cavada-eval plan eval.toml
cavada-eval run eval.toml
cavada-eval verify runs/latest
```

Expected: two factory cases and one verified cell. The local module is trusted
code and is not sandboxed.
