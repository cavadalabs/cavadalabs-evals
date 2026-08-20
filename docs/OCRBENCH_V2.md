# OCRBench v2 external adapter

OCRBench v2 is supported as pinned upstream evidence, not as a bundled CavadaLabs
suite. Its dataset is research-only and non-commercial, so this repository does
not download, copy, relicense, or redistribute it. Obtain permission separately
before any use outside those terms.

The adapter is pinned to upstream commit
`cbf4b64d2981dc5f9009df4bb7f5581f84381ad4`. Run inference and scoring with
the upstream repository, preserve the downloaded dataset archive, and record the
exact commands. Then convert the scored JSON:

```bash
python scripts/convert_ocrbench_v2.py \
  OCRBench_v2/res_folder/model.json external.json \
  --dataset-sha256 SHA256_OF_ORIGINAL_DATASET_ARCHIVE \
  --evaluator-sha256 SHA256_OF_PINNED_EVALUATOR_ARCHIVE \
  --invocation 'python eval.py --input_path predictions.json --output_path results.json'

cavada-eval import-external external.json runs/imports/ocrbench-v2-model
```

Create the evaluator hash reproducibly from a clean upstream checkout:

```bash
git archive --format=tar cbf4b64d2981dc5f9009df4bb7f5581f84381ad4 \
  OCRBench_v2/eval_scripts | shasum -a 256
```

Each valid upstream result is marked `scored`, not `pass` or `fail`, because
OCRBench v2 uses continuous task-specific scores without one universal passing
threshold. Ignored upstream cases remain `skipped`. The imported evidence keeps
the upstream methodology and license limitations and is not, by itself, a
CavadaLabs official result or legal certification.
