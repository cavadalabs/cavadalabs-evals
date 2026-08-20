# Multimodal suites

A case input is text or an ordered array of `text`, `image`, `audio`, `video`,
`document`, `tool_call`, and `tool_result` parts. Media uses local relative paths,
declared MIME, SHA-256 for official runs, license, origin, and personal-data
classification. Generic JSON adapters receive base64 content and metadata.
OpenAI-compatible adapters currently map text, images, and input audio; other
modalities must use an adapter that explicitly supports them.

Built-in deterministic primitives cover content integrity, image dimensions,
WAV metadata, transcript WER/CER, structured text, retrieval, and tool calls.
OCR, VQA, image-generation quality, speaker similarity, diarization, advanced
video, perceptual, and safety classifiers require pinned optional adapters and
calibrated datasets. Their absence must be reported, never replaced with a fake
score. C2PA marker detection is only discovery; cryptographic C2PA verification
requires an approved verifier and does not prove that content is truthful.

Original assets and failure previews are restricted. Public reports may contain
only separately sanitized derivatives. Rich media parsers and custom metrics
must execute in a sandbox with CPU, memory, time, filesystem, and network limits.

For real OCR evaluation, use the pinned, non-redistributing
[OCRBench v2 external adapter](OCRBENCH_V2.md). Its research-only dataset is not
included and its upstream scores remain separate from CavadaLabs official claims.
