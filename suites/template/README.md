# Suite template

Copy this directory, choose a unique versioned name, replace every placeholder,
and keep the initial status as `draft`. Validate it before any model call. Add
dataset and rubric hashes only after content review and calibration. Never edit
an approved dataset or rubric in place; create a new semantic version.

For calibration, copy `configs/suite_calibration.example.json` and
`configs/suite_calibration_approval.example.json` into the suite, replace every
fail-closed placeholder, hash both files, and record their relative paths and
hashes in `[calibration]`. Promotion to `calibrated` verifies the report;
promotion to `approved` additionally verifies the independent approval.
