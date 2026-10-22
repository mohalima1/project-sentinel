# Contributing

Read AGENTS.md, PROJECT_SPEC.md, and PROGRESS.md. Use the locked environment and
setup commands in README.md. Run pytest, Ruff, the frontend build, and browser smoke
checks before proposing a change. Document actual results and unverified behavior.
Use synthetic fixtures in tests and label them accordingly. Never commit real
inventory, logs, databases, credentials, VM images, or local exports.

Keep collection, ingestion, detection, matching, privileged controls, and presentation
separate. Missing data must not be described as a clean security assessment. Add
evidence and official references before claiming detection or CVE applicability.
