# Contributing to Sentinel-AI

Start with a small, reproducible issue or a focused pull request. Describe the
current behavior, expected behavior, Python/OS versions and a minimal example.
Remove secrets, real scan targets and private telemetry from examples.

## Local development

Python 3.10+ can run the scanner and its tests without installing the full
monitoring stack:

```sh
python -m unittest -v test_scanner.py test_native_features.py
python -m sentinel scan 127.0.0.1 -p 22,80,443
```

The loopback tests create local listeners and need permission to connect to
localhost. They do not require an AI key or contact an AI provider. To work on
monitoring, install the package in a virtual environment with `python -m pip
install -e .`, then run `python -m unittest -v test_sentinel.py`.

Keep measured results separate from guesses and AI text. Cover changes to
network states, parsing or AI data sharing with targeted tests. Explain what
you tested and any limitations in the pull request. Never add API keys or
private scan reports to a commit. Scan only authorized systems.
