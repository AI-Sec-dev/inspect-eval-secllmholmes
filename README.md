# SecLLMHolmes Benchmark

An [Inspect AI](https://inspect.aisi.org.uk/) implementation of the vulnerability
identification task from [SecLLMHolmes](https://arxiv.org/abs/2312.12575).

The evaluation uses 228 C and Python code scenarios spanning hand-crafted,
augmented, and real-world examples. The model identifies a CWE or CVE identifier
for vulnerable code, or returns `NONE` for patched code. Responses should use
JSON without Markdown, for example `{"answer":"CWE-79"}` or `{"answer":"NONE"}`.

The current task uses Inspect's `includes()` scorer to check whether the response
contains the expected identifier or `NONE`. It does not validate the JSON format
or assess the model's reasoning, and does not reproduce all investigative
dimensions of the original benchmark.

Challenge files are bundled in `src/secllmholmes/challenges/`. If the selected
challenge set is incomplete, the loader downloads a pinned upstream archive,
verifies its SHA-256 checksum, and copies missing files while preserving existing
files. Each dataset load generates `src/secllmholmes/generated/challenges.csv`
from the challenge files. Sample IDs are paths relative to the challenges directory.

## Installation

Python 3.11 or newer is required. Clone the repository and install the project
with [uv](https://docs.astral.sh/uv/):

```bash
git clone https://github.com/AI-Sec-dev/inspect-eval-secllmholmes.git
cd inspect-eval-secllmholmes
uv sync
```

## Usage

Set the credentials required by your model provider, then run:

```bash
uv run inspect eval secllmholmes/secllmholmes --model <provider/model>

# Limit the evaluation to ten samples
uv run inspect eval secllmholmes/secllmholmes --model <provider/model> --limit 10

# Evaluate a specific sample
uv run inspect eval secllmholmes/secllmholmes --model <provider/model> --sample-id hand-crafted/dataset/CWE-79/1.py
```

For example, run a smoke test with a mock model without model API credentials:

```bash
uv run inspect eval secllmholmes/secllmholmes --model mockllm/model --limit 10
```

Mock-model results check execution only; they do not measure model capability.
Inspect saves evaluation logs under `logs/` by default. View them with:

```bash
uv run inspect view
```

## Development

```bash
uv sync
uv run pytest tests/test_secllmholmes.py
uv run ruff check
uv run ruff format --check
```

The SecLLMHolmes tests cover sample conversion, challenge selection, CSV
generation, bundled dataset loading, download handling, and correct and incorrect
answers through the real solver and scorer with a mock model. Downloads are
mocked, and generated datasets and evaluation logs use temporary directories.

## Citation

If you use this evaluation, cite the original
[SecLLMHolmes paper](https://arxiv.org/abs/2312.12575):

```bibtex
@article{ullah2023llms,
  title = {{LLMs} Cannot Reliably Identify and Reason About Security Vulnerabilities (Yet?): A Comprehensive Evaluation, Framework, and Benchmarks},
  author = {Ullah, Saad and Han, Mingji and Pujar, Saurabh and Pearce, Hammond and Coskun, Ayse and Stringhini, Gianluca},
  year = {2023},
  eprint = {2312.12575},
  archiveprefix = {arXiv},
  primaryclass = {cs.CR}
}
```

## License

This implementation is licensed under the [MIT License](LICENSE). The bundled
challenge files may be subject to separate
[upstream terms](https://github.com/ai4cloudops/SecLLMHolmes).
