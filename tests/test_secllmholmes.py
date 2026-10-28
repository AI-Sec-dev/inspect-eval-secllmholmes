"""Tests for SecLLMHolmes dataset preparation and evaluation."""

import csv
import json
import re
from pathlib import Path
from unittest.mock import Mock
from zipfile import ZipFile

import pytest
from inspect_ai import eval
from inspect_ai.dataset import MemoryDataset, Sample
from inspect_ai.model import ModelOutput, get_model

from secllmholmes import dataset as dataset_module
from secllmholmes.task import SYSTEM_MESSAGE, secllmholmes


@pytest.fixture(autouse=True)
def isolate_dataset_io(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """Keep generated files temporary and reject unexpected network access."""
    monkeypatch.setattr(dataset_module, "GENERATED_PATH", tmp_path / "generated")
    monkeypatch.setattr(
        dataset_module,
        "download",
        Mock(side_effect=AssertionError("Unexpected download")),
    )


def write_challenge(root: Path, relative: str, code: str = "example code\n") -> Path:
    path = root / relative
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(code, encoding="utf-8")
    return path


@pytest.mark.parametrize("target", ["CWE-79", "CVE-2023-1452", "NONE"])
def test_record_to_sample(target: str) -> None:
    sample = dataset_module.record_to_sample(
        {"id": "dataset/example.py", "prompts": "Analyze this code", "answers": target}
    )
    assert sample.id == "dataset/example.py"
    assert sample.input == "Analyze this code"
    assert sample.target == target


def test_challenge_selection(tmp_path: Path) -> None:
    included = [
        "hand-crafted/dataset/CWE-79/1.py",
        "augmented/trivial/A1/dataset/CWE-79/p_1.py",
        "augmented/non-trivial/A3/A3_1/dataset/CWE-79/1.c",
        "real-world/gpac/CVE-2023-1452/vuln.c",
        "real-world/gpac/CVE-2023-1452/patch.c",
    ]
    excluded = [
        "augmented/non-trivial/A3/A3_0/dataset/CWE-79/1.c",
        "few-shot/examples/CWE-79.py",
        "hand-crafted/dataset/CWE-79/README.md",
        "real-world/gpac/CVE-2023-1452/helper.c",
    ]
    for relative in included + excluded:
        write_challenge(tmp_path, relative)
    assert dataset_module._challenge_files(tmp_path) == sorted(
        (tmp_path / relative for relative in included), key=str
    )


def test_generate_dataset(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    root = tmp_path / "challenges"
    targets = {
        "hand-crafted/dataset/cwe-79/1.py": "CWE-79",
        "hand-crafted/dataset/cwe-79/p_1.py": "NONE",
        "real-world/project/CVE-2023-1452/vuln.c": "CVE-2023-1452",
        "real-world/project/CVE-2023-1452/patch.c": "NONE",
    }
    code = 'print("quoted, code")\n# Unicode: ä\n'
    for relative in targets:
        write_challenge(root, relative, code)
    monkeypatch.setattr(dataset_module, "_ensure_challenges", lambda: root)
    output = tmp_path / "output" / "samples.csv"
    assert dataset_module.generate_dataset(str(output)) == str(output.absolute())
    with output.open(encoding="utf-8", newline="") as file:
        rows = list(csv.DictReader(file))
    assert [row["id"] for row in rows] == sorted(targets)
    assert {row["id"]: row["answers"] for row in rows} == targets
    assert all(row["prompts"].endswith(code) for row in rows)
    assert all('JSON with "answer" as the key' in row["prompts"] for row in rows)


def test_missing_vulnerability_identifier(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    write_challenge(tmp_path, "dataset/unknown/1.py")
    monkeypatch.setattr(dataset_module, "_ensure_challenges", lambda: tmp_path)
    with pytest.raises(ValueError, match="No CWE or CVE identifier"):
        dataset_module.generate_dataset()


def test_load_bundled_dataset() -> None:
    dataset = dataset_module.load_dataset()
    assert len(dataset) == dataset_module.EXPECTED_CHALLENGES
    ids = [sample.id for sample in dataset]
    assert len(set(ids)) == len(ids)
    assert all(
        isinstance(sample_id, str) and not Path(sample_id).is_absolute()
        for sample_id in ids
    )
    for sample in dataset:
        assert isinstance(sample.input, str) and "Code:\n" in sample.input
        assert isinstance(sample.target, str)
        assert re.fullmatch(r"NONE|CWE-\d+|CVE-\d{4}-\d+", sample.target)
    dataset_module.download.assert_not_called()


def test_existing_challenges_do_not_download() -> None:
    assert dataset_module._ensure_challenges() == dataset_module.CHALLENGES_PATH
    dataset_module.download.assert_not_called()


def test_excess_challenges_rejected(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(dataset_module, "EXPECTED_CHALLENGES", 1)
    for name in ("1.py", "2.py"):
        write_challenge(tmp_path, f"dataset/CWE-79/{name}")
    with pytest.raises(ValueError, match="Expected 1 challenges, found 2"):
        dataset_module._ensure_challenges(tmp_path)
    dataset_module.download.assert_not_called()


def test_download_preserves_existing_files(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(dataset_module, "EXPECTED_CHALLENGES", 2)
    root = tmp_path / "challenges"
    existing = write_challenge(root, "dataset/CWE-79/1.py", "local changes")
    archive = tmp_path / "source.zip"
    prefix = f"SecLLMHolmes-{dataset_module.CHALLENGES_REVISION}/datasets/"
    with ZipFile(archive, "w") as source:
        source.writestr(prefix + "dataset/CWE-79/1.py", "upstream version")
        source.writestr(prefix + "dataset/CWE-79/p_1.py", "patched version")
        source.writestr("unrelated.txt", "ignore me")
    download = Mock(return_value=archive)
    monkeypatch.setattr(dataset_module, "download", download)
    assert dataset_module._ensure_challenges(root) == root
    assert existing.read_text(encoding="utf-8") == "local changes"
    assert (root / "dataset/CWE-79/p_1.py").read_text(
        encoding="utf-8"
    ) == "patched version"
    assert not (root / "unrelated.txt").exists()
    download.assert_called_once()
    url, checksum, destination = download.call_args.args
    assert url == dataset_module.CHALLENGES_URL
    assert checksum == dataset_module.CHALLENGES_SHA256
    assert destination.name == "challenges.zip"
    assert download.call_args.kwargs == {"timeout": 60}


@pytest.mark.parametrize(
    ("member", "error"),
    [
        ("../escape.py", "Unsafe archive path"),
        ("/escape.py", "Unsafe archive path"),
        ("README.md", "Expected 228 downloaded challenges, found 0"),
    ],
)
def test_invalid_archive_rejected(
    member: str, error: str, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    archive = tmp_path / "source.zip"
    prefix = f"SecLLMHolmes-{dataset_module.CHALLENGES_REVISION}/datasets/"
    with ZipFile(archive, "w") as source:
        source.writestr(prefix + member, "invalid dataset")
    monkeypatch.setattr(dataset_module, "download", Mock(return_value=archive))
    root = tmp_path / "challenges"
    with pytest.raises(ValueError, match=error):
        dataset_module._ensure_challenges(root)
    assert not root.exists()


@pytest.mark.parametrize("target", ["CWE-79", "CVE-2023-1452", "NONE"])
@pytest.mark.parametrize("correct", [True, False], ids=["correct", "incorrect"])
def test_task_scoring(
    target: str, correct: bool, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Exercise the real task, solver, and scorer without model API calls."""
    monkeypatch.setattr(
        "secllmholmes.task.load_dataset",
        lambda: MemoryDataset(
            [Sample(id="example", input="Analyze this code", target=target)]
        ),
    )
    answer = target if correct else "CWE-99999"
    [log] = eval(
        tasks=secllmholmes(),
        model=get_model(
            "mockllm/model",
            custom_outputs=[
                ModelOutput.from_content(
                    "mockllm/model", json.dumps({"answer": answer})
                )
            ],
        ),
        epochs=1,
        log_dir=str(tmp_path / "logs"),
    )
    assert log.status == "success", log.error
    assert log.results is not None
    assert log.results.scores[0].metrics["accuracy"].value == float(correct)
    assert log.samples is not None and len(log.samples) == 1
    assert any(
        message.role == "system" and message.content == SYSTEM_MESSAGE
        for message in log.samples[0].messages
    )
