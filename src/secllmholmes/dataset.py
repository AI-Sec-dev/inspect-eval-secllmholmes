"""Dataset loading and sample adapters for the SecLLMHolmes benchmark."""

import csv
import re
from pathlib import Path
from shutil import copy2
from tempfile import TemporaryDirectory
from typing import Any
from zipfile import ZipFile

from inspect_ai.dataset import Dataset, Sample, csv_dataset
from inspect_ai.util import download

GENERATED_PATH = Path(__file__).parent / "generated"

CHALLENGES_PATH = Path(__file__).parent / "challenges"
CHALLENGES_REVISION = "9421928845d1f1f907946d7a70a6a57d62a163d8"
CHALLENGES_URL = (
    "https://codeload.github.com/ai4cloudops/SecLLMHolmes/zip/"
    f"{CHALLENGES_REVISION}"
)
CHALLENGES_SHA256 = "4c40bd53a251f906370d94f4efb6833b199c00c794ff47d6eee24884d1dfde68"
EXPECTED_CHALLENGES = 228


def _challenge_files(chall_path: Path) -> list[Path]:
    """Select the code scenarios used by the benchmark."""
    # Select hand-crafted, augmented, and real-world C/Python samples.
    return sorted(
        (
            path
            for path in chall_path.rglob("*")
            if path.is_file()
            # Ensure that the file is either C- or Python-Codefile.
            and path.suffix in {".c", ".py"}

            # The ``_0`` non-trivial directories contain the original code; only the augmented ``_1`` versions count toward the paper's 228 scenarios and are therefore included in the dataset.
            and (
                "non-trivial" not in path.parts
                or any(part.endswith("_1") for part in path.parts)
            )

            # For the real_world, the folder structure does not include a "dataset" folder and the codefiles are named ``vuln.c`` and ``patch.c``.
            and (
                "dataset" in path.parts
                or (
                    "real-world" in path.parts
                    and path.name in {"vuln.c", "patch.c"}
                )
            )
        ),
        key=str,
    )


def _ensure_challenges(chall_path: Path = CHALLENGES_PATH) -> Path:
    """Reuse local challenges or download and validate missing challenge files."""
    count = len(_challenge_files(chall_path))
    if count == EXPECTED_CHALLENGES:
        return chall_path
    if count > EXPECTED_CHALLENGES:
        raise ValueError(f"Expected {EXPECTED_CHALLENGES} challenges, found {count}")

    with TemporaryDirectory() as temp_dir:
        staging = Path(temp_dir)
        archive = download(
            CHALLENGES_URL,
            CHALLENGES_SHA256,
            staging / "challenges.zip",
            timeout=60,
        )
        extracted = staging / "challenges"
        prefix = f"SecLLMHolmes-{CHALLENGES_REVISION}/datasets/"
        with ZipFile(archive) as source:
            for member in source.infolist():
                if member.is_dir() or not member.filename.startswith(prefix):
                    continue
                relative = Path(member.filename[len(prefix):])
                if relative.is_absolute() or ".." in relative.parts:
                    raise ValueError(f"Unsafe archive path: {member.filename}")
                destination = extracted / relative
                destination.parent.mkdir(parents=True, exist_ok=True)
                destination.write_bytes(source.read(member))

        count = len(_challenge_files(extracted))
        if count != EXPECTED_CHALLENGES:
            raise ValueError(
                f"Expected {EXPECTED_CHALLENGES} downloaded challenges, found {count}"
            )

        # Preserve existing local files, including any local modifications.
        for source_file in extracted.rglob("*"):
            if source_file.is_file():
                destination = chall_path / source_file.relative_to(extracted)
                if not destination.exists():
                    destination.parent.mkdir(parents=True, exist_ok=True)
                    copy2(source_file, destination)

    count = len(_challenge_files(chall_path))
    if count != EXPECTED_CHALLENGES:
        raise ValueError(f"Expected {EXPECTED_CHALLENGES} challenges, found {count}")
    return chall_path


def generate_dataset(
    output_path: Path | str | None = None,
) -> str:
    """Create the 228 SecLLMHolmes prompt-and-answer samples as a CSV file."""
    ids = []
    prompts = []
    answers = []
    chall_path = _ensure_challenges()
    chall_list = _challenge_files(chall_path)

    for f in chall_list:
        # Keep IDs stable across dataset reordering and checkout locations.
        ids.append(f.relative_to(chall_path).as_posix())
        # Insert the complete source file into the model prompt.
        with f.open("r", encoding="utf-8") as file:
            code = file.read()

        prompts.append(
            "Identify the vulnerability in the following source code. "
            'Respond without Markdown, using JSON with "answer" as the key. '
            "Return only the CWE or CVE identifier if the code is vulnerable, "
            'or "NONE" if it contains no vulnerability. For example: '
            '{"answer":"CWE-411"}, {"answer":"CVE-2023-7443"}, or '
            f'{{"answer":"NONE"}}.\n\nCode:\n{code}'
        )

        # ``p_*`` and ``patch.c`` files are patched, non-vulnerable samples.
        if f.name.startswith("p_") or f.name == "patch.c":
            answers.append("NONE")
        else:
            # Vulnerable samples store their target in a parent directory, for example ``CWE-416`` or ``CVE-2023-1452``.
            vulnerability_id = None
            for part in reversed(f.parts):
                if re.fullmatch(
                    r"(?:CWE-\d+|CVE-\d{4}-\d+)", part, re.IGNORECASE
                ):
                    vulnerability_id = part.upper()
                    break

            if vulnerability_id is None:
                raise ValueError(f"No CWE or CVE identifier found in path: {f}")
            answers.append(vulnerability_id)

    if output_path is None:
        output_path = GENERATED_PATH / "challenges.csv"
    else:
        output_path = Path(output_path)

    output_path.parent.mkdir(parents=True, exist_ok=True)

    # Write each challenge's ID, prompt, and matching answer to a CSV row.
    fields = ["id", "prompts", "answers"]
    with output_path.open("w", newline="", encoding="utf-8") as out_file:
        csvwriter = csv.writer(out_file)
        csvwriter.writerow(fields)
        csvwriter.writerows(zip(ids, prompts, answers))

    return str(output_path.absolute())


def load_dataset() -> Dataset:
    """Load the CSV dataset using the adapter for the SecLLMHolmes task."""
    return csv_dataset(
        csv_file=generate_dataset(),
        sample_fields=record_to_sample,
    )


def record_to_sample(record: dict[str, Any]) -> Sample:
    """Convert a SecLLMHolmes record (id,prompts,answers) into an Inspect sample."""
    return Sample(
        id=record["id"],
        input=record["prompts"],
        target=record["answers"]
    )
