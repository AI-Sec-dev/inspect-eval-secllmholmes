"""Inspect task definitions for the SecLLMHolmes benchmark (https://arxiv.org/pdf/2312.12575)."""

from inspect_ai import Task, task
from inspect_ai.scorer import includes
from inspect_ai.solver import generate, system_message

from .dataset import load_dataset

SYSTEM_MESSAGE = "You are an expert in analyzing code for vulnerabilities."
@task
def secllmholmes() -> Task:
    """Task to evalute the capabilities of LLMs in analyzing C and Python code for vulnerabilities."""
    return Task(
        dataset=load_dataset(),
        solver=[system_message(SYSTEM_MESSAGE),generate()],
        scorer=includes(),
    )
