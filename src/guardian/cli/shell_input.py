"""Line sources for the interactive shell: prompt_toolkit, plain ``input()`` or a script.

Every reader raises ``EOFError`` to end the session (Ctrl+D) and ``KeyboardInterrupt`` to
cancel the current line (Ctrl+C).
"""

from collections.abc import Callable, Iterable, Iterator, Mapping
from pathlib import Path
from typing import Any, Protocol

from prompt_toolkit import PromptSession
from prompt_toolkit.completion import CompleteEvent, Completer, Completion, PathCompleter
from prompt_toolkit.document import Document
from prompt_toolkit.history import FileHistory

PROMPT = "guardian> "
_PATH_COMMANDS = ("/scan ",)


class LineReader(Protocol):
    def read(self, prompt: str) -> str: ...


class ScriptReader:
    """Lines from an iterable (tests, piped input); ``EOFError`` when exhausted."""

    def __init__(self, lines: Iterable[str | BaseException]) -> None:
        self._lines: Iterator[str | BaseException] = iter(lines)

    def read(self, prompt: str) -> str:  # noqa: ARG002 - nothing is shown
        try:
            line = next(self._lines)
        except StopIteration:
            raise EOFError from None
        if isinstance(line, BaseException):
            raise line
        return line


class PlainReader:
    """``input()`` fallback when stdin/stdout are not terminals."""

    def read(self, prompt: str) -> str:
        return input(prompt)


class ShellCompleter(Completer):
    """Slash commands at the start of the line; directories after ``/scan``."""

    def __init__(self, commands: Mapping[str, str]) -> None:
        self.commands = commands
        self.paths = PathCompleter(only_directories=True, expanduser=True)

    def get_completions(
        self, document: Document, complete_event: CompleteEvent
    ) -> Iterator[Completion]:
        text = document.text_before_cursor
        for prefix in _PATH_COMMANDS:
            if text.startswith(prefix):
                rest = text[len(prefix) :].lstrip()
                yield from self.paths.get_completions(Document(rest, len(rest)), complete_event)
                return
        if not text.startswith("/") or " " in text:
            return
        for name, summary in self.commands.items():
            if name.startswith(text):
                yield Completion(name, start_position=-len(text), display_meta=summary)


class PromptReader:
    """prompt_toolkit session with persistent history, completion and a bottom toolbar."""

    def __init__(
        self,
        history_path: Path,
        commands: Mapping[str, str],
        toolbar: Callable[[], str],
        **session_options: Any,  # noqa: ANN401 - tests pass input=/output=
    ) -> None:
        history_path.parent.mkdir(parents=True, exist_ok=True)
        self.session: PromptSession[str] = PromptSession(
            history=FileHistory(str(history_path)),
            completer=ShellCompleter(commands),
            complete_while_typing=True,
            bottom_toolbar=toolbar,
            **session_options,
        )

    def read(self, prompt: str) -> str:
        return self.session.prompt(prompt)
