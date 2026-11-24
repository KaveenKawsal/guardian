"""Guardian's full-screen workspace in the current terminal."""

import asyncio
from contextlib import redirect_stderr, redirect_stdout
from io import StringIO
from typing import TYPE_CHECKING, Any

from prompt_toolkit.application import Application
from prompt_toolkit.document import Document
from prompt_toolkit.filters import Condition
from prompt_toolkit.formatted_text import StyleAndTextTuples
from prompt_toolkit.history import FileHistory
from prompt_toolkit.key_binding import KeyBindings, KeyPressEvent
from prompt_toolkit.layout import (
    ConditionalContainer, Dimension, Float, FloatContainer, HSplit, Layout, VSplit, Window,
    WindowAlign,
)
from prompt_toolkit.layout.controls import FormattedTextControl
from prompt_toolkit.layout.menus import CompletionsMenu
from prompt_toolkit.mouse_events import MouseEvent, MouseEventType
from prompt_toolkit.styles import Style
from prompt_toolkit.widgets import TextArea
from rich.text import Text

from guardian.cli.shell_input import ShellCompleter

if TYPE_CHECKING:
    from guardian.cli.shell import GuardianShell


STYLE = Style.from_dict({
    "": "bg:#14191e #dbe5ee",
    "header": "#71e3c1 bold",
    "brand": "#71e3c1 bold",
    "muted": "#a2b4c8",
    "button": "bg:#26343c #e6f5ff bold",
    "composer": "bg:#202b33 #eef8ff",
    "sidebar": "bg:#1b242b #cfdae4",
    "footer": "#a2b4c8",
})


class Workspace:
    def __init__(self, shell: "GuardianShell", commands: dict[str, str], **io: Any) -> None:
        self.shell = shell
        self.pending = ""
        self.started = False
        session = Condition(lambda: self.started)
        home_screen = ~session
        self.transcript = TextArea(read_only=True, scrollbar=True, focus_on_click=True)
        self.composer = TextArea(
            height=Dimension(min=2, preferred=3, max=3),
            prompt=" > ",
            style="class:composer",
            multiline=True,
            history=FileHistory(str(shell.history_path)),
            completer=ShellCompleter(commands),
            complete_while_typing=True,
        )
        home = Window(FormattedTextControl([
            ("class:brand", "G U A R D I A N\n"),
            ("class:muted", "Scan a repository or ask about its findings."),
        ]), height=3, align=WindowAlign.CENTER)
        content = HSplit([
            ConditionalContainer(Window(), home_screen),
            ConditionalContainer(home, home_screen),
            ConditionalContainer(self.transcript, session),
            self.composer,
            Window(FormattedTextControl(self.actions), height=2, wrap_lines=True),
            ConditionalContainer(Window(FormattedTextControl(self.footer), height=1,
                                        style="class:footer"), session),
            ConditionalContainer(Window(), home_screen),
        ], width=lambda: Dimension(weight=1) if self.started else Dimension(preferred=70, max=70))
        sidebar = ConditionalContainer(
            Window(FormattedTextControl(self.context), width=31, wrap_lines=True,
                   style="class:sidebar"),
            Condition(lambda: self.started and self.app.output.get_size().columns >= 94),
        )
        root = HSplit([
            ConditionalContainer(Window(FormattedTextControl(self.header), height=2,
                                        style="class:header"), session),
            VSplit([
                Window(width=lambda: Dimension.exact(2) if self.started else Dimension(weight=1)),
                content,
                Window(width=lambda: Dimension.exact(2) if self.started else Dimension(weight=1)),
                sidebar,
            ]),
        ])
        surface = FloatContainer(root, floats=[
            Float(xcursor=True, ycursor=True, content=CompletionsMenu(max_height=10)),
        ])
        self.app: Application[None] = Application(
            layout=Layout(surface, focused_element=self.composer),
            key_bindings=self.bindings(), style=STYLE, full_screen=True,
            mouse_support=True, **io,
        )

    def header(self) -> str:
        return "  GUARDIAN   /   Session"

    def context(self) -> StyleAndTextTuples:
        context = self.shell.toolbar().split(" | Enter send", 1)[0].strip()
        return [
            ("class:brand", "\n  Workspace\n\n"),
            ("", "\n".join(f"  {part}" for part in context.split(" | "))),
            ("class:muted", "\n\n  Ctrl+P  Commands\n  F6      Switch focus"),
        ]

    def footer(self) -> str:
        if self.pending:
            return "  Working… results will appear here."
        return "  Enter send   ·   Alt+Enter newline   ·   Ctrl+P commands   ·   Ctrl+Q exit"

    def actions(self) -> StyleAndTextTuples:
        fragments: StyleAndTextTuples = []
        for label, command in [
            ("Scan", "/scan "), ("Findings", "/findings"), ("History", "/history"),
            ("Commands", "/help"), ("Send", None), ("Exit", "/exit"),
        ]:
            def click(event: MouseEvent, value: str | None = command) -> None:
                if event.event_type == MouseEventType.MOUSE_UP:
                    if value == "/scan " and not self.pending:
                        self.composer.buffer.reset(Document(value, len(value)))
                        self.app.layout.focus(self.composer)
                    else:
                        self.submit(value)

            fragments.extend([("class:button", f" {label} ", click), ("", "  ")])
        return fragments

    def bindings(self) -> KeyBindings:
        keys = KeyBindings()

        @keys.add("c-m", filter=Condition(lambda: self.app.layout.has_focus(self.composer)))
        def send(event: KeyPressEvent) -> None:
            buffer = event.current_buffer
            state = buffer.complete_state
            choice = state.current_completion if state is not None else None
            if choice is not None:
                buffer.cancel_completion()
                buffer.apply_completion(choice)
            else:
                self.submit()

        @keys.add("c-p", eager=True)
        @keys.add("c-k", eager=True)
        def palette(event: KeyPressEvent) -> None:
            event.app.layout.focus(self.composer)
            buffer = self.composer.buffer
            if not buffer.text.strip():
                buffer.reset(Document("/", 1))
            buffer.start_completion(select_first=False)

        @keys.add("c-q", eager=True)
        def quit_app(event: KeyPressEvent) -> None:
            self.submit("/exit")

        @keys.add("escape", "enter")
        def newline(event: KeyPressEvent) -> None:
            if event.app.layout.has_focus(self.composer):
                self.composer.buffer.insert_text("\n")

        @keys.add("f6")
        def switch_panel(event: KeyPressEvent) -> None:
            if self.transcript.text and event.app.layout.has_focus(self.composer):
                event.app.layout.focus(self.transcript)
            else:
                event.app.layout.focus(self.composer)

        return keys

    def append(self, text: str) -> None:
        # Strip terminal controls before placing command output in the viewport.
        clean = Text.from_ansi(text).plain
        clean = "".join(char for char in clean if char in "\n\t" or char.isprintable())
        text = (self.transcript.text + clean)[-120_000:]
        self.transcript.buffer.set_document(Document(text, len(text)), bypass_readonly=True)

    def submit(self, command: str | None = None) -> None:
        if self.pending:
            return
        text = (self.composer.text if command is None else command).strip()
        if not text:
            return
        if text.lower() in {"/exit", "/quit"}:
            self.app.exit()
            return
        if command is None:
            self.composer.buffer.append_to_history()
            self.composer.buffer.reset()
        self.pending = text
        self.started = True
        self.append(f"\n  You\n  {text}\n\n")
        self.app.layout.focus(self.composer)
        self.app.create_background_task(self.execute(text))

    def dispatch(self, text: str) -> tuple[bool, str]:
        # An in-memory stream has no console handle. Rich therefore cannot use
        # the Windows console renderer, and ordinary print/echo is captured too.
        # prompt_toolkit's Output already owns its original terminal stream.
        stream = StringIO()
        with redirect_stdout(stream), redirect_stderr(stream):
            keep_open = self.shell.dispatch(text)
        return keep_open, stream.getvalue()

    async def execute(self, text: str) -> None:
        try:
            keep_open, output = await asyncio.to_thread(self.dispatch, text)
            if text.lower() == "/clear":
                self.transcript.text = ""
            if output:
                self.append(output)
            if not keep_open:
                self.app.exit()
        finally:
            self.pending = ""
            self.app.invalidate()

    def run(self) -> None:
        self.app.run()
