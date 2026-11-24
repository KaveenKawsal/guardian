"""Tool-calling loop that answers questions about a scan with the user's LLM provider.

The loop is deliberately small: the model may call the read-only tools of
:class:`~guardian.assistant.tools.ScanToolbox` for at most ``max_rounds`` rounds, then it must
answer. Tool output is passed back as ``ToolMessage`` data only; nothing the model or the
scanned repository says is ever executed.
"""

import time
from collections import deque
from collections.abc import Callable
from dataclasses import dataclass, field
from typing import Any

from langchain_core.language_models import BaseChatModel
from langchain_core.messages import (
    AIMessage,
    AIMessageChunk,
    BaseMessage,
    HumanMessage,
    SystemMessage,
    ToolMessage,
)
from langchain_core.runnables import Runnable
from pydantic import SecretStr

from guardian.assistant.prompts import (
    FINAL_ANSWER_NUDGE,
    NO_PROVIDER_MESSAGE,
    NO_SCAN_MESSAGE,
    SYSTEM_PROMPT,
    suggest_commands,
)
from guardian.assistant.tools import TOOL_SPECS, ScanToolbox
from guardian.core.config import GuardianSettings
from guardian.core.exceptions import ConfigurationError
from guardian.llm.providers import build_chat_model, resolve_provider, safe_error_message

MAX_TOOL_ROUNDS = 6
MAX_CALLS_PER_ROUND = 8
DEFAULT_TIMEOUT_SECONDS = 180.0
DEFAULT_MEMORY_TURNS = 6
MAX_REMEMBERED_CHARS = 4000
HTTP_NOT_FOUND = 404
HTTP_TOO_MANY_REQUESTS = 429

TokenSink = Callable[[str], None]


@dataclass
class AssistantReply:
    text: str
    streamed: bool = False
    """True when ``text`` was already delivered through the token callback."""
    error: str | None = None
    tool_calls: list[str] = field(default_factory=list)
    rounds: int = 0


class Conversation:
    """The last ``max_turns`` question/answer pairs of one shell session."""

    def __init__(self, max_turns: int = DEFAULT_MEMORY_TURNS) -> None:
        self._turns: deque[tuple[str, str]] = deque(maxlen=max_turns)

    def __len__(self) -> int:
        return len(self._turns)

    def add(self, question: str, answer: str) -> None:
        self._turns.append((question[:MAX_REMEMBERED_CHARS], answer[:MAX_REMEMBERED_CHARS]))

    def clear(self) -> None:
        self._turns.clear()

    def messages(self) -> list[BaseMessage]:
        history: list[BaseMessage] = []
        for question, answer in self._turns:
            history.extend((HumanMessage(question), AIMessage(answer)))
        return history


def describe_provider_error(exc: BaseException, secret: SecretStr | None = None) -> str:
    """One key-free line describing a provider failure, with what to do next."""
    reason = safe_error_message(exc, secret)
    status = getattr(exc, "status_code", None) or getattr(exc, "code", None)
    lowered = reason.lower()
    if reason.startswith("API key rejected"):
        return f"{reason}. Fix the key in your .env, then run `guardian ai test`."
    if status == HTTP_TOO_MANY_REQUESTS or any(
        m in lowered for m in ("rate limit", "rate_limit", "resource_exhausted", "quota")
    ):
        return "The provider rate-limited the request. Wait a moment, or switch with /model."
    if status == HTTP_NOT_FOUND or any(
        m in lowered for m in ("model_not_found", "not found", "does not exist", "decommission")
    ):
        return "The configured model is not available. Pick another with /model <provider> <model>."
    return f"AI request failed ({reason}). Check with `guardian ai test` or switch with /model."


class Assistant:
    def __init__(  # noqa: PLR0913 - every collaborator is injectable for tests
        self,
        settings: GuardianSettings,
        *,
        chat_model: BaseChatModel | None = None,
        conversation: Conversation | None = None,
        max_rounds: int = MAX_TOOL_ROUNDS,
        timeout_seconds: float = DEFAULT_TIMEOUT_SECONDS,
        clock: Callable[[], float] = time.monotonic,
    ) -> None:
        self.settings = settings
        self.chat_model = chat_model
        self.conversation = conversation or Conversation()
        self.max_rounds = max_rounds
        self.timeout_seconds = timeout_seconds
        self.clock = clock

    def ask(
        self, question: str, toolbox: ScanToolbox | None, on_token: TokenSink | None = None
    ) -> AssistantReply:
        if toolbox is None:
            return AssistantReply(NO_SCAN_MESSAGE)
        secret: SecretStr | None = None
        model = self.chat_model
        if model is None:
            try:
                config = resolve_provider(self.settings)
            except ConfigurationError as exc:
                return _offline(str(exc), question)
            if config is None:
                return _offline(NO_PROVIDER_MESSAGE, question)
            secret = config.api_key
            model = build_chat_model(config, self.settings)
        try:
            reply = self._run(model, question, toolbox, on_token)
        except Exception as exc:  # noqa: BLE001 - provider SDKs raise many unrelated types
            message = describe_provider_error(exc, secret)
            return AssistantReply(message, error=message)
        if reply.error is None:
            self.conversation.add(question, reply.text)
        return reply

    def _run(
        self,
        model: BaseChatModel,
        question: str,
        toolbox: ScanToolbox,
        on_token: TokenSink | None,
    ) -> AssistantReply:
        deadline = self.clock() + self.timeout_seconds
        bound = model.bind_tools(TOOL_SPECS)
        messages: list[BaseMessage] = [
            SystemMessage(SYSTEM_PROMPT),
            *self.conversation.messages(),
            HumanMessage(question),
        ]
        reply = AssistantReply("")
        for _ in range(self.max_rounds):
            if self.clock() > deadline:
                return _timed_out(reply)
            message, streamed = _complete(bound, messages, on_token)
            messages.append(message)
            if not message.tool_calls:
                reply.text, reply.streamed = message.text, streamed
                return reply
            reply.rounds += 1
            for call in message.tool_calls[:MAX_CALLS_PER_ROUND]:
                reply.tool_calls.append(call["name"])
                payload = toolbox.call(call["name"], call.get("args"))
                content = toolbox.serialize(
                    {"tool": call["name"], "untrusted_repository_data": payload}
                )
                messages.append(ToolMessage(content, tool_call_id=call.get("id") or call["name"]))
            messages.extend(
                ToolMessage(
                    '{"error": "too many tool calls in one round"}',
                    tool_call_id=call.get("id") or call["name"],
                )
                for call in message.tool_calls[MAX_CALLS_PER_ROUND:]
            )

        if self.clock() > deadline:
            return _timed_out(reply)
        # Out of tool rounds: one last call without tools forces an answer.
        message, streamed = _complete(
            model, [*messages, HumanMessage(FINAL_ANSWER_NUDGE)], on_token
        )
        if message.tool_calls or not message.text.strip():
            reply.text = (
                f"Stopped after {self.max_rounds} tool rounds without a final answer. "
                "Try a narrower question."
            )
            reply.error = "max_rounds"
            return reply
        reply.text, reply.streamed = message.text, streamed
        return reply


def _complete(
    model: Runnable[Any, Any], messages: list[BaseMessage], on_token: TokenSink | None
) -> tuple[AIMessage, bool]:
    """One model turn, streamed through ``on_token`` when given. Returns (message, streamed)."""
    if on_token is None:
        result = model.invoke(messages)
        return _as_message(result), False
    merged: AIMessageChunk | None = None
    whole: AIMessage | None = None
    emitted = False
    for chunk in model.stream(messages):
        if isinstance(chunk, AIMessageChunk):
            merged = chunk if merged is None else merged + chunk
        elif isinstance(chunk, AIMessage):
            whole = chunk  # models without native streaming yield one complete message
        else:
            continue
        text = chunk.text
        if text:
            on_token(text)
            emitted = True
    if merged is None:
        return whole or AIMessage(""), emitted
    message = AIMessage(
        content=merged.content,
        tool_calls=merged.tool_calls,
        invalid_tool_calls=merged.invalid_tool_calls,
        id=merged.id,
    )
    return message, emitted


def _as_message(result: object) -> AIMessage:
    if isinstance(result, AIMessage):
        return result
    return AIMessage(str(result))


def _timed_out(reply: AssistantReply) -> AssistantReply:
    reply.text = "The assistant ran out of time. Try a narrower question."
    reply.error = "timeout"
    return reply


def _offline(message: str, question: str) -> AssistantReply:
    hints = ", ".join(suggest_commands(question))
    return AssistantReply(f"{message}\nMeanwhile, try: {hints}", error="no_provider")
