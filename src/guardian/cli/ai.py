"""``guardian ai``: check LLM provider keys, list live models and switch provider/model."""

from enum import StrEnum
from typing import Annotated

import typer
from rich.table import Table

from guardian.cli.common import cli_errors, console, err_console
from guardian.core.config import LLM_PROVIDERS, GuardianSettings, LLMProvider, env_files
from guardian.core.exceptions import ConfigurationError
from guardian.llm.catalog import list_models
from guardian.llm.envfile import target_env_file, update_env_file
from guardian.llm.keys import (
    MAX_BACKUP_KEYS,
    KeySettings,
    backup_env_var,
    key_pool_entries,
    load_key_settings,
    requests_per_minute,
    tokens_per_minute,
)
from guardian.llm.providers import (
    KEY_ENV_VARS,
    KEY_URLS,
    MODEL_ENV_VARS,
    PROVIDER_LABELS,
    LLMProviderError,
    active_provider,
    api_key_for,
    check_provider,
    configured_model,
    mask_secret,
    require_provider,
)

ai_app = typer.Typer(
    name="ai",
    help="Configure and check the LLM providers used for AI investigation.",
    no_args_is_help=True,
    pretty_exceptions_show_locals=False,  # never dump settings (API keys) into tracebacks
)


class Provider(StrEnum):
    groq = "groq"
    google = "google"


def load_settings() -> GuardianSettings:
    """Settings from the env files as they are *now* (home/cwd resolved at call time)."""
    return GuardianSettings(_env_file=env_files())


def _literal(value: Provider) -> LLMProvider:
    return "groq" if value is Provider.groq else "google"


def _provider(value: Provider | None) -> LLMProvider | None:
    return None if value is None else _literal(value)


ProviderOption = Annotated[
    Provider | None, typer.Option("--provider", "-p", help="Provider (default: active one).")
]


@ai_app.command()
def status() -> None:
    """Show configured providers, masked keys, key pools, pacing and the settings files."""
    with cli_errors():
        settings = load_settings()
        keys = load_key_settings()
    active = active_provider(settings)
    table = Table(title="Guardian LLM providers", title_justify="left")
    table.add_column("Provider")
    table.add_column("API key")
    table.add_column("Keys", justify="right")
    table.add_column("Model", no_wrap=True)
    table.add_column("Active")
    for provider in LLM_PROVIDERS:
        model = configured_model(settings, provider)
        if provider == active and settings.llm_model:
            model = f"{settings.llm_model} (GUARDIAN_LLM_MODEL)"
        key = api_key_for(settings, provider)
        key_text = mask_secret(key)
        pool_size = len(key_pool_entries(settings, provider, keys))
        table.add_row(
            f"{PROVIDER_LABELS[provider]} ({provider})",
            f"[green]{key_text}[/green]" if key else f"[dim]{key_text}[/dim]",
            str(pool_size),
            model,
            "[cyan]*[/cyan]" if provider == active else "",
        )
    console.print(table)
    _print_pools(settings, keys)

    if not settings.ai_enabled:
        console.print("[yellow]AI is disabled (GUARDIAN_AI_ENABLED=false).[/yellow]")
    if active is None:
        console.print(
            "No active provider. Add GROQ_API_KEY / GOOGLE_API_KEY to an env file, then run "
            "[bold]guardian ai use groq|google[/bold]."
        )
    elif api_key_for(settings, active) is None:
        console.print(
            f"[yellow]{PROVIDER_LABELS[active]} is selected but {KEY_ENV_VARS[active]} is not "
            f"set (get one at {KEY_URLS[active]}).[/yellow]"
        )
    console.print("Settings files (later overrides earlier; environment variables win):")
    for path in env_files():
        resolved = path.resolve()
        state = "[green]found[/green]" if resolved.is_file() else "[dim]not found[/dim]"
        console.print(f"  {resolved}  {state}")


def _print_pools(settings: GuardianSettings, keys: KeySettings) -> None:
    """Key pools in rotation order (masked) and the pacing that keeps calls under limits."""
    console.print("Key pools (tried in order; a rate-limited key cools down and the next is used):")
    for provider in LLM_PROVIDERS:
        entries = key_pool_entries(settings, provider, keys)
        listed = ", ".join(f"#{e.index} {e.env_var} {e.masked}" for e in entries) or "none"
        console.print(f"  {PROVIDER_LABELS[provider]}: {listed}", highlight=False)
    console.print(
        "Pacing: "
        + "; ".join(
            f"{PROVIDER_LABELS[p]} {tokens_per_minute(keys, p)} tokens/min, "
            f"{requests_per_minute(keys, p)} requests/min"
            for p in LLM_PROVIDERS
        )
        + f"; longest cool-down wait {keys.llm_max_wait_seconds:g}s",
        highlight=False,
    )
    console.print(
        f"[dim]Backup keys: {backup_env_var('groq', 1)} .. "
        f"{backup_env_var('groq', MAX_BACKUP_KEYS)}"
        f" (same for GOOGLE_API_KEY). Groq limits apply per organization: keys from the same "
        "organization share one limit, only keys from different accounts add capacity.[/dim]"
    )


@ai_app.command()
def models(provider: ProviderOption = None) -> None:
    """List the models the provider currently offers to your key."""
    with cli_errors():
        settings = load_settings()
        config = require_provider(settings, provider=_provider(provider))
    current = configured_model(settings, config.provider)
    try:
        names = list_models(config.provider, config.api_key)
    except LLMProviderError as exc:
        err_console.print(f"[red]error:[/red] {exc}")
        raise typer.Exit(code=1) from None
    table = Table(title=f"{config.label} models", title_justify="left")
    table.add_column("Model")
    table.add_column("Configured")
    for name in names:
        table.add_row(name, "[cyan]*[/cyan]" if name in {current, config.model} else "")
    console.print(table)
    if config.model not in names:
        console.print(
            f"[yellow]Configured model {config.model!r} is not in the list; choose one with "
            f"`guardian ai use {config.provider} --model NAME`.[/yellow]"
        )


@ai_app.command("test")
def check(
    provider: ProviderOption = None,
    model: Annotated[str | None, typer.Option("--model", "-m", help="Model to try.")] = None,
) -> None:
    """Send one tiny prompt to check the key and model work."""
    try:
        result = check_provider(load_settings(), provider=_provider(provider), model=model)
    except (LLMProviderError, ConfigurationError) as exc:
        err_console.print(f"[red]failed:[/red] {exc}")
        raise typer.Exit(code=1) from None
    console.print(
        f"[green]ok[/green] {PROVIDER_LABELS[result.provider]} model {result.model} "
        f"answered in {result.latency_seconds:.2f}s: {result.reply!r}"
    )


@ai_app.command()
def use(
    provider: Annotated[Provider, typer.Argument(help="Provider to make active.")],
    model: Annotated[
        str | None, typer.Option("--model", "-m", help="Model to use for this provider.")
    ] = None,
) -> None:
    """Switch the active provider (and optionally its model) in your env file."""
    chosen = _literal(provider)
    updates = {"GUARDIAN_LLM_PROVIDER": chosen}
    if model:
        updates[MODEL_ENV_VARS[chosen]] = model.strip()
    path = target_env_file()
    with cli_errors():
        update_env_file(path, updates)
        settings = load_settings()
    console.print(f"Active provider: [bold]{PROVIDER_LABELS[chosen]}[/bold] (written to {path})")
    console.print(f"Model: {model.strip() if model else configured_model(settings, chosen)}")
    if settings.llm_provider != chosen:
        console.print(
            "[yellow]Note: GUARDIAN_LLM_PROVIDER is overridden by an environment variable or "
            f"a later env file (effective: {settings.llm_provider}).[/yellow]"
        )
    if settings.llm_model:
        console.print(
            f"[yellow]Note: GUARDIAN_LLM_MODEL={settings.llm_model} overrides the provider "
            "model; remove it to use the model shown above.[/yellow]"
        )
    if api_key_for(settings, chosen) is None:
        console.print(
            f"[yellow]{KEY_ENV_VARS[chosen]} is not set. Add it to {path.resolve()} "
            f"(get one at {KEY_URLS[chosen]}).[/yellow]"
        )
