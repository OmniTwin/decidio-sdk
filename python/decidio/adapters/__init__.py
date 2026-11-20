"""Engine adapters — each maps the Decidio gate onto an engine's native durable wait.
Thin by rule (see _common): only the suspend/resume translation lives here.

`bind(name, ...)` backs `guard.protect(fn, describe, adapter=name)` for engines whose
wait primitive is contextvar-based (LangGraph `interrupt`, Temporal `wait_condition`) —
those are true drop-ins. Engines that pass an explicit handle are used through their own
functions (they need the handle at call time): Inngest `step` and Temporal through
`gate(...)`, the OpenAI Agents `RunState` through `authorize_interruptions(...)` and, on
resume, `apply_verified_resume(...)`; see decidio/adapters/{inngest,temporal,openai}.py.
"""
from __future__ import annotations

import functools
from typing import Any, Callable


def bind(name: str, guard: Any, fn: Callable[..., Any], describe: Callable[..., dict], evidence: Any = None) -> Callable[..., Any]:
    """Bind an engine adapter behind `guard.protect(fn, describe, adapter=name)`.

    BETA. The engine adapters share the CORE's gate semantics — the verdict allow-list
    (`_common.assert_authorize_verdict`, enforced inside `authorize()` so no door can skip it),
    the canonical argument model, the transport rule and evidence handling are ONE
    implementation exercised across every door — but their ENGINE integration is verified
    against structural mocks (a fake `interrupt`, a fake `step`, a fake `wait_condition`, a
    duck-typed RunState), not live engines. Use the core path for production until that changes.
    """
    if name == "langgraph":
        from . import langgraph as lg




        @functools.wraps(fn)
        def wrapped(*a: Any, **k: Any) -> Any:
            return lg.gate(guard, describe(*a, **k), lambda: fn(*a, **k), evidence=evidence)
        return wrapped

    if name in ("inngest", "temporal", "openai"):





        entry = ("decidio.adapters.openai.authorize_interruptions(...) and, on resume, "
                 "decidio.adapters.openai.apply_verified_resume(...)") if name == "openai" else f"decidio.adapters.{name}.gate(...)"
        raise ValueError(
            f'the "{name}" adapter needs the engine handle at call time — call '
            f"{entry} directly (see its docstring)."
        )
    raise ValueError(
        f'unknown adapter "{name}" - the available engine adapters are "langgraph", '
        f'"inngest", "temporal", "openai" (decidio.adapters.<name>), or omit the option '
        f'for the core gate.'
    )
