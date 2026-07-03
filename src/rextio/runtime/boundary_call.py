"""In-process dispatch for native scalar boundary calls.

Generated native code calls :func:`boundary_call` when an explicitly marked
native function invokes a project function that lives on the Python fallback
(analyzer diagnostic ``RXT075``). The callee runs in the host interpreter, so
its behavior is CPython-exact by construction; only immutable scalars cross
the boundary (the analyzer enforces the same rule as dispatcher delegation).
Scalars cross by VALUE: the callee sees equal values re-boxed from the native
caller's extracted copies, not the caller's original objects, so an identity
check (``is``) on an argument is not preserved (the ``None``/``bool``
singletons are). Traceback frames of a callee exception include this hook.

The target is resolved with ``getattr`` at every call, so runtime replacement
of the fallback function (tests monkeypatching a module attribute) is honored
by the native path exactly like a Python caller would honor it.

Every dispatch also counts one boundary crossing against the CALLING native
function, feeding the same counter the generated wrappers consult - a native
function that chatters across the boundary crosses the threshold and is
demoted to its Python fallback on the next wrapper entry.
"""

from __future__ import annotations

import importlib
from typing import Any

from rextio.runtime.boundary_fallback import boundary_fallback_required


def boundary_call(caller_qualname: str, target_qualname: str, args: tuple[Any, ...]) -> Any:
    """Dispatch one native-to-Python scalar boundary call."""
    # Count the crossing against the caller. The return value is deliberately
    # ignored here: a function already executing natively cannot demote
    # mid-flight; its wrapper reads the same counter on the next entry. Note
    # this is NOT a pure query - once the count crosses the threshold,
    # boundary_fallback_required permanently latches the caller into
    # fallback_functions, so every future wrapper entry takes the fallback.
    boundary_fallback_required(caller_qualname)
    module_name, _, attribute = target_qualname.rpartition(".")
    module = importlib.import_module(module_name)
    return getattr(module, attribute)(*args)
