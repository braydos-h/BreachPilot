"""Phase 1: regression test that every AttackModule subclass exported from
``tools.attack_modules.modules.__init__`` is actually registered in the
central registry (``_MODULE_CLASSES`` / ``list_modules()``).

Catches the ``ModbusWriteCoil``-style drift where a class is exported from
``modules/__init__.py`` (so ``from tools.attack_modules.modules import X``
works) but never added to ``_MODULE_CLASSES`` (so ``list_modules()`` /
``find_modules()`` / ``get_module()`` never return it). This is exactly the
silent dead-code failure mode the 3-place registration edit produces.

Also verifies the ``@register_attack_module`` decorator path: decorating a
fresh subclass makes it appear in ``list_modules()`` without any edit to
``_MODULE_CLASSES``.
"""

from __future__ import annotations

import tools.attack_modules.modules as _modules_pkg
from tools.attack_modules import _MODULE_CLASSES, get_module, list_modules
from tools.attack_modules import registry as registry_mod
from tools.attack_modules.base import AttackModule, ModuleContext
from tools.attack_modules.modules import __all__ as MODULE_EXPORT_NAMES


def test_every_exported_module_is_registered() -> None:
    """Every class exported from ``tools.attack_modules.modules`` (by the
    PascalCase name in ``__all__``) must be registered in ``_MODULE_CLASSES``
    AND its ``.name`` attribute must resolve via ``get_module``.

    Catches the ``ModbusWriteCoil``-style drift where a class is exported but
    never added to ``_MODULE_CLASSES``. Note: ``__all__`` carries the PascalCase
    *class* name; ``get_module`` matches by the ``.name`` attribute (which most
    modules set to the PascalCase name, but a few -- detection / ICS -- use
    snake_case). The test resolves the class via ``getattr`` and then checks
    ``get_module(cls.name)`` so both conventions are covered.
    """
    missing: list[str] = []
    for class_name in MODULE_EXPORT_NAMES:
        cls = getattr(_modules_pkg, class_name, None)
        if cls is None:
            missing.append(f"{class_name} (not importable from modules package)")
            continue
        if cls not in _MODULE_CLASSES:
            missing.append(f"{class_name} (class not in _MODULE_CLASSES)")
            continue
        # The .name attribute is what get_module matches on.
        if get_module(cls.name) is None:
            missing.append(f"{class_name} (.name={cls.name!r} not resolvable via get_module)")
    assert not missing, (
        f"AttackModule classes exported from tools.attack_modules.modules.__all__ "
        f"but NOT properly registered: {missing}. "
        f"Add them to registry._MODULE_CLASSES or decorate with @register_attack_module."
    )


def test_registered_modules_have_unique_names() -> None:
    """No two registered classes may share a .name (would shadow each other)."""
    names = [m.name for m in list_modules()]
    dupes = [n for n in set(names) if names.count(n) > 1]
    assert not dupes, f"Duplicate AttackModule.name values in registry: {dupes}"


def test_register_attack_module_decorator_appends() -> None:
    """Decorating a fresh subclass registers it without editing _MODULE_CLASSES."""
    class _TempModule(AttackModule):
        name = "_TempModuleForTest"
        description = "test fixture"
        target_services = []
        target_ports = []

        def run(self, ctx: ModuleContext) -> dict:
            return {"status": "info", "module": self.name}

    decorated = registry_mod.register_attack_module(_TempModule)
    assert decorated is _TempModule  # decorator returns the class unchanged
    assert _TempModule in _MODULE_CLASSES
    # get_module resolves by name
    assert get_module("_TempModuleForTest") is not None
    # Cleanup so the fixture doesn't leak into other tests
    try:
        _MODULE_CLASSES.remove(_TempModule)
    except ValueError:
        pass


def test_ics_write_modules_registered_and_gated() -> None:
    """Phase 1: the 4 ICS destructive write modules are registered (fixing the
    prior drift where they were exported but never in _MODULE_CLASSES) AND
    their applicability is 0 unless ics.allow_write + ics.destructive_ics are
    both armed. Default config (both false) -> 0 applicability -> invisible
    to find_modules.
    """
    # The .name attribute (not the class name) is what get_module matches.
    ics_write_class_names = ("ModbusWriteCoil", "ModbusWriteRegister", "S7PlcStop", "S7PlcStart")
    for class_name in ics_write_class_names:
        cls = getattr(_modules_pkg, class_name)
        assert cls in _MODULE_CLASSES, f"{class_name} should be registered in _MODULE_CLASSES"
        mod = get_module(cls.name)
        assert mod is not None, f"{class_name} (.name={cls.name!r}) should resolve via get_module"
        # Destructive-ICS gate: applicability must be 0 under the safe default
        ctx = ModuleContext(
            target_ip="127.0.0.1",
            services=[{"service": "modbus", "port": "502/tcp", "version": ""}],
        )
        # The base applicability() short-circuits to 0 when destructive_ics
        # is set and _ics_write_allowed() returns False (the safe default).
        assert mod.applicability(ctx) == 0, (
            f"{class_name} applicability must be 0 when ics.allow_write/destructive_ics are false"
        )
