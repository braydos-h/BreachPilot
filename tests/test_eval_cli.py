from __future__ import annotations

import asyncio

from main import parse_args


def test_eval_flag_parsed() -> None:
    args = parse_args(["--eval", "--target", "10.0.0.5"])
    assert getattr(args, "eval", False) is True
    assert args.target == "10.0.0.5"


def test_eval_flag_default_false() -> None:
    args = parse_args(["--target", "10.0.0.5"])
    assert getattr(args, "eval", False) is False


def test_run_eval_importable() -> None:
    from tools.eval_harness import run_eval

    assert asyncio.iscoroutinefunction(run_eval)