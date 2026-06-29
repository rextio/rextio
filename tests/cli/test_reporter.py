from __future__ import annotations

import io
import json
from argparse import Namespace

from rextio.cli.reporter import Reporter, Verbosity


def _reporter(**kwargs: object) -> tuple[Reporter, io.StringIO, io.StringIO]:
    out, err = io.StringIO(), io.StringIO()
    reporter = Reporter(stdout=out, stderr=err, **kwargs)  # type: ignore[arg-type]
    return reporter, out, err


def test_info_goes_to_stdout_and_errors_to_stderr() -> None:
    reporter, out, err = _reporter()
    reporter.info("building")
    reporter.error("boom")

    assert out.getvalue() == "building\n"
    assert err.getvalue() == "boom\n"


def test_quiet_suppresses_info_and_detail_but_keeps_result_warnings_and_errors() -> None:
    reporter, out, err = _reporter(verbosity=Verbosity.QUIET)
    reporter.info("status")
    reporter.detail("trace")
    reporter.warn("careful")
    reporter.error("boom")
    reporter.print_result(text="result", data={"k": 1})

    # Progress is suppressed; the result still prints (the result is the point of
    # the command — --quiet trims chatter, not the answer).
    assert out.getvalue() == "result\n"
    assert "careful" in err.getvalue()
    assert "boom" in err.getvalue()


def test_detail_requires_verbose() -> None:
    normal, normal_out, _ = _reporter(verbosity=Verbosity.NORMAL)
    normal.detail("trace")
    assert normal_out.getvalue() == ""

    verbose, verbose_out, _ = _reporter(verbosity=Verbosity.VERBOSE)
    verbose.detail("trace")
    assert verbose_out.getvalue() == "trace\n"


def test_print_result_text_mode() -> None:
    reporter, out, _ = _reporter()
    reporter.print_result(text="human", data={"k": 1})
    assert out.getvalue() == "human\n"


def test_quiet_keeps_the_result_in_both_formats() -> None:
    text_reporter, text_out, _ = _reporter(verbosity=Verbosity.QUIET)
    text_reporter.print_result(text="human", data={"k": 1})
    assert text_out.getvalue() == "human\n"

    json_reporter, json_out, _ = _reporter(verbosity=Verbosity.QUIET, output_format="json")
    json_reporter.print_result(text="human", data={"k": 1})
    assert json.loads(json_out.getvalue()) == {"k": 1}


def test_json_mode_keeps_stdout_parseable_and_warnings_go_to_stderr() -> None:
    reporter, out, err = _reporter(output_format="json")
    reporter.info("status")  # stdout progress is suppressed so stdout stays parseable
    reporter.warn("careful")  # warnings still surface — on stderr, never stdout
    reporter.print_result(text="human", data={"k": 1})

    assert "careful" in err.getvalue()
    assert json.loads(out.getvalue()) == {"k": 1}


def test_from_args_maps_flags() -> None:
    quiet = Reporter.from_args(Namespace(quiet=True))
    assert quiet.verbosity is Verbosity.QUIET

    verbose = Reporter.from_args(Namespace(verbose=True))
    assert verbose.verbosity is Verbosity.VERBOSE

    explicit = Reporter.from_args(Namespace(format="json"))
    assert explicit.json is True


def test_from_args_falls_back_to_legacy_json_flag() -> None:
    reporter = Reporter.from_args(Namespace(json=True))
    assert reporter.json is True


def test_from_args_tolerates_missing_attributes() -> None:
    reporter = Reporter.from_args(Namespace())
    assert reporter.verbosity is Verbosity.NORMAL
    assert reporter.json is False
