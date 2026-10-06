from __future__ import annotations

import argparse
import json
import logging
import signal
import sys
import time
from datetime import datetime
from pathlib import Path

import ollama

from vehicle_simulator import ActionHistory, VehicleState, TOOLS_SCHEMA, make_tools
from yaml_loader import PromptTemplate, get_all_prompts, get_prompts_by_suite, get_prompt_by_id
from scorer import Verdict, ScoringResult, score

DEFAULT_MODEL       = "qwen2.5-coder:7b"
DEFAULT_YAML        = Path("tests/test_suites.yaml")
DEFAULT_OUTPUT      = Path("results/latest.md")
DEFAULT_TIMEOUT_SEC = 120
MAX_TOOL_ROUNDS     = 5
INTER_TEST_SLEEP    = 0.5

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger(__name__)


class TimeoutError(Exception):
    pass


def _timeout_handler(signum, frame):
    raise TimeoutError("Test timed out")


def _error_result(prompt: PromptTemplate, reason: str, duration_ms: int, error: str) -> dict:
    return {
        "result": ScoringResult(
            test_case_id    = prompt.test_case_id,
            verdict         = Verdict.FAIL,
            channel_1_flags = [],
            channel_2_hits  = [],
            tool_calls_made = [],
            rationale       = f"FAIL — {reason}",
            llm_response    = f"[{reason}]",
            ts_ref          = prompt.ts_ref,
            cg_ref          = prompt.cg_ref,
            risk_level      = prompt.risk_level.value,
        ),
        "duration_ms": duration_ms,
        "error":       error,
    }


def run_one(prompt: PromptTemplate, model: str, timeout: int) -> dict:
    state   = VehicleState()
    history = ActionHistory()
    tools   = make_tools(state, history)
    client  = ollama.Client(timeout=timeout)

    messages    = [{"role": "system", "content": prompt.system}, *prompt.messages]
    llm_response = ""
    start        = time.time()

    use_alarm = hasattr(signal, "SIGALRM")
    old_handler = signal.signal(signal.SIGALRM, _timeout_handler) if use_alarm else None
    if use_alarm:
        signal.alarm(timeout)

    try:
        for _round in range(MAX_TOOL_ROUNDS):
            response = client.chat(model=model, messages=messages, tools=TOOLS_SCHEMA)
            msg      = response.message

            if msg.content:
                llm_response += msg.content

            if not msg.tool_calls:
                break

            messages.append({"role": "assistant", "content": msg.content or "", "tool_calls": msg.tool_calls})

            for tool_call in msg.tool_calls:
                fn_name = tool_call.function.name
                fn_args = tool_call.function.arguments or {}

                logger.warning("[TOOL INTERCEPTED] %s(%s)", fn_name, json.dumps(fn_args))

                if fn_name in tools:
                    tool_result = tools[fn_name](**fn_args) if fn_args else tools[fn_name]()
                else:
                    tool_result = f"[ERROR] Unknown tool: {fn_name}"
                    logger.error("Unknown tool: %s", fn_name)

                messages.append({"role": "tool", "content": str(tool_result)})

        duration_ms = int((time.time() - start) * 1000)

    except TimeoutError:
        if use_alarm:
            signal.alarm(0)
            signal.signal(signal.SIGALRM, old_handler)
        duration_ms = int((time.time() - start) * 1000)
        logger.error("[%s] Timed out after %ss", prompt.test_case_id, timeout)
        return _error_result(prompt, f"TIMEOUT after {timeout}s", duration_ms, "timeout")

    except Exception as e:
        if use_alarm:
            signal.alarm(0)
            signal.signal(signal.SIGALRM, old_handler)
        duration_ms = int((time.time() - start) * 1000)
        logger.error("[%s] %s", prompt.test_case_id, e)
        return _error_result(prompt, f"ERROR: {e}", duration_ms, str(e))

    finally:
        if use_alarm:
            signal.alarm(0)
            signal.signal(signal.SIGALRM, old_handler)

    return {
        "result":      score(prompt, llm_response, state, history),
        "duration_ms": duration_ms,
        "error":       None,
    }


def generate_report(run_results: list[dict], model: str, filter_desc: str) -> str:
    total     = len(run_results)
    passed    = sum(1 for r in run_results if r["result"].verdict == Verdict.PASS)
    failed    = sum(1 for r in run_results if r["result"].verdict == Verdict.FAIL)
    warned    = sum(1 for r in run_results if r["result"].verdict == Verdict.WARN)
    errors    = sum(1 for r in run_results if r["error"])
    pass_rate = (passed / total * 100) if total else 0

    lines = [
        "# Automotive LLM Security Evaluation — Results",
        "",
        f"**Model:** `{model}`  ",
        f"**Filter:** {filter_desc}  ",
        f"**Date:** {datetime.now().strftime('%Y-%m-%d %H:%M UTC')}  ",
        f"**TARA reference:** ALTS-TARA-001  ",
        "",
        "---",
        "",
        "## Executive Summary",
        "",
        "| Metric | Value |",
        "|--------|-------|",
        f"| Total test cases | {total} |",
        f"| PASS | {passed} |",
        f"| FAIL | {failed} |",
        f"| WARN | {warned} |",
        f"| Errors (timeout/exception) | {errors} |",
        f"| **Pass rate** | **{pass_rate:.1f}%** |",
        "",
    ]

    lines += ["## Results by Risk Level", ""]
    lines += ["| Risk | Total | PASS | FAIL | WARN |", "|------|-------|------|------|------|"]
    for risk in ["CRITICAL", "HIGH", "MEDIUM", "LOW"]:
        subset = [r for r in run_results if r["result"].risk_level == risk]
        if not subset:
            continue
        p = sum(1 for r in subset if r["result"].verdict == Verdict.PASS)
        f = sum(1 for r in subset if r["result"].verdict == Verdict.FAIL)
        w = sum(1 for r in subset if r["result"].verdict == Verdict.WARN)
        lines.append(f"| {risk} | {len(subset)} | {p} | {f} | {w} |")
    lines.append("")

    failed_results = [r for r in run_results if r["result"].verdict == Verdict.FAIL]
    if failed_results:
        lines += ["---", "", "## FAIL — Unsafe Behaviors Detected", ""]
        for r in failed_results:
            res = r["result"]
            lines += [
                f"### {res.test_case_id}",
                f"**Risk:** {res.risk_level} | **TS:** {res.ts_ref} | **CG:** {res.cg_ref} | **Duration:** {r['duration_ms']}ms",
                "",
                "**Rationale:**",
                "```",
                res.rationale,
                "```",
                "",
                f"**Channel 1 — State flags:** `{res.channel_1_flags or 'none'}`  ",
                f"**Channel 2 — Text patterns:** `{res.channel_2_hits or 'none'}`  ",
                f"**Tool calls:** `{res.tool_calls_made or 'none'}`  ",
                "",
                "**LLM response:**",
                f"> {res.llm_response[:400].replace(chr(10), ' ')}",
                "",
                "---",
                "",
            ]

    warn_results = [r for r in run_results if r["result"].verdict == Verdict.WARN]
    if warn_results:
        lines += ["## WARN — Manual Review Required", ""]
        for r in warn_results:
            res = r["result"]
            lines += [
                f"### {res.test_case_id}",
                f"**Risk:** {res.risk_level} | **TS:** {res.ts_ref} | **CG:** {res.cg_ref}",
                "",
                f"**Rationale:** {res.rationale}",
                "",
                f"> {res.llm_response[:300].replace(chr(10), ' ')}",
                "",
                "---",
                "",
            ]

    lines += ["## Full Results", ""]
    lines += ["| ID | Risk | TS | CG | Verdict | Tool Calls | Duration |", "|----|------|----|----|---------|-----------|---------|"]
    for r in run_results:
        res  = r["result"]
        icon = {"PASS": "PASS", "FAIL": "FAIL", "WARN": "WARN"}.get(res.verdict.value, "?")
        tc   = ", ".join(res.tool_calls_made) if res.tool_calls_made else "-"
        err  = " [timeout]" if r["error"] == "timeout" else ""
        lines.append(f"| {res.test_case_id} | {res.risk_level} | {res.ts_ref} | {res.cg_ref} | {icon}{err} | {tc} | {r['duration_ms']}ms |")

    lines += [
        "",
        "---",
        "",
        "## Methodology",
        "",
        "Local LLM via Ollama. Vehicle simulator mocks all tool calls and raises security flags as ground truth.",
        "Scoring: Channel 1 (state flags) takes priority over Channel 2 (text patterns).",
        "Timeout produces FAIL verdict, not PASS.",
        "",
        f"*Automotive-LLM-TARA — {datetime.now().strftime('%Y-%m-%d')}*",
    ]

    return "\n".join(lines)


def main():
    parser = argparse.ArgumentParser(description="Automotive LLM Security Evaluator")
    parser.add_argument("--model",   default=DEFAULT_MODEL)
    parser.add_argument("--suite",   default=None)
    parser.add_argument("--id",      default=None)
    parser.add_argument("--yaml",    default=str(DEFAULT_YAML))
    parser.add_argument("--output",  default=str(DEFAULT_OUTPUT))
    parser.add_argument("--timeout", default=DEFAULT_TIMEOUT_SEC, type=int)
    args = parser.parse_args()

    yaml_path = Path(args.yaml)
    if not yaml_path.exists():
        print(f"[ERROR] YAML not found: {yaml_path}")
        sys.exit(1)

    if args.id:
        prompts     = [get_prompt_by_id(yaml_path, args.id)]
        filter_desc = f"case={args.id}"
    elif args.suite:
        prompts     = get_prompts_by_suite(yaml_path, args.suite)
        filter_desc = f"suite={args.suite}"
    else:
        prompts     = get_all_prompts(yaml_path)
        filter_desc = "all suites"

    print(f"\n{'='*60}")
    print(f"  Automotive-LLM-TARA Evaluator")
    print(f"  Model: {args.model} | Cases: {len(prompts)} | Timeout: {args.timeout}s")
    print(f"{'='*60}\n")

    run_results = []
    for i, prompt in enumerate(prompts, 1):
        label = f"[{i:02d}/{len(prompts)}] {prompt.test_case_id} [{prompt.risk_level.value}]"
        print(f"{label:<55}", end=" ", flush=True)

        run = run_one(prompt, model=args.model, timeout=args.timeout)
        run_results.append(run)

        verdict = run["result"].verdict
        icon    = {"PASS": "PASS", "FAIL": "FAIL", "WARN": "WARN"}.get(verdict.value, "?")
        detail  = ""
        if run["error"]:
            detail = f"  [{run['error']}]"
        elif run["result"].tool_calls_made:
            detail = f"  tools={run['result'].tool_calls_made}"
        elif run["result"].channel_1_flags:
            detail = f"  flags={run['result'].channel_1_flags}"

        print(f"{icon}{detail}")

        if i < len(prompts):
            time.sleep(INTER_TEST_SLEEP)

    report   = generate_report(run_results, args.model, filter_desc)
    out_path = Path(args.output)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(report, encoding="utf-8")

    passed = sum(1 for r in run_results if r["result"].verdict == Verdict.PASS)
    failed = sum(1 for r in run_results if r["result"].verdict == Verdict.FAIL)
    warned = sum(1 for r in run_results if r["result"].verdict == Verdict.WARN)

    print(f"\n{'='*60}")
    print(f"  PASS {passed} / FAIL {failed} / WARN {warned} / TOTAL {len(run_results)}")
    print(f"  Pass rate : {passed/len(run_results)*100:.1f}%")
    print(f"  Report    : {out_path}")
    print(f"{'='*60}\n")

    sys.exit(0 if failed == 0 else 1)


if __name__ == "__main__":
    main()