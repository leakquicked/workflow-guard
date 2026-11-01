"""Workflow Guard: read-only static checks for GitHub Actions workflow YAML."""
from __future__ import annotations
import argparse, json, re, sys
from pathlib import Path
from dataclasses import asdict, dataclass
from typing import Any
import yaml

SHA40 = re.compile(r"^[0-9a-fA-F]{40}$")
UNTRUSTED = ("github.event.issue.title", "github.event.issue.body", "github.event.comment.body",
             "github.event.review.body", "github.event.pull_request.title",
             "github.event.pull_request.body", "github.event.pull_request.head.ref", "github.head_ref")

@dataclass(frozen=True)
class Finding:
    rule_id: str
    severity: str
    file: str
    line: int
    message: str
    recommendation: str
    def to_dict(self) -> dict[str, Any]:
        return asdict(self)

def line_of(text: str, needle: str) -> int:
    return next((i for i, line in enumerate(text.splitlines(), 1) if needle and needle in line), 1)

def analyze_text(text: str, file_name: str = "<workflow>") -> list[Finding]:
    try:
        data = yaml.load(text, Loader=yaml.BaseLoader)  # Preserve YAML key "on".
    except yaml.YAMLError as exc:
        raise ValueError(f"Invalid YAML: {exc}") from exc
    if not isinstance(data, dict):
        raise ValueError("Workflow must be a YAML mapping.")
    out: list[Finding] = []
    perms = data.get("permissions")
    if perms is None:
        out.append(Finding("WG001","high",file_name,line_of(text,"jobs:"),
            "Workflow permissions are not explicitly restricted.",
            "Declare least-privilege top-level permissions and add job-level scopes only when needed."))
    elif isinstance(perms, str) and perms.lower() == "write-all":
        out.append(Finding("WG006","high",file_name,line_of(text,"permissions:"),
            "Workflow grants write-all token permissions.","Replace write-all with explicit minimum scopes."))
    triggers = data.get("on", [])
    if isinstance(triggers, str): triggers = [triggers]
    if isinstance(triggers, dict): triggers = list(triggers)
    if "pull_request_target" in triggers:
        out.append(Finding("WG003","high",file_name,line_of(text,"pull_request_target"),
            "Workflow uses the privileged pull_request_target trigger.",
            "Do not check out or execute untrusted pull-request content in this privileged context."))
    jobs = data.get("jobs", {})
    if not isinstance(jobs, dict): jobs = {}
    for job_name, job in jobs.items():
        if not isinstance(job, dict): continue
        if isinstance(job.get("permissions"), str) and job["permissions"].lower() == "write-all":
            out.append(Finding("WG006","high",file_name,line_of(text,"permissions:"),
                f"Job '{job_name}' grants write-all token permissions.","Use explicit least-privilege scopes."))
        steps = job.get("steps", [])
        if not isinstance(steps, list): continue
        for step in steps:
            if not isinstance(step, dict): continue
            uses = step.get("uses")
            if isinstance(uses, str) and not uses.startswith(("./","docker://")):
                ref = uses.rsplit("@",1)
                if len(ref) != 2 or not SHA40.fullmatch(ref[1]):
                    out.append(Finding("WG002","medium",file_name,line_of(text,uses),
                        f"Action '{uses}' is not pinned to a full 40-character commit SHA.",
                        "Pin to a reviewed full commit SHA; retain the release tag in a comment."))
            if str(step.get("persist-credentials","")).lower() == "true":
                out.append(Finding("WG005","medium",file_name,line_of(text,"persist-credentials"),
                    "Checkout credentials are explicitly persisted.",
                    "Set persist-credentials: false unless later Git operations require authentication."))
            run = step.get("run")
            if isinstance(run,str):
                hit = next((ctx for ctx in UNTRUSTED if "${{ " + ctx + " }}" in run),None)
                if hit:
                    out.append(Finding("WG004","high",file_name,line_of(text,hit),
                        f"Shell script directly interpolates untrusted event data: {hit}.",
                        "Pass values through environment variables, validate them and quote them; never interpolate into script source."))
    return sorted(out,key=lambda f:(f.file,f.line,f.rule_id,f.message))

def scan(path: Path) -> list[Finding]:
    paths = [path] if path.is_file() else sorted(p for p in path.rglob("*") if p.is_file() and p.suffix.lower() in {".yml",".yaml"})
    if not path.exists(): raise ValueError(f"Path does not exist: {path}")
    if path.is_file() and path.suffix.lower() not in {".yml",".yaml"}: raise ValueError("Input must be a .yml or .yaml file.")
    findings=[]
    for p in paths:
        try: findings.extend(analyze_text(p.read_text(encoding="utf-8"),str(p)))
        except OSError as exc: raise ValueError(f"Cannot read {p}: {exc}") from exc
    return findings

def main(argv: list[str] | None = None) -> int:
    parser=argparse.ArgumentParser(description="Statically audit GitHub Actions workflow YAML.")
    parser.add_argument("path",type=Path)
    parser.add_argument("--format",choices=("text","json"),default="text")
    parser.add_argument("--strict",action="store_true",help="Return 1 when findings exist.")
    args=parser.parse_args(argv)
    try: findings=scan(args.path)
    except ValueError as exc: print(f"workflow-guard: {exc}",file=sys.stderr); return 2
    if args.format=="json": print(json.dumps([f.to_dict() for f in findings],indent=2))
    else:
        for f in findings:
            print(f"{f.file}:{f.line}: {f.rule_id} {f.severity.upper()} {f.message}\n  Fix: {f.recommendation}")
        print(f"{len(findings)} finding(s).")
    return 1 if args.strict and findings else 0

if __name__=="__main__": raise SystemExit(main())
