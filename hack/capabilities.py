#!/usr/bin/env python3
"""Check docs/capabilities.md against a Ceph source tree.

Reads the Ceph source with the ast module only (no mgr runtime needed) and
compares four sections of the matrix with it:

  - "Orchestrator methods": public methods of orchestrator._interface.Orchestrator
  - "ceph orch commands": prefixes of OrchestratorCLICommand.Read/Write in orchestrator/module.py,
    and the `orch ...` prefixes of CephadmCLICommand in cephadm/module.py
  - "Service types": service_type values of the ServiceSpec classes
  - "Spec fields": "<service_type>.<field>" for the constructor arguments of each
    service type's spec class (ServiceSpec._cls), and "placement.<field>"

Fails on rows that are missing, stale (not in the source) or duplicated.
The "Dashboard pages" and "PoC CLI commands" sections are maintained by hand.

usage: capabilities.py <ceph source dir> [docs/capabilities.md]
       capabilities.py --list <ceph source dir>   print what the source has
"""

import ast
import pathlib
import re
import sys

SECTIONS = ("Orchestrator methods", "ceph orch commands", "Service types", "Spec fields")
STATUSES = ("implemented", "unsupported") + tuple(f"milestone {n}" for n in range(1, 7))


def parse(path):
    return ast.parse(path.read_text(), filename=str(path))


def orchestrator_methods(mgr):
    tree = parse(mgr / "orchestrator" / "_interface.py")
    for node in tree.body:
        if isinstance(node, ast.ClassDef) and node.name == "Orchestrator":
            return sorted(
                f.name for f in node.body
                if isinstance(f, (ast.FunctionDef, ast.AsyncFunctionDef)) and not f.name.startswith("_")
            )
    raise SystemExit("class Orchestrator not found")


def cli_prefixes(path, decorator, only_orch=False):
    out = []
    for node in ast.walk(parse(path)):
        if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            continue
        for dec in node.decorator_list:
            if not (isinstance(dec, ast.Call) and isinstance(dec.func, ast.Attribute)):
                continue
            if not (isinstance(dec.func.value, ast.Name) and dec.func.value.id == decorator):
                continue
            args = list(dec.args) + [k.value for k in dec.keywords if k.arg == "prefix"]
            if args and isinstance(args[0], ast.Constant):
                if not only_orch or args[0].value.startswith("orch "):
                    out.append(args[0].value)
    return out


def orch_commands(mgr):
    # the generic orchestrator commands, plus the `orch ...` commands cephadm registers itself
    out = cli_prefixes(mgr / "orchestrator" / "module.py", "OrchestratorCLICommand")
    out += cli_prefixes(mgr / "cephadm" / "module.py", "CephadmCLICommand", only_orch=True)
    return sorted(set(out))


def service_specs(src):
    """Map service_type to the constructor arguments of its spec class, plus "placement"."""
    deploy = src / "python-common" / "ceph" / "deployment"
    classes = {}
    for f in ("service_spec.py", "drive_group.py"):
        for n in parse(deploy / f).body:
            if isinstance(n, ast.ClassDef):
                classes[n.name] = n

    def base_of(cls):
        for b in cls.bases:
            if isinstance(b, ast.Name) and b.id in classes:
                return b.id
        return None

    def fields(name):
        cls = classes[name]
        for f in cls.body:
            if isinstance(f, ast.FunctionDef) and f.name == "__init__":
                a = f.args
                own = [x.arg for x in a.args + a.kwonlyargs if x.arg not in ("self", "service_type")]
                # a constructor taking **kwargs passes the rest on to its base
                if a.kwarg is not None and base_of(cls):
                    own += [x for x in fields(base_of(cls)) if x not in own]
                return own
        return fields(base_of(cls)) if base_of(cls) else []

    spec = classes["ServiceSpec"]
    mapping, known = {}, []
    for f in spec.body:
        if isinstance(f, ast.Assign) and any(isinstance(t, ast.Name) and t.id == "KNOWN_SERVICE_TYPES" for t in f.targets):
            known = [e.value for e in getattr(f.value, "elts", []) if isinstance(e, ast.Constant)]
        if isinstance(f, ast.FunctionDef) and f.name == "_cls":
            for node in ast.walk(f):
                if isinstance(node, ast.Dict):
                    for k, v in zip(node.keys, node.values):
                        if not isinstance(v, ast.Name):
                            continue
                        if isinstance(k, ast.Constant):
                            mapping[k.value] = v.id
                        elif isinstance(k, ast.Attribute) and k.attr == "service_type" and isinstance(k.value, ast.Name):
                            # SMBSpec.service_type: SMBSpec
                            for g in classes[k.value.id].body:
                                if isinstance(g, ast.Assign) and any(isinstance(t, ast.Name) and t.id == "service_type" for t in g.targets):
                                    mapping[g.value.value] = v.id
    if not mapping or not known:
        raise SystemExit("ServiceSpec._cls or KNOWN_SERVICE_TYPES not found")

    out = {t: fields(mapping.get(t, "ServiceSpec")) for t in known}
    out["placement"] = fields("PlacementSpec")
    return out


def source(src):
    mgr = src / "src" / "pybind" / "mgr"
    specs = service_specs(src / "src")
    return {
        "Orchestrator methods": orchestrator_methods(mgr),
        "ceph orch commands": orch_commands(mgr),
        "Service types": sorted(t for t in specs if t != "placement"),
        "Spec fields": sorted(f"{t}.{f}" for t, fs in specs.items() for f in fs),
    }


def matrix(path):
    rows, section, bad = {}, None, []
    for n, line in enumerate(path.read_text().splitlines(), 1):
        if line.startswith("## "):
            section = line[3:].strip()
            continue
        if section not in SECTIONS or not line.startswith("| `"):
            continue
        cells = [c.strip() for c in line.strip().strip("|").split("|")]
        name = cells[0].strip("`")
        if len(cells) < 2 or cells[1] not in STATUSES:
            bad.append(f"line {n}: status {cells[1] if len(cells) > 1 else ''!r} is not one of {', '.join(STATUSES)}")
        rows.setdefault(section, []).append(name)
    return rows, bad


def main(argv):
    if argv[:1] == ["--list"]:
        for sec, names in source(pathlib.Path(argv[1])).items():
            print(f"## {sec}")
            for n in names:
                print(n)
        return 0

    src = pathlib.Path(argv[0])
    doc = pathlib.Path(argv[1] if len(argv) > 1 else "docs/capabilities.md")
    have, want = source(src), None
    want, errors = matrix(doc)
    for sec in SECTIONS:
        names = want.get(sec, [])
        dups = sorted({n for n in names if names.count(n) > 1})
        missing = sorted(set(have[sec]) - set(names))
        stale = sorted(set(names) - set(have[sec]))
        errors += [f"{sec}: duplicate row {n}" for n in dups]
        errors += [f"{sec}: missing row {n}" for n in missing]
        errors += [f"{sec}: stale row {n}" for n in stale]
    for e in errors:
        print(e, file=sys.stderr)
    return 1 if errors else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
