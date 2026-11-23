#!/usr/bin/env python3
"""Embed an identity for the image compiled from the actual Go input graph."""

import argparse
import hashlib
import json
import os
from pathlib import Path
import subprocess
import tempfile
import uuid
import shlex


def run(arguments):
    return subprocess.run(arguments, text=True, capture_output=True, check=True).stdout


def inputs():
    environment = json.loads(run(["go", "env", "-json", "GOOS", "GOARCH", "CGO_ENABLED", "GOVERSION",
                                      "GOAMD64", "GOARM64", "GOARM", "GOMIPS", "GOMIPS64", "GOPPC64",
                                      "GORISCV64", "GOWASM", "GOEXPERIMENT", "CC", "CXX",
                                      "CGO_CFLAGS", "CGO_CPPFLAGS", "CGO_CXXFLAGS", "CGO_FFLAGS", "CGO_LDFLAGS"]))
    graph = run(["go", "list", "-deps", "-json", "./cmd/" + TOOL])
    decoder = json.JSONDecoder()
    digest = hashlib.sha256(json.dumps(environment, sort_keys=True).encode())
    digest.update(run(["go", "env", "GOFLAGS"]).encode())
    digest.update(Path(__file__).read_bytes())
    module_files = set()
    try:
        digest.update(run(["git", "rev-parse", "HEAD"]).encode())
        digest.update(str(bool(run(["git", "status", "--porcelain"]))).encode())
    except subprocess.CalledProcessError:
        digest.update(b"source-export")
    position = 0
    while position < len(graph):
        while position < len(graph) and graph[position].isspace():
            position += 1
        if position == len(graph):
            break
        package, position = decoder.raw_decode(graph, position)
        directory = Path(package["Dir"])
        digest.update(package["ImportPath"].encode())
        digest.update(json.dumps({key: package.get(key) for key in (
            "GoVersion", "CgoCFLAGS", "CgoCPPFLAGS", "CgoCXXFLAGS", "CgoFFLAGS", "CgoLDFLAGS", "Module")},
            sort_keys=True).encode())
        module = package.get("Module") or {}
        for definition in (module, module.get("Replace") or {}):
            if definition.get("GoMod"):
                module_files.add(Path(definition["GoMod"]))
        for name in sorted(set(sum([package.get(key, []) for key in (
                "GoFiles", "CgoFiles", "CFiles", "CXXFiles", "MFiles",
                "HFiles", "SFiles", "SysoFiles", "EmbedFiles")], []))):
            path = directory / name
            digest.update(str(path).encode())
            digest.update(b"\0")
            digest.update(path.read_bytes())
            digest.update(b"\0")
    for definition in sorted(module_files):
        digest.update(str(definition).encode())
        digest.update(definition.read_bytes())
    return digest.hexdigest(), environment


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--tool", choices=("intent", "keylease"), required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--manifest", type=Path)
    options = parser.parse_args()
    TOOL = options.tool
    before, environment = inputs()
    symbol = ("github.com/lanej/intent/internal/activation.BuildIdentity" if TOOL == "intent"
              else "github.com/lanej/keylease/internal/broker.BuildIdentity")
    options.output.parent.mkdir(parents=True, exist_ok=True)
    if options.manifest is not None and options.manifest.is_file() and options.output.is_file():
        cached = json.loads(options.manifest.read_text())
        if (cached.get("input_fingerprint") == before
                and cached.get("sha256") == hashlib.sha256(options.output.read_bytes()).hexdigest()
                and cached.get("platform") == environment["GOOS"]
                and cached.get("architecture") == environment["GOARCH"]):
            print(json.dumps(cached))
            raise SystemExit(0)
    image_id = before + "-" + uuid.uuid4().hex
    global_flags = shlex.split(run(["go", "env", "GOFLAGS"]).strip())
    linker_flags = next((flag.removeprefix("-ldflags=") for flag in global_flags
                         if flag.startswith("-ldflags=")), "")
    with tempfile.TemporaryDirectory(prefix=".lifecycle-build-", dir=options.output.parent) as temporary:
        binary = Path(temporary) / TOOL
        subprocess.run(["go", "build", "-buildvcs=true", "-ldflags",
                        f"{linker_flags} -X {symbol}={image_id}", "-o", str(binary), "./cmd/" + TOOL], check=True)
        after, after_environment = inputs()
        if after != before or after_environment != environment:
            raise SystemExit("Go compilation inputs changed; preserve the previous selected artifact")
        record = {"expected_identity": "build:" + image_id, "input_fingerprint": before,
                  "sha256": hashlib.sha256(binary.read_bytes()).hexdigest(),
                  "platform": environment["GOOS"], "architecture": environment["GOARCH"]}
        binary.replace(options.output)
    if options.manifest is not None:
        options.manifest.parent.mkdir(parents=True, exist_ok=True)
        with tempfile.NamedTemporaryFile("w", dir=options.manifest.parent, delete=False) as stream:
            stage = Path(stream.name)
            json.dump(record, stream)
            stream.write("\n")
            stream.flush()
            os.fsync(stream.fileno())
        stage.replace(options.manifest)
    print(json.dumps(record))
