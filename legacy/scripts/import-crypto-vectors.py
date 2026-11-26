#!/usr/bin/env python3
"""Extract the supported ML-DSA interface from pinned public test corpora.

Run with a directory containing NIST {keyGen,sigGen,sigVer}-{prompt,expectedResults}.json,
revision, wycheproof-mldsa65.json and wycheproof-revision. Does not access the network.
The full source URLs and SHA-256 checksums are recorded in the generated fixture.
"""
import gzip
import hashlib
import json
import pathlib
import sys

source = pathlib.Path(sys.argv[1])
destination = pathlib.Path(__file__).resolve().parents[1] / "internal/guard/testdata/crypto-vectors.json.gz"
revision = (source / "revision").read_text().strip()
wycheproof_revision = (source / "wycheproof-revision").read_text().strip()
sources = []


def read(name, url):
    data = (source / name).read_bytes()
    sources.append({"url": url, "sha256": hashlib.sha256(data).hexdigest()})
    return json.loads(data)


output = {"sources": sources, "keygen": [], "siggen": [], "verify": []}
for mode in ("keyGen", "sigGen", "sigVer"):
    base = f"https://github.com/usnistgov/ACVP-Server/blob/{revision}/gen-val/json-files/ML-DSA-{mode}-FIPS204"
    prompt = read(f"{mode}-prompt.json", base + "/prompt.json")
    results = read(f"{mode}-expectedResults.json", base + "/expectedResults.json")
    expected = {(g["tgId"], t["tcId"]): t for g in results["testGroups"] for t in g["tests"]}
    for group in prompt["testGroups"]:
        if group["parameterSet"] != "ML-DSA-65":
            continue
        if mode != "keyGen" and (group.get("signatureInterface") != "external" or group.get("preHash") != "pure"):
            continue
        for test in group["tests"]:
            result = expected[group["tgId"], test["tcId"]]
            case = {"id": f"NIST/{mode}/{group['tgId']}/{test['tcId']}"}
            if mode == "keyGen":
                case.update(seed=test["seed"], pk=result["pk"], sk=result["sk"])
                output["keygen"].append(case)
            elif mode == "sigGen":
                case.update(sk=test["sk"], msg=test["message"], ctx=test["context"], sig=result["signature"], deterministic=group["deterministic"])
                output["siggen"].append(case)
            else:
                case.update(pk=test["pk"], msg=test["message"], ctx=test["context"], sig=test["signature"], valid=result["testPassed"])
                output["verify"].append(case)

wycheproof = read("wycheproof-mldsa65.json", f"https://github.com/C2SP/wycheproof/blob/{wycheproof_revision}/testvectors_v1/mldsa_65_verify_test.json")
count = 0
for group in wycheproof["testGroups"]:
    for test in group["tests"]:
        assert test["result"] in ("valid", "invalid"), "Unhandled expected result"
        output["verify"].append(dict(id=f"Wycheproof/{test['tcId']}", pk=group["publicKey"], msg=test["msg"], ctx=test.get("ctx", ""), sig=test["sig"], valid=test["result"] == "valid", comment=test["comment"], flags=test["flags"]))
        count += 1
assert count == wycheproof["numberOfTests"]
assert [len(output[k]) for k in ("keygen", "siggen", "verify")] == [25, 30, 225], "Review changes to pinned corpora before importing"
destination.parent.mkdir(parents=True, exist_ok=True)
destination.write_bytes(gzip.compress(json.dumps(output, sort_keys=True, separators=(",", ":")).encode(), mtime=0))
print(f"Wrote {destination}: 25 keygen, 30 siggen, 225 verification cases")
