#!/usr/bin/env python3
"""Render the two-page brief and an explicitly labelled recorded-evidence walkthrough.
Optional authoring dependencies: reportlab, pypdf, Pillow, ffmpeg; video narration uses macOS say.
No authoring dependency is imported by the application or reviewer tests.
"""
from pathlib import Path
import argparse, json, re, subprocess, textwrap
from html import escape
from reportlab.pdfgen import canvas
from reportlab.lib.colors import HexColor
from reportlab.lib.styles import ParagraphStyle
from reportlab.platypus import Paragraph
from pypdf import PdfReader
from PIL import Image, ImageDraw, ImageFont

ROOT = Path(__file__).resolve().parents[1]
REPO = "https://github.com/lokendra005/KeyGuard_Devforge"
metadata=json.loads((ROOT/"docs/submission.json").read_text())
RELEASE=metadata["release"]
WALKTHROUGH_RELEASE=metadata.get("stream_release",RELEASE)
VIDEO=metadata.get("stream_url") or REPO+"/releases/download/"+RELEASE+"/keyguard-demo.mp4"
COMMIT=metadata.get("source_commit") or subprocess.check_output(["git","rev-parse","HEAD"],cwd=ROOT,text=True).strip()
TEAM=", ".join(metadata["team"])
parser = argparse.ArgumentParser(); parser.add_argument("--video", action="store_true"); args = parser.parse_args()
log = (ROOT / "evidence/demo-arm64.log").read_text()
count = int(re.search(r"tests (\d+)", log).group(1))
assert f"pass {count}" in log and "fail 0" in log and "skipped 0" in log
replica = json.loads(re.search(r"REPLICA_MEASUREMENT (\{[^\n]+\})", log).group(1))
metrics = json.loads((ROOT / "evidence/detector-holdout.json").read_text())["metrics"]
second = json.loads((ROOT / "evidence/detector-topology-holdout.json").read_text())["metrics"]
revocation = json.loads((ROOT / "evidence/revocation-100.json").read_text())
walkthrough = (ROOT / "evidence/walkthrough.log").read_text()
output = ROOT / "docs/KeyGuard-brief.pdf"
c = canvas.Canvas(str(output), pagesize=(595.28, 841.89))
c.setTitle("KeyGuard - DevForge Track 4 brief and threat model")
c.setAuthor("lokendra005")
NAVY, BLUE, GRAY = HexColor("#142a3b"), HexColor("#176b9a"), HexColor("#51616f")
style = ParagraphStyle("body", fontName="Helvetica", fontSize=10, leading=14, textColor=NAVY)
y = 795

def paragraph(text, size=10, space=8):
    global y
    s = ParagraphStyle("p", parent=style, fontSize=size, leading=size*1.4)
    p = Paragraph(text, s); _, h = p.wrap(507, 800)
    assert y-h >= 46, "PDF page overflow"
    p.drawOn(c, 44, y-h); y -= h+space

def title(text, subtitle):
    global y
    c.setFillColor(BLUE); c.rect(0, 818, 595.28, 24, fill=1, stroke=0)
    c.setFillColor(NAVY); c.setFont("Helvetica-Bold", 24); c.drawString(44, y-25, text); y -= 42
    paragraph(subtitle, 10, 12)

def section(name, text):
    paragraph("<b>"+name+"</b>", 12, 4); paragraph(text)

def footer(page):
    c.setStrokeColor(HexColor("#ccd7df")); c.line(44, 38, 551, 38)
    c.setFillColor(GRAY); c.setFont("Helvetica", 8); c.drawString(44, 25, "KeyGuard / Track 4 / "+RELEASE+" / 27 November 2026"); c.drawRightString(551, 25, str(page)+" / 2")

title("KeyGuard", "DevForge Track 4 | Team: "+escape(TEAM)+" | "+RELEASE)
paragraph("Tested source commit: <b>"+COMMIT+"</b>",8,8)
paragraph(f'<link href="{REPO}" color="#176b9a">github.com/lokendra005/KeyGuard_Devforge</link> | <link href="{REPO}/tree/{RELEASE}/evidence" color="#176b9a">Reproducible source and committed evidence</link>')
section("Purpose and distinction", "Protect files and messages when an identity key is lost, replaced or abused. Real post-quantum signing and encapsulation are combined with atomic identity lifecycle changes, two-custodian recovery and independently cached read nodes that stop authorizing after lease expiry. An explainable detector separates approved activity, suspicious role changes and connected service paths without using ML or evaluation labels.")
section("Working architecture", "Node 24.11.1 / OpenSSL 3.5.4 provides ML-DSA-65, ML-KEM-768 and SLH-DSA; messages use hybrid X25519 + ML-KEM-768. The local worker adapter, signed HTTPS API, CLI and observer dashboard share an atomic SQLite authority. Independent nodes verify signed policy-chain suffixes and snapshots, keep separate encrypted databases and enforce challenge-bound leases. Sender and receiver encrypt/decrypt locally; the relay holds ciphertext only.")
for i, (head, detail) in enumerate([("Identity", "Epoch + nonce + expiry"), ("Authority", "Atomic policy + audit"), ("Read nodes", "Pinned chain + leases")]):
    x=44+i*173; c.setFillColor(HexColor("#eef4f7")); c.roundRect(x,y-51,161,48,5,fill=1,stroke=0)
    c.setFillColor(NAVY); c.setFont("Helvetica-Bold",10); c.drawString(x+10,y-20,head)
    c.setFont("Helvetica",8); c.drawString(x+10,y-36,detail)
y-=64
section("Measured outcomes", f"Offline Linux ARM64 and AMD64: <b>{count}/{count} tests</b>, no failures/skips; <b>225/225</b> independent signature vectors on each. Public organizer validator: 22 passing records; independent Python oracle: 16 successful KEM exchanges. The suite includes an actual SIGKILL, corrupted backups, stale/replayed grants, forged-request floods and real CLI file delivery.")
paragraph(f"Revocation on five replicas, {revocation['revocations']} revocations / {revocation['observations']} node observations (sync {revocation['sync_interval_ms']} ms, lease {revocation['lease_ms']} ms): stolen-key requests rejected after p50 <b>{revocation['p50_ms']} ms</b>, p99 <b>{revocation['p99_ms']} ms</b>, max {revocation['max_ms']} ms. Every revoke reports when it holds on all nodes (bound {revocation['max_reported_replica_grace_ms']} ms). Partitioned nodes ({replica['lease_ms']} ms lease, 5 processes): max {replica['max_ms']} ms.")
paragraph(f"<b>Original holdout:</b> 4,000 reference / 12,000 evaluation; F1 {metrics['f1']:.4f}; TP {metrics['tp']}, FP {metrics['fp']}, FN {metrics['fn']}; median alert delay {metrics['median_alert_latency_ms']/1000:.2f} s; {metrics['false_alerted_events_per_1000_benign']:.2f} false-alerted events per 1,000 benign.",9,5)
paragraph(f"<b>Independent topology holdout:</b> 3,600 reference / 13,200 evaluation; F1 {second['f1']:.4f}; TP {second['tp']}, FP {second['fp']}, FN {second['fn']}; median delay {second['median_alert_latency_ms']/1000:.2f} s; {second['false_alerted_events_per_1000_benign']:.2f} false-alerted events per 1,000 benign. <b>Organizer practice set:</b> all 5 labelled findings alerted, 0 false alerts. Cross-identity pivots catch credential hopping; malformed or conflicting records are quarantined, not fatal; one identity with 100k unusual edges is analysed in ~1.3 s. Synthetic results are not production or hidden-test scores.",9,5)
section("Run and fallback video", "Run <b>./scripts/demo.sh</b> with Node 24.11.1, or <b>./scripts/demo.sh --docker</b> from the offline reviewer bundle. The executable map covers all 12 goals and explicitly reports unsupported resumption.")
paragraph(f'<b>Five-minute video (300 seconds):</b> <link href="{VIDEO}" color="#176b9a">Watch the {WALKTHROUGH_RELEASE} walkthrough</link><br/>5-minute demo of the review-v8 system, matching the measurements above (Google Drive folder, viewable by anyone with the link). No API key is needed.',9)
footer(1); c.showPage(); y=795

title("Threat model", "One-page scope, defenses and assumptions - implementation evidence, not certification")
section("Assets and adversaries", "Assets are file confidentiality/integrity, identity keys and epochs, current authorization policy, audit provenance, recovery state and service availability. Adversaries include unauthenticated callers, holders of stolen user keys, replaying/delaying network peers, a compromised ciphertext relay and an attacker who obtains a database-only copy. A fully compromised authority or read-node host has stronger access and is outside the confidentiality/authorization guarantee.")
section("Trust boundaries", "The organizer worker is a trusted local actor-assertion boundary; it is never an unsigned HTTP API. Network actions require key-possession proofs and current policy. Two distinct custodians from independent enrollment lineages authorize recovery (one admin cannot enroll a puppet second approver); the second approval rechecks the first. Replica sync exports plaintext only to a caller holding the replicator credential <i>and</i> the bound node private key, which signs every request with a monotonic counter; each export is audited. Admin credentials can acquire all plaintext through audited ownership changes but cannot call sync. Node hosts are trusted. TLS and pinned authority keys protect sync; separately pinned peer keys authenticate message endpoints. External audit checkpoints must be held independently of backups.")
section("Defenses and conditional arguments", "Post-signature attacks on the system (revoked key, stale epoch, signed replay) become bounded signed alerts naming identity, key, node and event, and revoke that actor's sessions. ML-DSA commands bind version, authority, actor, epoch, nonce, expiry and body; strict JSON rejects duplicate fields. Authentication, effect and signed audit commit together. Revocation cannot be blocked by the soft audit budget; rejected requests use bounded minute counters. Rotation preserves partial transfers only until old-key cutoff. One-use ephemeral ML-KEM keys, transcript-bound HKDF-SHA384 and AES-256-GCM protect complete messages; replay, recipient substitution, altered chunks and expired offers fail. A signed SHA-384 chain, an RFC 9162 Merkle tree (inclusion proof on every audit answer) with ML-DSA + SLH-DSA signed tree heads, plus an external retained checkpoint detect edits or restoring an older known prefix.")
paragraph("A node's lease begins at challenge send time, not response receipt. Any stale-policy grant predates revocation; a node denies after <b>L/(1-rho)</b> real time if its monotonic clock advances at rate at least <b>1-rho</b>, and revoke returns that instant as <b>effective_everywhere_at</b>. Fresh sync includes revocation; a partition expires closed. This bounds new authorization/response queueing, not arrival of already buffered data. Restart requires fresh sync. Delay/partition tests and deterministic cutoff tests exercise these cases; there is no claim of Byzantine consensus.")
section("Assumptions and exclusions", "Assume standard primitive security, trusted runtimes/authority and node hosts, correct local SQLite durability, independent key/checkpoint custody, and a monotonic clock that progresses through suspension at the specified rate. <b>master.key lives beside its database</b>: at-rest encryption does not protect theft of the whole directory. JavaScript/native memory erasure is not proven; forward secrecy assumes ephemeral-key disposal and uncompromised endpoints during exchange. Whole-host rollback without an external anchor, arbitrary network filesystems and unbounded DDoS are excluded.")
paragraph("Session resumption and a Double Ratchet/PQXDH are intentionally absent: each message uses a fresh one-time hybrid offer, so there is no post-compromise healing inside a session. Nodes trade availability for bounded stale authorization. Detection relies on reviewed reference data and trusted timing/context; isolated stolen-credential access and hops spaced beyond the 30-minute window remain blind spots. Input/storage/backup budgets are explicit; physical disk failure can prevent any durable write. Synthetic data, public vectors and local tests do not establish production accuracy, FIPS certification, universal formal verification.",9.5)
footer(2); c.save()
assert len(PdfReader(str(output)).pages)==2
print("Wrote verified two-page PDF:",output)
if not args.video: raise SystemExit(0)

stage=ROOT/".cache/video-review"; stage.mkdir(parents=True,exist_ok=True)
font_path="/System/Library/Fonts/Menlo.ttc"
font=lambda size:ImageFont.truetype(font_path,size)

def excerpts(pattern, limit=6):
    rows=[line.strip() for line in log.splitlines() if re.search(pattern,line)]
    assert rows, pattern
    return "\n".join(rows[:limit])

chapters=[
("Working system, reproducible evidence", "A recorded-evidence walkthrough, not staged UI output.", walkthrough.split("setup (")[0]+"\n"+excerpts(r"tests \d+|pass \d+|fail 0|skipped 0"), "This is KeyGuard for DevForge Track Four. This narrated walkthrough uses actual recorded adapter and test output. The source, run scripts and evidence are available in the repository. The system uses real post quantum cryptography, not mocked signatures or a dataset classifier. Runtime decisions use registered identities, current policy and cryptographic verification."),
("Owner access and scenario isolation", "Fresh identities and resources are generated on each run.", "\n".join(walkthrough.splitlines()[2:9])+"\n\n"+"\n".join(walkthrough.splitlines()[-8:]), "The real process per request adapter initializes a scenario, allows its owner to read and denies access after revocation. A second trusted setup replaces scenario tables in one transaction. Invalid replacement rolls back. Production initialization remains separate and refuses to overwrite an authority. Expected policy errors return structured JSON without pretending the process crashed."),
("Real protected reads", "Native KEM + exact organizer proof, independently checked.", excerpts(r"ML-KEM protected|independent NIST/Wycheproof")+"\n\n"+(ROOT/"evidence/pqcrypto-linux.log").read_text(), "Protected reads use real M L KEM seven sixty eight encapsulation. The proof is the exact organizer specified HMAC over the challenge concatenated with stored content. An independent Python implementation generated sixteen keys, decapsulated the actual Linux adapter responses and recomputed the proofs. Signature verification also passes two hundred twenty five pinned independent vectors."),
("Signed rotation and recovery", "Epoch, nonce, expiry and proof of the replacement key.", excerpts(r"rotation|recovery|partial transfers",8), "Network commands bind the authority, destination audience, actor, key fingerprint, epoch, nonce, expiry and operation. Rotation verifies possession of the replacement key and commits the cutoff atomically. In flight transfers continue only during the old key's valid grace period. Two distinct custodians approve loss recovery, and stale approvers or competing proposals fail."),
("Independent nodes, bounded stale access", "Five processes, five encrypted databases; two partitions.", json.dumps(replica,indent=2)[:0]+"100 revocations x 5 replicas (stolen key, old epoch):\n"+"\n".join(f"{k}: {revocation[k]}" for k in ["observations","p50_ms","p95_ms","p99_ms","max_ms","max_reported_replica_grace_ms"])+"\n\npartition run, lease_ms "+str(replica['lease_ms'])+":\n"+"\n".join(f"node {r['node']} | {r['reason']} | observed {r['observed_ms']} ms" for r in replica['observations']), "Each node keeps an encrypted cache and signed policy chain. A sync needs the replicator credential and a signature from the node's own key, so a stolen credential cannot export. Across one hundred revocations, a stolen key stops working on every node within about one second. Each revoke reports when it holds everywhere. Partitioned nodes expire closed."),
("Crash safety and audit availability", "Security controls remain possible at the soft audit budget.", excerpts(r"SIGKILL|crash|forged requests|forged HTTP|capacity|scenario",7), "The suite actually kills a process during an uncommitted rotation and checks recovery. Authentication, effects and signed audit records share a transaction. Forged requests now update bounded minute counters instead of filling the signed log. Reaching the normal audit budget cannot block revocation or recovery. Physical disk failure remains a real limit to durable commits."),
("Backups and signed history", "Rollback detection needs an independently retained checkpoint.", excerpts(r"backup|signed audit|checkpoint|correlation",7), "File contents and identity backups are encrypted. Signed SHA three eighty four audit chains preserve record boundaries and correlation history. A trusted checkpoint detects an older restored backup. Cold startup verifies a signed saved checkpoint and checks only newer links; full exported history can be checked independently. Master keys are beside the database, so encryption protects database only leaks, not an entire compromised host."),
("Encrypted client delivery", "Only complete, authenticated plaintext is released.", excerpts(r"CLI sender|one-time KEM|recipient, sender|bounded loss|relay stores|chunk boundaries",6), "The recipient signs a one use ephemeral key offer bound to both peers. The sender encapsulates, derives a transcript bound key and encrypts locally. The relay stores ciphertext. Reordered and duplicate chunks are handled, conflicting or modified chunks fail, and incomplete messages expire. Real CLI processes transfer a file and acknowledge it. Session resumption is deliberately unsupported."),
("Detection beyond the practice set", "Frozen reference + held-out events; renamed services and actions.", json.dumps({k:metrics[k] for k in ["tp","fp","fn","tn","f1","median_alert_latency_ms","false_alerted_events_per_1000_benign"]},indent=2), "Both holdouts use separate reference and evaluation windows, and their scores are unchanged. On the organizer practice set, all five labelled findings alert, with no false alerts. Credential hopping across identities is detected. Labels only enter scoring. Synthetic accuracy is not a production guarantee."),
("Input diversity and realistic limits", "Timezone offsets, sub-millisecond input, late arrival and decoys.", excerpts(r"RFC3339|frozen reference|12,000|ten thousand|regrant|clock normalization",7), "Input accepts timezone offsets and fractional seconds. A malformed or conflicting record is quarantined, not fatal. Unknown outcomes on role changes fail closed. One identity with a hundred thousand unusual edges is analysed in about a second. Benign three-edge fan-out can still alert, and hops more than thirty minutes apart are missed."),
("Offline deployment and clean checkout", "Built image, real TLS, committed logs and no API keys.", (ROOT/"evidence/tls.log").read_text()+"\n"+excerpts(r"tests \d+|pass \d+|fail 0|skipped 0"), "The root Docker build works from source without prebuilt local binaries. Offline review includes both Linux architectures and pinned runtime images. Tests run unprivileged, with network access disabled and read only source. Real TLS trust and plaintext refusal are checked. The dashboard requires an observer token; identity metadata now requires proof of key possession."),
("Reproduce and inspect the boundaries", "Every claimed result has a script or committed evidence.", "./scripts/install-node.sh\n./scripts/demo.sh\n\nOffline bundle:\n./scripts/demo.sh --docker\n\nSource and evidence:\ngithub.com/lokendra005/KeyGuard_Devforge\n\nLimits: no session resumption, no independent audit,\nno hidden-test score or production-accuracy claim.", "Run the demo script to reproduce the adapter, crypto, lifecycle, messaging, detection and independent node checks. The two page brief links this video and states the threat model. This is executable evidence under explicit assumptions, not universal formal verification. Review the known detector misses, memory disposal assumption, lease clock requirement and absence of session resumption before deploying."),
]
assert len(chapters)==12
script=[]; images=[]; audios=[]
for i,(heading,subtitle,output_text,narration) in enumerate(chapters):
    image=Image.new("RGB",(1280,720),"#101d2a"); d=ImageDraw.Draw(image)
    d.rectangle((0,0,1280,8),fill="#55c5de")
    d.text((48,32),f"KEYGUARD   /   TRACK 4   /   {i+1:02d} OF 12",font=font(18),fill="#77d1e6")
    d.text((48,86),heading,font=font(30),fill="#f0f6fb")
    d.text((48,137),subtitle,font=font(19),fill="#a7bacc")
    d.rounded_rectangle((40,190,1240,646),radius=12,fill="#182a3b",outline="#334d61")
    lines=[]
    for line in output_text.splitlines(): lines += textwrap.wrap(line,width=91,replace_whitespace=False,drop_whitespace=False) or [""]
    if len(lines)>18: lines=lines[:17]+["[excerpt; complete output is committed under evidence/]"]
    for j,line in enumerate(lines): d.text((60,210+j*22),line,font=font(19),fill="#d7e5ef")
    d.text((48,676),"Recorded evidence + explanatory narration | Synthetic fixtures, no operator data",font=font(15),fill="#90aabe")
    img=stage/f"scene-{i:02d}.png"; image.save(img); images.append(img)
    txt=stage/f"scene-{i:02d}.txt"; txt.write_text(narration)
    speech=stage/f"scene-{i:02d}.aiff"
    for rate in [175,190,205]:
        subprocess.run(["/usr/bin/say","-v","Samantha (English (US))","-r",str(rate),"-f",str(txt),"-o",str(speech)],check=True)
        duration=float(subprocess.check_output(["ffprobe","-v","error","-show_entries","format=duration","-of","default=noprint_wrappers=1:nokey=1",str(speech)],text=True))
        if duration<=24.5: break
    assert duration<=24.5,(i,duration)
    wav=stage/f"scene-{i:02d}.wav"
    subprocess.run(["ffmpeg","-v","error","-y","-i",str(speech),"-af","apad","-t","25","-ar","24000","-ac","1",str(wav)],check=True)
    audios.append(wav); script.append({"start_seconds":i*25,"duration_seconds":25,"title":heading,"narration":narration,"evidence_excerpt":output_text})
    print("Rendered chapter",i+1,flush=True)
(ROOT/"docs/video-script.json").write_text(json.dumps(script,indent=2)+"\n")
video_list=stage/"images.txt"; video_list.write_text("".join(f"file '{p}'\nduration 25\n" for p in images)+f"file '{images[-1]}'\n")
audio_list=stage/"audio.txt"; audio_list.write_text("".join(f"file '{p}'\n" for p in audios))
video=ROOT/"dist/keyguard-demo.mp4";video.parent.mkdir(exist_ok=True)
subprocess.run(["ffmpeg","-v","error","-y","-f","concat","-safe","0","-i",str(video_list),"-f","concat","-safe","0","-i",str(audio_list),"-t","300","-vf","fps=12,format=yuv420p","-c:v","libx264","-preset","fast","-crf","23","-c:a","aac","-b:a","96k","-movflags","+faststart",str(video)],check=True)
probe=json.loads(subprocess.check_output(["ffprobe","-v","error","-show_format","-show_streams","-of","json",str(video)],text=True))
assert abs(float(probe['format']['duration'])-300)<0.1
assert {s['codec_type'] for s in probe['streams']}=={'video','audio'}
(ROOT/"evidence/video-validation.json").write_text(json.dumps({"duration_seconds":float(probe['format']['duration']),"width":1280,"height":720,"chapters":12,"narration":"Local system TTS; no voice cloning","content":"Actual recorded adapter/test evidence excerpts with authored explanations, not a real-time screen recording."},indent=2)+"\n")
print("Wrote",video,flush=True)
