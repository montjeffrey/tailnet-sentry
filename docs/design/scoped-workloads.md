# Design: scoped workloads and automated containment on a tailnet

Status: **draft for discussion. No code yet.**

Real device names, node IDs and role assignments belong in local configuration, never in this
document.

## The problem

[compute-pool](https://github.com/montjeffrey/compute-pool) turns the devices on a tailnet into one
pool of CPU. The reason it exists is that research and analysis work is expensive, and a single
machine is the bottleneck. The same tailnet also carries day-to-day development and automation
work, and increasingly the thing submitting jobs is an LLM agent rather than a person.

So one tailnet carries two kinds of work with very different risk. The heavy research work is
exactly the work most likely to touch something hostile. The development machines hold source code,
credentials and access to other systems. Today an allowed device can send any command to any agent,
so a job that goes wrong on one machine can reach the others.

This document is about keeping those two apart, proving that a job changed only what it said it
would, and containing a device automatically when it has not.

## The pattern: a gate, not a reviewer

The model for this is **GateGuard**, the ECC hook. Before an edit proceeds it demands a
declaration: name the importers, name the affected API, show the data schema, quote the
instruction. Two properties are worth copying exactly:

- **It is deterministic.** It does not ask a model whether an edit looks safe. It mechanically
  requires declarations and refuses until they appear. Nothing can talk it round.
- **It has an explicit, logged override** (`ECC_GATEGUARD=off`, `ECC_DISABLED_HOOKS`) rather than a
  silent bypass, or a soft warning that gets ignored.

And one property worth improving on: **GateGuard gates the declaration, not its truth.** Facts get
stated and the edit proceeds; nothing checks them. A job that declares `"network": "none"` has to
be *enforced* by the runtime and *verified* afterwards by its receipt, not believed because it was
declared. Declaration, enforcement, verification — the first on its own is theatre.

## Decision 1: two pool tiers, not one pool

An earlier draft of this design said the research machines should stay out of the pool. That was
wrong: pooling compute for that work is the whole point of the project. The answer is not to
exclude them but to give them their own tier with a different trust level.

| | **Trusted tier** | **Research tier** |
| --- | --- | --- |
| Machines | the development workstations | VMs dedicated to heavy analysis |
| Tag | user-owned, no tag | `tag:pool-research` |
| Assumption | kept clean | **assumed dirty at all times** |
| Holds credentials | yes | never |
| May submit jobs to | the research tier | nothing |
| Reachable from | the other trusted machines | only the pool port, only from the trusted tier |
| Lifetime | long | rebuilt from a pinned image on a schedule, and after any finding |
| Outputs | used directly | returned as files only, hashed, never executed on a trusted machine |

The guarantee this buys is worth stating plainly: **the research tier is not kept clean, so it does
not matter very much when it is not.** A machine that holds no credentials, can open no connection
to anything but its own pool port, and is rebuilt from a known image cannot be used as a way into
the development machines. That is a structural property of the ACL, not something a scanner has to
notice in time.

The research tier never sends jobs. One machine running a job must not be able to make another
machine run one; that is what turns a single bad job into a chain across the tailnet.

### ACL sketch

```jsonc
{
  "tagOwners": {
    "tag:pool-research": ["autogroup:admin"],
    "tag:quarantine":    ["autogroup:admin"],
  },
  "grants": [
    // trusted machines send jobs to the research tier: the pool port and nothing else
    {"src": ["autogroup:member"], "dst": ["tag:pool-research"], "ip": ["tcp:7470"]},
    // the trusted machines among themselves
    {"src": ["autogroup:member"], "dst": ["autogroup:member"], "ip": ["*"]},
    // deliberately absent: any rule whose src is tag:pool-research, tag:quarantine,
    // "*" or autogroup:tagged. A tagged device has no user identity, so the member
    // rule above stops matching it.
  ],
  "tests": [
    {"src": "tag:pool-research", "deny": ["DEV-HOST:22", "DEV-HOST:445", "DEV-HOST:7470"]},
    {"src": "tag:quarantine",    "deny": ["DEV-HOST:22", "DEV-HOST:443"]},
  ],
}
```

Replies on a connection the trusted side opened still flow, so job output streams back normally.
The `tests` block is what stops a later ACL edit from quietly reopening the path; add a line per
destination that matters, since a test only checks what it names.

**Blocker to resolve first.** compute-pool currently refuses to exchange jobs with any tagged
device (`IsOwned`, `compute-pool/internal/tsutil/tsutil.go:59`), because a tagged device has no
user identity and could otherwise pose as an idle agent. Tagging the research tier therefore
removes it from the pool today. compute-pool needs to learn that a specific operator-owned tag is
an acceptable *destination* for jobs (never a source), with the tag named explicitly in
configuration. Small change, security-sensitive, needs its own review.

### Roles, not machines

Four roles, which need not be four machines. Which device fills which role is recorded by node ID
in the local rules file and the scheduler configuration — for the same reason the README gives for
the baseline and audit files: they describe your tailnet.

| Role | What it needs | Notes |
| --- | --- | --- |
| **Main workstation** | nothing special | the busiest and most exposed; on the protect list |
| **Monitor** | always on, read-only credential | runs the scheduled scan; needs no trust beyond reporting honestly what it saw |
| **Trust anchor** | separate, trusted, used occasionally | holds the baseline pin and the narrow write credential; where a containment command is run from |
| **Research tier** | disposable | tagged, rebuilt, holds nothing |

The split between **monitor** and **trust anchor** is the useful part, and it falls out of what
each one actually needs. The scheduled scan has to run every half hour, so its host must be awake —
but it only ever reads, so a compromise of it leaks a device list and nothing more. The pin and the
write credential need real trust, but they are touched rarely and by hand. The always-on
requirement and the trust requirement therefore land on different machines, and neither machine has
to satisfy both.

A machine kept out of daily work is a good **trust anchor** for that reason: separate, lightly
exposed, and "occasionally awake" is all the role asks. If it is a laptop, it is a poor **monitor**,
because it sleeps, travels and runs on battery, and a scan that only happens when the lid is open
widens the polling gap the threat model already names.

Two conditions, or the separation decays:

- **Enforce it rather than intend it.** Keeping the anchor out of the work has to be written into
  the ACL and the pool configuration — no pool agent, no browser automation, not a job destination —
  or the machine drifts into being a second daily driver and stops being an anchor.
- **The monitor must not be a guest of the machine it watches.** A VM hosted on the main
  workstation shares that machine's fate: whoever owns the host can read the guest's disk and
  memory. Such a VM cannot monitor its host; an always-on machine elsewhere — a small box, a cheap
  cloud instance — is the better monitor.

### The protect list

Never auto-isolated: the main workstation, the trust anchor (isolating it would cut your own
ability to respond) and the sentry host (already enforced in code). Everything else is eligible,
including every unknown device.

That is less of a gap than it looks. Tier A fires on `new-device` together with
`unexpected-owner`, or on `multiple-connections` — conditions describing a machine that is not
yours in the first place, which is by definition not on a protect list of known machines. The list
stops automation from acting against the machines you depend on. It does not touch the case
automation exists for.

### Where the monitor runs

The workstation that does the browsing, the development and the agent-running is usually both the
machine that matters most and the machine most likely to be compromised first. That has a consequence the
README already half states ("Run sentry on a machine you trust"): **sentry must not run on it.**

If the monitor runs on the most exposed machine, then whoever gets in can edit the baseline and
recompute its seal, rewrite the audit log wholesale (the chain catches edits and inserts, not a
full rewrite), read the pin if it is stored there, or simply stop the scheduled scan. The baseline
seal and pin both assume the host is not the adversary.

So run sentry on the monitor: not a daily driver, no browser, nothing else on it. It needs only a
read-only credential and either `tailscaled` or API access. The baseline pin is recorded on the
trust anchor and passed to the scheduled scan through its configuration. This is independent of
everything else here and worth doing first.

### The machine that cannot be auto-isolated

Automatically isolating the main workstation is the one action whose cost can exceed the attack's,
so it goes on the protect list. But protect-listed must not mean quiet. The opposite:

- **The loudest alerting of any device**, through a channel that does not depend on that machine
  being healthy. A desktop notification on the suspect host is worth nothing.
- **A pre-staged one-line response** to run from the trust anchor, so the slow part is your
  decision rather than looking up syntax.
- **The most sensitive detection, not the least.** `identity-changed`, `client-changed` and the key
  rules matter more here than anywhere else on the tailnet.

Because containment cannot be automatic there, the compensating controls carry the weight:

| Control | Why |
| --- | --- |
| Holds no write credential | otherwise a compromise there can re-tag or deauthorize every device, including isolating *your* machines |
| Is not the sentry host | see above |
| Does not hold the baseline pin | a pin stored on the audited machine audits nothing |
| Runs no pool agent, or accepts jobs from nothing | an inbound execution path on the riskiest machine is gratuitous; it only needs to *send* |
| Any model reviewer runs on the monitor | the thing judging the alerts must not sit on the machine under suspicion |

**The attacker path this leaves open, and why it is bounded.** A compromised workstation can still
submit jobs, because submitting is its job. Those jobs land on the research tier, which holds no
credentials, can reach nothing, runs read-only from a pinned image and is rebuilt afterwards. So
the research tier has to treat requests from the trusted tier as untrusted input — which is exactly
what a declared scope enforced by the runtime already does. The architecture covers this case;
worth writing down so it stays covered on purpose rather than by luck.

**And reduce the reason it is risky in the first place.** Browser automation driven by a model
consumes untrusted web content, which is a live injection path wherever it runs. Moving that work
into the research tier — headless browser in a pinned image, no credentials, no tailnet reach,
rebuilt after — puts the most exposed activity inside the blast-radius boundary instead of leaving
it on the workstation. The same containment that protects the tailnet from research jobs protects
it from browser agents.

## Decision 2: scoped, digest-pinned jobs

Every job on the research tier declares its scope, and the agent runs it from a container image
pinned by digest. A tag is refused, because tags move.

```jsonc
{
  "image":   "ghcr.io/you/analyze@sha256:9f2c…",
  "command": ["python", "analyze.py", "data.csv"],
  "inputs":  ["data.csv"],      // mounted read-only
  "output":  "out/",            // the only writable path
  "network": "none",            // or a named peer and port, or "internet"
  "timeout": "10m",
  "requester": "workstation"    // Tailscale identity of the sender
}
```

Container digests are SHA-256 over content, so identity is free: a malware scan, a CVE scan or a
signature check attaches to a digest once and is reused by every later job on that image.

**Before the run**, the agent requires: the digest is allowlisted or signed by a trusted key; the
digest has a cached clean scan; and the run configuration is the hardened one (no privileged mode,
no host network, PID or IPC namespace, no container-runtime socket, no host path mounts, all
capabilities dropped, read-only root filesystem, non-root user, no new privileges). A request that
tries to widen any of these is refused rather than downgraded.

**After the run**, the agent diffs the container's writable layer, hashes the returned files, and
writes a **receipt**: request hash, image digest, scan id, run-config hash, network decision, diff
summary, output hashes, exit code and timings. Receipts are signed with a per-device key,
hash-chained like sentry's audit log, and shipped off the device immediately. With a read-only root
and one writable path, the expected diff is small and anything else is a finding.

**What this does and does not stop.** Digest pinning proves the image is the one approved. It says
nothing about whether an approved image, given hostile arguments, does something harmful. A
prompt-injected agent will usually submit an *approved* image with a bad command, and every hash
check passes. What bounds the damage is the scope: no network, read-only root, one writable
directory, no credentials, and an ACL that lets the machine reach nothing. Hashes establish
identity; scope limits blast radius. Scope is the more important half.

## Decision 3: what may be contained automatically

The goal is to automate containment as far as it can be automated safely. The split that makes
that possible is between a **deterministic policy** that may act, and a **model** that may only
advise.

### What kind of model may be in the decision path

An earlier draft of this document said no model may decide. That objection was aimed at a
generative model, and it is the wrong objection to
[Jev](https://github.com/browser-use/jev-ultrafast).

Jev is a judgment model rather than a language model: it takes a state block and a question, and
returns one option from a set the caller supplies, plus a confidence score. It cannot emit prose,
cannot emit a command, and cannot invent an action outside the menu it was handed. That removes the
failure this design was most worried about — attacker-controlled text talking a generative model
into an action nobody authorised. A closed option set is a far better fit for a containment gate
than a chat completion is, and at 70–500 ms per decision it is cheap enough to run on every scan.

What remains is **steering**, not reprogramming. Device names, hostnames and owner strings are
chosen by whoever controls the device, and if they reach the state block they can push the choice
toward or away from an option. The fix is cheap and nearly complete:

> **Decide only on fields the device cannot choose.** The node ID is assigned by the control plane.
> The rule IDs that fired are produced by sentry's own code. Authorization, external, expiry and
> route facts are booleans from the API. None of these are attacker-authored text. A hostname or
> device name adds nothing a containment decision needs, so it is left out of the state block
> entirely and appears only in the human-facing alert, where `report.Clean()` already handles it.

The question put to the model is then a closed one over trustworthy inputs: given this set of rules
firing on this node, is this a legitimate rebuild, an expected change, or an intrusion? The options
are ours to define — `ISOLATE`, `WATCH`, `IGNORE`, `ESCALATE`.

Two things to confirm against the model's own documentation before building on this, since the
description above comes from secondary write-ups:

- that the option set is caller-supplied per question, so a containment vocabulary can replace the
  browser one (`CLICK`, `TYPE_TEXT`, … `BLOCKED`);
- that it runs locally, so tailnet reports never leave the tailnet.

**Confidence has to be calibrated before it carries weight.** A hand-picked threshold is a guess.
Run the model across the fixture suite and a stretch of real scans, compare the confidence it
reports on right and wrong answers, and set the threshold from that curve. Until that exists, every
verdict is advisory and lands in Tier B.

### Tier A — automatic, no model involved

Isolate without asking only when **all** of these hold. Each is a cheap boolean over the existing
report, no inference anywhere:

1. The finding set includes `new-device` **and** `unexpected-owner`, or includes
   `multiple-connections`; and
2. the device is not the host sentry runs on (already enforced); and
3. the device is not on an explicit **protect list** (the development workstations, the pool
   coordinator, anything whose loss would be worse than the risk); and
4. the device is not `external` (a shared-in device cannot be tagged anyway — remove the share); and
5. the quarantine policy is live, verified by reading the ACL and confirming
   `tag:quarantine` is granted nothing and no `*` or `autogroup:tagged` source rule exists; and
6. fewer than **N** automatic isolations have happened in the last hour (default 2).

Condition 5 matters more than it looks: without the policy, tagging changes a label and nothing
else, and an automated system reporting success while changing nothing is worse than no automation.
Condition 6 is the circuit breaker — an ACL edit or an API change that suddenly makes many devices
look anomalous must stop the loop and page a human, not sweep the tailnet.

Everything Tier A does is reversible with `sentry release`, and every action is already written to
the hash-chained audit log. The log should record the automated actor by name so a later reader can
tell an automatic action from yours.

These six conditions stay in force whatever model sits in the pipeline. They guard against the
classifier being wrong for any reason — a miscalibrated threshold, a device state nobody foresaw, a
plain bug — and not only against injection. A classifier may put something *into* Tier A's queue;
it may not remove one of the conditions.

### Tier B — model-assisted, human or delayed approval

Everything else: a single `unexpected-tags`, an `identity-changed`, an `exit-node`, a drifted
client. These are where judgement actually helps and where a wrong automatic action is expensive.
The model reads the report JSON and returns a structured verdict — urgency, which rule mattered,
what it would do, what it would want to know. That verdict goes to you through the existing webhook
along with a one-line command to run. Optionally, a Tier B recommendation may escalate to automatic
after a delay you set, so an alert you never read still ends in containment.

### Credential split

Today the scheduled scan deliberately holds a read-only credential, and the write client is loaded
only when you choose to isolate. Automatic containment breaks that property if the scanner simply
gains write scope.

Keep the split: the scanner stays read-only and **emits a containment request**; a separate small
service holds the narrow write credential (`devices:core` plus `tag:quarantine` only), re-validates
the request against the live inventory and the Tier A conditions itself, and acts. It trusts the
request as a trigger, never as an argument — it looks the device up again before touching it. Then
a leak of the scanning credential still only lists devices, and the component that can change the
tailnet is small enough to read in one sitting.

### Where the reviewer runs

The reviewer runs locally, which is the point: the report never leaves the tailnet. A closed-set
judgment model gives the verdict, and a locally hosted generative model can be added where a
written explanation is wanted. Either way the reviewer runs **on the monitor**, not on the
workstation it is judging, with no shell and no credential. It is handed the sanitized state block described above and returns a verdict, which is
treated as data: it drives ordering and the text of the alert. Tier A's conditions are evaluated by
code that never reads model output at all.

## Decision 4: ephemeral workers must not drown the signal

A research tier that is rebuilt often produces a new node ID each time. Against sentry's current
rules every rebuild is a `new-device` at high severity. A report that cries wolf after every
rebuild stops being read, which costs more than it protects.

Proposal: devices carrying `tag:pool-research` are **expected but bounded**. They are exempt from
`new-device` and from `unexpected-owner` (a tagged device has no user), and they stay fully subject
to `unexpected-routes`, `exit-node`, `multiple-connections`, `key-expiry-disabled` and
`client-changed`. A research machine advertising a subnet route or offering itself as an exit node
is a strong signal and the existing rules already catch it.

Bounded means two new rules: alert if the number of devices with that tag exceeds a configured
count, and alert if one appears outside the window when rebuilds are expected. Unexplained growth
in a tier that is meant to be disposable is itself the finding.

## Evidence: benchmarks and quality gates

compute-pool already sets the standard here — a measured speedup table that includes a row showing
no benefit (0.98×), and a `pool report` finding that runs at the same load differ by up to ±12%, so
small gains cannot be claimed. The security layer gets held to the same standard, and nothing in
this document should be stated as a number until it is measured on the real machines.

**Overhead of containment.** Same workload, four ways: raw `pool run`; rootless container; container
plus a user-space kernel; and, where available, a VM boundary. Report per-job startup cost and
steady-state throughput separately, and report CPU-bound and I/O-heavy workloads separately,
because a syscall-interception layer charges almost nothing for the first and a lot for the second.
Decide the default runtime from that table, not from this paragraph.

**Overhead of the integrity checks.** First-scan cost per image digest (once per device, amortised
over every later job); post-run diff time against number of files written; receipt signing. Each
should be small; show it rather than assert it.

**Detection quality, both halves.** True positives: a fixture suite where each case is a recorded
inventory plus a receipt and the findings that must result — a device that should not be there, a
changed owner, a cloned node key, a job that wrote outside its declared output, a job that reached
a peer it did not declare, an image whose digest is not allowlisted. These run in CI off recorded
fixtures with no live tailnet, exactly as the existing tests do. False positives: a week of normal
use on the real machines, counting every finding that needed no action. A tool with a good
true-positive rate and ten false alarms a day gets ignored and protects nothing.

**State the denominator honestly.** Measured against a ±12% run-to-run spread, a containment
overhead of a few percent cannot be distinguished from noise on this hardware, and should be
reported as "not measurable here" rather than as a number.

**What cannot be benchmarked.** A detection suite measures the scenarios someone thought of. Novel
or machine-generated code that no signature covers is absent from it by construction, so the
measured true-positive rate systematically overstates real-world detection. The structural
controls — no credentials, no network, no reachability, rebuilt from a pinned image — are what hold
when detection does not, and they are the part worth investing in.

## Honest limits

- **A pinned image is not a safe image.** A digest proves it is the image you approved.
- **Containers share the host kernel.** A kernel exploit escapes a container; a VM boundary is the
  stronger line for untrusted work.
- **A compromised machine can lie in its receipts.** Signing and immediate off-device shipping
  narrow the window; the ACL limits what a lying machine can reach. Neither makes it trustworthy.
- **Automatic containment can be wrong.** Tier A is narrow, rate-limited and reversible for exactly
  this reason, and a protect list exists so that being wrong cannot take out the machines you work on.
- **compute-pool runs raw commands today.** Containerised execution is a new mode, and each
  participating machine needs a container runtime.

## Phases

0. **Measure.** Build the overhead table above on the real machines. Fix the receipt and scope
   schema. Nothing ships until the cost of the default runtime is known.
1. **Two tiers.** Teach compute-pool to accept an operator-owned tag as a job destination but never
   a source; apply the ACL with its tests; confirm from the research tier that the development
   machines are unreachable.
2. **Scope and pre-run checks.** Digest pin, signature check, scan cache, hardened run config.
3. **Post-run diff and signed receipts**, plus the sentry rules that read them.
4. **Containment.** Tier A policy with the protect list, circuit breaker and live-ACL check, behind
   the credential split; audit entries name the automated actor. Then Tier B triage and notification.
5. **Optional.** Runtime telemetry on the hosts that support it; a lateral-movement rule from
   Tailscale network flow logs, if the plan in use exposes them.

## Open questions

1. **The judgment model's option sets and local execution** — confirm both against its docs (see
   Decision 3).
2. **Where role assignments live** — the local rules file, the scheduler configuration, or a new
   file of their own.
3. **Rebuild cadence** for the research tier, so the "outside the expected window" rule has a window.
4. **Images** — your own builds (signing with your own key is then easy) or public ones?
5. **Delayed escalation** — should an unread Tier B recommendation become automatic after a timeout,
   and if so, what timeout? Note this cannot apply to the protected workstation.
