# Alternative Isolation Designs for AI Agents

This document surveys the isolation designs that compete with fastenv's
architecture, explains what each one optimizes for, and states plainly where
fastenv's choice — a **Firecracker microVM per project, with `crun` containers
per agent inside it** — wins and where it does not.

The canonical requirements that this comparison is judged against live in
[prd.md](prd.md) and [architecture.md](architecture.md). The short version of
the workload we are isolating:

- Many semi-untrusted commands per agent (installers, builds, tests, generated
  scripts, shell from prompts).
- Heavy **fan-out**: multiple concurrent agents per project, created and torn
  down inside interactive loops.
- A clear **trust domain** per project (repo / tenant / org), which is coarser
  than the per-agent unit of work.
- A host that must never run project code directly and must receive only
  validated outputs.

Two axes matter throughout: **boundary strength** (can a compromised guest
reach the host or a neighboring tenant?) and **fan-out cost** (how cheap is it
to start/stop the Nth unit of work?). Most designs trade one for the other.
fastenv's thesis is that these two axes belong to *different layers* — so you
should not pay for them with a single mechanism.

---

## The competing designs

### A. Plain host containers (Docker / Podman / `crun` on the host)

One namespace+cgroup sandbox per agent, sharing the host kernel directly.

- **Boundary strength:** weak for untrusted code. A container escape (kernel
  LPE, misconfigured capability, shared `/proc` or socket) lands directly on
  the host and therefore on every other tenant's work. The shared kernel is the
  entire attack surface.
- **Fan-out cost:** excellent — tens of milliseconds to start, overlayfs CoW,
  trivial teardown.
- **Verdict for our use case:** this is exactly the boundary the PRD names as a
  **non-goal** ("treating host containers as the security boundary for
  untrusted projects"). Great fan-out, wrong trust boundary. fastenv keeps this
  mechanism but moves it *inside* the VM, where a shared kernel is acceptable
  because the tenant is already isolated by the VM.

### B. gVisor (`runsc`) — userspace kernel

A user-space kernel intercepts guest syscalls so the host kernel sees a much
narrower surface.

- **Boundary strength:** stronger than plain containers — the host kernel is no
  longer directly reachable for most syscalls. But the sandbox is still a host
  *process*, and the security argument rests on the correctness of a large
  syscall-emulation layer rather than a hardware boundary.
- **Fan-out cost:** good, though syscall interception imposes a real per-call
  performance tax that bites hard on build/test workloads (lots of `fork`,
  `stat`, I/O — precisely what agents do).
- **Verdict:** a reasonable middle point, but it taxes the exact syscall-heavy
  workloads agents run, and it raises the boundary on the *per-agent* unit
  rather than on the *project* trust domain. We would still need a separate
  answer for cheap intra-project fan-out.

### C. Kata Containers — a VM behind every OCI container

Each OCI container is transparently backed by its own lightweight VM.

- **Boundary strength:** strong — a real hardware/VM boundary per container.
- **Fan-out cost:** every agent pays full VM provisioning (kernel boot, device
  setup, guest agent handshake). This is VM cost on the *per-agent* axis, which
  is the axis we most want to keep cheap.
- **Verdict:** Kata puts the strong boundary in the right place but at the wrong
  *granularity* for fan-out. It is essentially "design D below, per agent." It
  is the closest philosophical cousin to fastenv and the clearest illustration
  of our core bet: agents within one project share a trust domain, so paying a
  VM boot per agent is wasted money.

### D. One Firecracker microVM per agent / task

The "serverless sandbox" pattern (the shape used by several hosted code-exec
products): a fresh microVM per unit of work.

- **Boundary strength:** strong and uniform — every task gets a hardware
  boundary.
- **Fan-out cost:** Firecracker boots fast (~125ms) but still far slower than a
  container, and each VM carries its own kernel, memory floor, rootfs, and
  device model. Ten agents on one repo means ten kernels and ten copies of the
  project's caches/objects — or a shared cache that quietly re-introduces a
  cross-tenant writable surface.
- **Verdict:** over-isolates *within* a project. Agents on the same repo do not
  need to be protected from each other at hardware strength — they need
  workspace isolation so they "don't stomp on each other" (PRD §7), which a
  container delivers for far less. Per-agent VMs also fragment the project-local
  cache the PRD wants to keep warm and shared-read-only within the trust domain.

### E. One giant shared VM (or bare host) for everything

All projects and agents in a single long-lived VM or directly on a build host,
separated only by users/namespaces.

- **Boundary strength:** weak across tenants — one guest kernel shared by all
  trust domains.
- **Fan-out cost:** excellent.
- **Verdict:** an explicit PRD **non-goal** ("one giant VM shared by all
  projects"). Cheapest possible fan-out, no project boundary. Rejected.

### F. Process-level sandboxes (seccomp-bpf + namespaces + `chroot`/Landlock)

Hand-rolled or library sandboxes (bubblewrap, raw seccomp profiles, Landlock)
with no container runtime and no VM.

- **Boundary strength:** weak-to-medium and *fragile*. Security depends on a
  hand-maintained syscall allowlist; one missing filter or a kernel bug breaks
  it. Shares the host kernel.
- **Fan-out cost:** excellent — lightest possible.
- **Verdict:** the PRD explicitly refuses to make a filtering layer the primary
  boundary ("Using eBPF as the primary isolation boundary" is a non-goal; the
  same logic applies to seccomp). Useful as defense-in-depth *inside* a layer,
  never as the layer itself.

#### Deep dive: Landlock

Landlock deserves a closer look because it is the most modern and most
promising member of design F, and because it is the mechanism people most often
reach for when they want "a sandbox without root or a container runtime." It is
an unprivileged Linux Security Module (LSM), available since kernel 5.13, that
lets a process restrict *itself* and its future children. A launcher builds a
ruleset (`landlock_create_ruleset`), grants specific access rights to specific
resources (`landlock_add_rule`), then locks it in (`landlock_restrict_self`)
before `exec`-ing the untrusted program.

**What is genuinely great about it:**

- **Unprivileged self-sandboxing.** No root, no `CAP_SYS_ADMIN`, no setuid
  helper, no daemon. Any process can drop into a tighter sandbox on its own.
  This is the headline feature and the reason it is attractive for embedding
  directly in an agent launcher.
- **Monotonic and stackable.** Restrictions only ever *tighten*. A child can add
  more rules but can never loosen what a parent applied, and rulesets compose by
  stacking. A trusted launcher can drop privileges in stages, and untrusted code
  downstream physically cannot climb back out.
- **Semantically aware, not string-matched.** Landlock mediates at LSM hooks on
  the opened inode hierarchy, not by matching path *strings* or raw syscall
  arguments. That sidesteps the classic TOCTOU and path-canonicalization
  footguns that make hand-rolled seccomp path filtering so error-prone.
- **Cheap.** It is in-kernel hook enforcement — none of gVisor's per-syscall
  emulation tax. Effectively free on the hot path.
- **Graceful degradation by design.** The ABI is versioned and queryable, so a
  launcher can apply the strongest policy the running kernel supports and skip
  rules it doesn't. (This is also a liability — see below.)

**Why it is not enough against adversarial or incompetent AI agents:**

1. **It shares the host kernel — so it is not a boundary against a kernel
   exploit.** Landlock is an LSM running in the *same* kernel as the sandboxed
   code. A single kernel LPE bypasses it entirely. This matters more for AI
   agents than for almost any other workload: an agent legitimately runs
   compilers, JITs, package installers, `io_uring`, and arbitrary downloaded
   binaries — an enormous and unpredictable kernel-surface to fish for a bug in.
   This is the same structural ceiling as seccomp and eBPF, which the PRD names
   a non-goal as a *primary* boundary, and exactly the gap the Firecracker layer
   exists to close.

2. **It only mediates the operation classes it has hooks for; everything else
   is unrestricted by default.** Landlock is allowlist-style *within* a covered
   class, but anything outside a covered class is wide open. Coverage grew one
   kernel at a time: filesystem rights in 5.13, file reparenting in 5.19,
   truncate in 6.2, **TCP bind/connect only** in 6.7, device `ioctl` in 6.10,
   abstract-socket and signal scoping in 6.12. Notably it does **not** gate UDP,
   raw/packet sockets, most syscalls (`ptrace`, `bpf`, `keyctl`, clone flags,
   etc.), or resource use. An agent doing DNS-based exfiltration or UDP C2 walks
   straight through the network rules; a fork bomb or a disk-filler is not even
   in scope. To get container-class confinement you must still stack seccomp +
   namespaces + cgroups around it — at which point you have rebuilt a container,
   still on the shared host kernel.

3. **A missing hook fails *open*, not closed.** Because uncovered classes are
   unrestricted, a gap in coverage is silent permissiveness, not a denial. An
   adversarial agent only has to find the one thing your policy never mentioned.

4. **Kernel-version fragility makes the policy silently weaker than you think.**
   The same launcher code yields a strong sandbox on a 6.12 host and a
   filesystem-only sandbox on a 6.2 host — the network rules simply don't exist
   there. In a heterogeneous fleet, "best-effort" ABI negotiation means your
   egress restriction can quietly evaporate on an older kernel while the code
   reports success. That is a dangerous failure mode for hostile code.

5. **It is a self-imposed sandbox, so it is only as good as the launcher — and
   AI is writing the launcher.** The security depends entirely on the launcher
   building the ruleset correctly and calling `restrict_self` *before* handing
   control to untrusted code. There is no second line of defense if it forgets a
   `restrict_self`, grants an over-broad directory hierarchy, or starts the
   agent on the wrong side of the lock. For the "incompetent agent" case this is
   the crux: agent-generated or agent-modified harness code can get this subtly
   wrong, and the failure is invisible until exploited. fastenv's model
   deliberately does not let the thing being sandboxed (or code it influenced)
   own its own boundary.

6. **It provides none of the fan-out workspace isolation the PRD requires.**
   Landlock is about *access rights*, not *resource partitioning*. It gives no
   private PID namespace, no private mount view or per-agent `/tmp`, no
   CPU/memory/PID limits, no CoW workspace. The requirement that "agents don't
   stomp on each other" (PRD §4.3, §7) is entirely unmet by Landlock alone —
   that is namespaces + overlayfs + cgroups, i.e. the `crun` container layer.

7. **A *useful* agent policy is necessarily a permissive one.** Agents must read
   most of `/usr`, write build and cache dirs, `exec` arbitrary toolchain and
   downloaded binaries, and reach package mirrors over TCP. A Landlock policy
   broad enough to let real dev work happen ends up granting most of what an
   attacker wants anyway. The more useful the sandbox, the less the sandbox is
   buying you.

**Where Landlock fits in fastenv.** None of this makes Landlock useless — it
makes it a *defense-in-depth layer*, not a boundary, which is precisely the role
the PRD assigns to filtering planes ("eBPF observes and constrains, but does not
replace the VM boundary"). The right place for Landlock in this architecture is
*inside* the `crun` container, *inside* the project VM: a cheap extra rail that
narrows a specific agent run's filesystem and TCP reach below what the container
already allows. If it is misconfigured or the kernel is too old, the container
and the VM are still there. As the *outermost* answer to adversarial or
incompetent AI agents, it fails for the structural reason that it shares the
host kernel and only sees the operations it has hooks for — and AI agents
present an unusually large, unpredictable, and self-modifying surface against
both of those limits.

### G. Remote / hosted sandbox services (e2b, Modal, Daytona-style)

Outsource isolation to a third-party code-execution API.

- **Boundary strength:** typically strong (most are microVM-backed internally),
  but you inherit *their* trust model, network egress posture, and secret
  handling — and project code leaves your infrastructure.
- **Fan-out cost:** good, but gated by network round-trips and provisioning
  APIs, not local primitives. Interactive loops feel the latency.
- **Verdict:** orthogonal to fastenv's goal. fastenv is the *substrate* that a
  control plane owns and instruments (host eBPF, artifact validation, secret
  brokering). Handing that to a remote service forfeits the host-owned policy
  plane the PRD requires and the local-loop latency the success criteria
  demand.

### H. Capability-based microkernel OS (Fuchsia / Zircon)

A different kernel entirely. **Fuchsia** is Google's non-Linux OS; its
microkernel, **Zircon**, keeps almost nothing in kernel space — scheduling,
memory, and IPC only — and pushes drivers, filesystems, and network stacks out
into user-space processes. Isolation is not bolted on with namespaces and
filters; it is the kernel's native model. Every kernel resource is an *object*
reached only through an explicit, unforgeable **handle**, and a process can act
only on the handles it has been granted (object-capability security). There is
no ambient authority and no global namespace to escape into — the structural
opposite of the Unix "a process can touch anything its UID permits" model that
designs A–G all inherit.

- **Boundary strength:** strong *by construction* on a different dimension than
  the others. Where designs A/F narrow a huge ambient-authority surface with
  allowlists, and C/D wrap a hardware wall around a Linux guest, Zircon starts
  from zero authority and adds capabilities explicitly. The kernel attack
  surface is small (a microkernel exposes a few dozen syscalls, not Linux's
  ~400), and a compromised driver or network stack is "just" a user process
  holding a bounded set of handles, not kernel-resident code. This is the
  cleanest *design* answer to the exact thing the Landlock deep dive flags as
  Linux's structural ceiling: a sprawling, fail-open kernel surface that an
  agent running compilers, JITs, and downloaded binaries is unusually good at
  fishing for bugs in.
- **Fan-out cost:** in principle excellent — capability handoff and process
  spawn are cheap primitives, with no VM boot and no per-syscall emulation tax.
  In practice unknown for this workload: there is no mature container/overlayfs
  fan-out ecosystem, no `crun`/Firecracker-equivalent fleet tooling, and no
  warm project-cache story comparable to what the PRD assumes.
- **Verdict:** **aspirational and orthogonal, not deployable as fastenv's
  substrate today.** The disqualifier is not the security model — that model is
  arguably *better* than anything in A–G — it is the workload. Agents run Linux
  toolchains: `apt`/`pip`/`cargo`, prebuilt `x86_64` ELF binaries, `io_uring`,
  CUDA, the whole Linux userland. Fuchsia runs Linux binaries only through
  **Starnix**, a Linux-syscall compatibility layer that is young, partial, and
  itself re-imports a large Linux-shaped surface — so you would be betting the
  isolation story on an emulation layer (gVisor's structural weakness, design B)
  on top of an OS with a fraction of Linux's hardware, toolchain, and operational
  support. fastenv's bet is on **boundary placement on commodity Linux + KVM**
  (a hardware wall at the project, a cheap namespace wall at the agent), not on
  switching the kernel underneath the entire fleet. Zircon is the useful
  *north-star*: it shows what "isolation as the kernel's native model" looks
  like, and it validates fastenv's instinct that the shared Linux kernel — not
  the choice of container vs. VM — is the real ceiling. But adopting it would
  mean giving up the Linux toolchain compatibility the workload is defined by,
  which is a non-starter, not a tuning decision.

#### Deep dive: the wider microkernel field

Zircon is not the only kernel that treats isolation as a first-class primitive.
Each of the projects below is disqualified as fastenv's *substrate* by the same
two facts that sink Fuchsia — no native Linux toolchain, no proven high-fan-out
fleet ecosystem — so this is not a shortlist of replacements. It is a list of
*ideas*, each of which isolates one thing fastenv's Linux-based design either
borrows already or could borrow later. They are grouped by what they contribute.

**Formal verification of the boundary — seL4.** The high-assurance member of the
L4 family: a capability-based microkernel (~10k LOC) with machine-checked proofs
that the implementation matches its spec *and* that the spec enforces integrity
and confidentiality. No Linux mechanism — namespaces, seccomp, Landlock, KVM —
has anything close to a proof of its isolation. seL4 also runs as a **hypervisor**
(via a VMM component / the seL4 Microkit), so the realistic way to run Linux
agents on it is *as a guest VM on a verified hypervisor* — which lands you back
at a VM boundary, just with a far smaller, proven TCB underneath it instead of
KVM+QEMU. That is the single most interesting long-horizon idea here: it attacks
the exact gap the Landlock dive names (an unprovable, sprawling kernel surface)
not by shrinking Linux but by shrinking and *proving* the thing that contains it.

**Hierarchical capability delegation — Genode.** Not one kernel but an OS
framework that runs atop a choice of kernels (seL4, NOVA, Fiasco.OC, or even
Linux as a base platform). Its defining abstraction is a **recursive system
structure**: every component is a child sandbox created by a parent that
explicitly hands down a bounded budget of capabilities and resources (RAM,
caps, CPU), and a child can only ever sub-delegate, never widen, what it was
given. That is, almost line for line, fastenv's host→project→agent policy
hierarchy (PRD §4.6) and Landlock's monotonic-tightening property generalized to
the whole OS. Genode is the strongest *conceptual* match in this document for
fastenv's "different boundaries at different layers, each narrowing the last"
thesis — it is what that thesis looks like when the kernel, not a stack of Linux
mechanisms, enforces it.

**Shrinking the VMM/hypervisor TCB — NOVA (and Hedron/Bedrock).** A
*microhypervisor*: microkernel minimality applied to virtualization, so the
trusted code that stands between guests is a few thousand lines rather than a
general-purpose kernel plus QEMU. This is the same instinct as fastenv's
"wrap the VMM itself in seccomp" posture (see the seccomp section), taken to its
logical end — make the enforcer small enough to audit (or, with seL4, prove)
rather than merely confining a large one after the fact. The most plausible
future where a microkernel touches fastenv is here: a verified/minimal
microhypervisor replacing KVM+Firecracker under the *project* boundary, with the
agent-container layer unchanged on top.

**Memory-safe kernels — Redox OS.** A Unix-like microkernel written in Rust,
with a scheme/URL-based resource model that is capability-flavored. Its
relevance is narrow but pointed: a memory-safe kernel structurally removes a
large share of the kernel-LPE bug class that the Landlock dive treats as Linux's
unavoidable ceiling. It is hobbyist-scale today, with only partial Linux
compatibility (relibc), so it is an existence proof of the idea, not a platform —
but "the kernel itself can't be memory-corrupted" is exactly the property a
shared-kernel agent layer most wishes it had.

**Mature, shipping microkernels — QNX and HarmonyOS/HongMeng.** Proof that
capability/message-passing microkernels ship at industrial scale: **QNX** is a
POSIX-compliant commercial RTOS in cars, medical, and industrial control;
Huawei's **HongMeng** microkernel (HarmonyOS NEXT) is a capability-based kernel
with formally verified components shipping on consumer devices. Both rebut "micro­
kernels are only research toys." Neither fits us: QNX is tuned for real-time
embedded determinism and is closed/commercially licensed, not multi-tenant
server fan-out; HongMeng is a closed, vertically integrated ecosystem. They
inform the *feasibility* argument, not the substrate choice.

**Reliability-oriented microkernels — MINIX 3 (and the Mach/Hurd lineage).**
MINIX 3 isolates drivers in user space behind a *reincarnation server* that
restarts crashed components — a fault-isolation story, closer to "a buggy
component can't take down the system" than to "adversarial code can't escape."
Useful framing for the *incompetent-agent* half of the threat model (containment
of accidents, not just attacks), but the project is largely dormant. The
historical **Mach** microkernel (and GNU Hurd) is the ancestor of much of this
lineage and survives in hybrid form inside XNU/macOS — a reminder that "micro­
kernel ideas in a shipping OS" usually arrive as a *hybrid*, not a purist
rewrite, which is effectively the pragmatic position fastenv takes on Linux.

**Synthesis — what actually transfers.** Three ideas from this field are worth
keeping in view, in rough order of how reachable they are for fastenv:

1. **Capability delegation matching the trust hierarchy (Genode).** fastenv
   already approximates this with host→project→agent policy layering; the
   microkernel world just shows the cleaner, kernel-enforced form of the same
   shape. This is a *design influence we can apply now*, not a migration.
2. **A minimal/verified microhypervisor under the project boundary (NOVA,
   seL4-as-hypervisor).** The one place a microkernel could realistically slot
   into fastenv without giving up Linux: swap the *enforcer* of the project VM
   boundary for a smaller, auditable one, while Linux guests and the `crun`
   agent layer stay exactly as they are. A long-horizon option, not a near-term
   plan.
3. **Memory-safe and/or proven kernel code (Redox, seL4).** The asymptotic
   answer to the shared-kernel ceiling — but only available by changing the
   kernel, which the workload forbids today.

The through-line is the same as §H's: every one of these has a *better-than-Linux
isolation model and a worse-than-Linux ability to run the agent workload*. They
are north-stars and component-level ideas, not substrates. fastenv's commitment
remains boundary *placement* on commodity Linux + KVM; the microkernel field
mainly tells us which direction to evolve the enforcers, not to replace the OS.

---

## Side-by-side

| Design | Tenant boundary | Per-agent fan-out | Boundary type | Fits our trust model? |
|---|---|---|---|---|
| A. Host containers | Weak | Excellent | Shared kernel | No — PRD non-goal |
| B. gVisor | Medium | Good (syscall tax) | Userspace kernel | Partial; wrong granularity |
| C. Kata (VM per container) | Strong | Poor (VM per agent) | Hardware/VM | Over-isolates fan-out |
| D. Firecracker per agent | Strong | Medium | Hardware/VM | Over-isolates fan-out |
| E. One giant VM | Weak | Excellent | Shared kernel | No — PRD non-goal |
| F. Process sandboxes | Weak/fragile | Excellent | Syscall filter | No — PRD non-goal |
| G. Remote service | Strong (theirs) | Good (network) | Hardware/VM | No — forfeits host plane |
| H. Fuchsia / Zircon | Strong (capability) | Unproven | Microkernel/capability | No — not a Linux substrate |
| **fastenv (VM/project + container/agent)** | **Strong** | **Excellent** | **Hardware + namespace** | **Yes** |

---

## Why fastenv's split wins for this use case

fastenv's claim is not that microVMs beat containers or vice versa. It is that
**the project boundary and the agent boundary are different problems and should
be solved by different mechanisms**:

- **The project boundary needs strength, and it is paid for rarely.** A repo /
  tenant is a real trust domain, so it gets a hardware-grade Firecracker
  boundary. But a project VM is long-lived relative to agent runs (architecture
  §4) and can be prewarmed or reused within the trust domain, so its boot cost
  amortizes across many agents. You pay VM cost on the axis where it is cheap to
  amortize.

- **The agent boundary needs cheapness, and it is paid for constantly.** Agents
  on the same repo already share a trust domain, so they do not need to be
  isolated from each other at hardware strength — they need clean,
  non-stomping workspaces (PRD §4.3, §7). A `crun` container with an overlayfs
  CoW workspace and private PID/mount namespaces delivers exactly that for
  container-class cost. You pay container cost on the axis where it is paid most
  often.

Every single-mechanism design above is forced to pick the same boundary for
both problems and therefore loses on one axis:

- Designs A/E/F get cheap fan-out but **fail the tenant boundary** — the PRD's
  central non-goal.
- Designs C/D get a strong tenant boundary but **pay VM cost per agent**,
  fragmenting the project-local cache and slowing the interactive loop the PRD
  performance section protects.
- Design B taxes the syscall-heavy workload agents actually run and still picks
  the wrong granularity for fan-out.
- Design G is strong but **moves policy ownership off the host**, contradicting
  the requirement that the host owns scheduling, secrets, artifact validation,
  and eBPF monitoring.

The two-layer split also lines up the rest of the requirements cleanly, which a
single mechanism cannot do:

- **Hierarchical policy** (PRD §4.6): host decides VM network access → project
  VM sets project policy → agent container narrows it per run. Three layers,
  three natural decision points.
- **Dual-plane eBPF** (PRD §3): host eBPF watches the Firecracker/jailer
  boundary; guest eBPF watches agents inside the VM. Two kernels, two
  kernel-local policy planes — impossible without the VM layer.
- **Controlled output flow** (PRD §4.4): the host sees VM-level state and
  validated artifacts only, never a live writable guest workspace. The VM image
  *is* the export boundary.
- **Trust-scoped caching** (architecture §6): project-local package/Git caches
  stay warm and shared **read-only within one trust domain** — which only makes
  sense when "one trust domain" is a concrete VM. Per-agent VMs (C/D) have no
  natural place for this; host containers (A/E/F) can only share it by crossing
  the tenant boundary.

---

## Object-capability policy — the authority axis containment leaves open

Everything above argues one axis: **containment** — *can a compromised unit
reach beyond its box?* The microkernel section (§H) quietly introduced a second,
orthogonal one, because capability security is not a containment model at all —
it is an **authority** model: *given everything a unit legitimately holds inside
its box, how much can it actually do, and how much of that can it hand to what it
spawns?* These two axes are independent and multiplicative, and fastenv's
workload makes the second one matter more than it does almost anywhere else. It
is worth pulling out, because the object-capability (ocap) *discipline* transfers
to commodity Linux without changing the kernel, while the kernel-native form
(§H) does not.

### What ocap actually asks for

An object-capability system has no *ambient authority*. Authority does not flow
from who you are (a UID, a role, an ACL the kernel checks on your behalf); it
flows only from what you *hold*. A capability is an unforgeable reference that
**fuses designation and authority** — naming the resource and being permitted to
use it are the same act — so a subject can only ever act on the specific objects
it was explicitly handed. Authority is **delegated, attenuated, and revoked**,
never assumed. The design target is the **principle of least authority (POLA)**:
each unit runs with the minimum set of capabilities its current task needs, and
each thing it spawns gets a *narrowed* subset, never a copy of the parent's full
reach.

This is the structural opposite of Linux's defaults, which designs A–G all
inherit: a process opens files *by path* against an ambient filesystem, reaches
the network through whatever routes exist, and reads secrets from an environment
it was simply *given*. Authority is ambient and coarse; the boundary is the only
thing standing between the unit and everything its identity can touch.

### Why agents need the authority axis, not just the boundary

Two properties of the agent workload make ambient authority dangerous in a way
containment cannot fix:

1. **Prompt injection is a confused-deputy attack, and it happens entirely
   *inside* the box.** A confused deputy is a program tricked into wielding its
   legitimate authority on an attacker's behalf. An AI agent is a confused deputy
   waiting to happen: any content it ingests — a README, a web page, a
   dependency's post-install script, another tool's output — can steer it to
   exercise authority it holds for some unrelated purpose. Containment does
   *nothing* here, because the agent never escapes; it acts within its box, using
   authority it genuinely has, against a target the attacker chose. Ocap is the
   one structural answer: if the agent only holds capabilities scoped to the
   current task, a hijacked agent can only reach what those capabilities name.
   POLA turns "the model got talked into it" from a breach into a no-op, because
   the authority to be hijacked was never present. This is the single strongest
   reason ocap belongs in this document — it closes a gap the entire containment
   thesis is blind to.

2. **Agents fan out into things that inherit authority by default.** An agent
   spawns subprocesses, MCP servers, downloaded toolchains, and generated
   scripts. On ambient-authority Linux each child inherits the parent's full
   reach — its file access, its sockets, its environment secrets. Ocap reframes
   every spawn as a **delegation**: the child receives only an attenuated handle,
   and *can only* sub-delegate, never widen. That is exactly Genode's recursive
   delegation (§H) and the hierarchical-policy requirement (PRD §4.6) —
   host → project → agent → tool as a chain where each link hands down strictly
   less than it holds.

### Doing ocap on commodity Linux

Linux is ambient-authority at the core, so ocap here is a **discipline enforced
by brokers plus the filtering layers**, not a kernel-native primitive. The
pieces already exist:

- **File descriptors are Linux's one true capability** — unforgeable, and
  transferable between processes over Unix sockets (`SCM_RIGHTS`). The canonical
  move is to hand a unit an *fd* to the exact file/dir/socket it may use, never a
  *path* into an ambient namespace.
- **The filtering layers stop being mere defense-in-depth and start *enabling*
  ocap.** Landlock and seccomp that strip open-by-path and the exotic syscall
  tail remove the ambient back-channels that would otherwise let a unit route
  around its capabilities — leaving brokered fds/handles as the *only* way to
  reach a resource. This is the deeper role of the §F/seccomp mechanisms: not
  just narrowing a surface, but making capabilities load-bearing.
- **A host/project broker holds the real authority and vends scoped, revocable
  proxies.** The host already owns secrets, network egress, and artifact writes
  (PRD §4.4, §4.6); ocap says the agent never holds the *real* secret or a
  wide-open socket — it holds a narrow, revocable handle, or a bearer-capability
  token (macaroon-style: independently attenuable, delegatable, caveat-scoped)
  for control-plane operations. Containment guarantees the agent cannot bypass
  the broker to touch the real resource directly; ocap guarantees that even
  exercising everything it legitimately holds, the authority is minimal and
  time-boxed.

### How the two axes compose

Containment and ocap answer different questions and neither substitutes for the
other:

| | Ambient authority inside | Least authority (ocap) inside |
|---|---|---|
| **Weak boundary** | Worst case — escapable *and* maximal blast radius | Contained damage, but escapable |
| **Strong boundary** | Today's default container: hard to escape, but a subverted or injected agent wields broad FS / egress / secrets inside | **The target** — hard to escape *and* a hijacked unit can reach only what it was handed |

fastenv's main thesis (hardware wall at the project, namespace wall at the
agent) buys the bottom row. Ocap policy is what moves it from the bottom-left
cell — a strong box around a broadly-authorized interior — to the bottom-right.
The boundary makes the broker unbypassable; the capability discipline makes what
the agent holds *worth little to steal*. They multiply.

> **Current state.** fastenv today sits in the bottom-left cell: strong
> containment around an interior that is still largely ambient-authority — the
> agent container has broad filesystem and network reach, the agent-layer seccomp
> profile is not yet wired (see the Seccomp section), and secret/handle brokering
> is a stated host responsibility (PRD §4.4, §4.6) rather than a built-out
> capability model. An ocap interior — fd/handle vending, scoped revocable
> control-plane tokens, attenuated delegation to spawned tools — is a direction
> the existing requirements point at, not a shipped capability. It is the
> highest-leverage place to harden the *inside* of the boundary fastenv already
> provides.

---

## Seccomp at both layers — defense-in-depth, not the boundary

The same belt-and-suspenders logic that makes Landlock a *rail and not a wall*
applies to seccomp, and fastenv's design uses seccomp at **both** of its
boundary layers — notably, so does Firecracker itself.

- **The VMM layer.** Firecracker installs a tight, argument-aware seccomp-bpf
  **allowlist** on its own VMM process (only the handful of syscalls and the
  specific KVM `ioctl` codes it needs). This confines the *host-side* VMM, not
  the guest: if a malicious guest finds a device-emulation or vmexit bug and
  pops the VMM, seccomp sharply limits what that compromised process can do to
  the host. In other words, the project that *gives* you the hardware boundary
  still wraps its own enforcer in seccomp — because no single mechanism is
  trusted alone. fastenv inherits this: Firecracker is launched without
  `--no-seccomp`, so the default VMM filter is active whenever a VM boots.
- **The agent layer.** Inside the guest, a seccomp profile on the `crun`
  container drops the exotic-syscall tail (`ptrace`, `bpf`, `keyctl`,
  `io_uring` setup, raw/packet sockets) that namespaces alone leave reachable in
  the *guest* kernel. Paired with Landlock (path/port semantics) and namespaces
  + cgroups (workspace and resource isolation), this is what brings the agent
  layer up to a well-configured container's strength — see the Landlock deep
  dive above for why that is container-strength, not VM-strength.

So fastenv ends up running seccomp in both layers, pointed in opposite
directions: hardening the **agent inside the VM**, and (via Firecracker)
hardening the **VMM that enforces the project boundary**. In both cases seccomp
narrows the syscall surface as a backstop; the hardware boundary remains the
load-bearing wall.

> **Current state.** The VMM-layer filter is live today (Firecracker's default).
> The agent-layer profile is the target but is **not yet wired** — the generated
> OCI `config.json` omits `linux.seccomp`, so agent containers currently run with
> syscalls unconfined by seccomp. See architecture.md §5 (Seccomp) for the
> intended host→project→agent policy hierarchy and the gap.

---

## Where fastenv's choice is *not* better

Stating the boundaries honestly:

- **Single-tenant, fully-trusted code.** If every agent is trusted and there is
  one tenant, the VM layer is pure overhead — plain host containers (A) are
  simpler and faster. fastenv's value appears only when a real tenant boundary
  exists.
- **One-agent-per-project workloads.** With no fan-out, the inner container
  layer earns little, and a VM-per-agent design (D) is comparably good and
  conceptually simpler.
- **Hard per-agent hostile isolation.** If agents on the *same* repo must be
  mutually hardware-isolated (e.g. running genuinely adversarial code against
  each other within one project), the container layer is too weak and you want
  Kata/per-agent VMs (C/D) despite the cost. fastenv assumes intra-project
  agents share a trust domain.
- **Cross-platform / no-KVM hosts.** Firecracker needs KVM (Linux/bare-metal or
  nested-virt). On platforms without it, the VM layer is unavailable and a
  gVisor- or container-based design is the only option.
- **Zero-ops / serverless preference.** If you would rather not operate
  Firecracker, jailer, and an artifact plane at all, a hosted service (G) trades
  control for operational simplicity.

---

## Summary

The competing designs each commit to a single isolation mechanism and are
forced to use it for both the tenant boundary and the per-agent unit — so they
land as either "cheap but porous" (A, E, F), "strong but expensive per agent"
(C, D), "taxed and wrong-granularity" (B), or "strong but not host-owned" (G).

fastenv refuses the single-mechanism framing. It puts a **hardware boundary
where the trust domain is (the project, paid rarely and amortized)** and a
**namespace boundary where the fan-out is (the agent, paid constantly and kept
cheap)**. For the specific workload of many semi-untrusted, high-fan-out coding
agents grouped under a project trust domain — with a host that owns policy and
ingests only validated outputs — that two-layer split is strictly better than
any design that has to answer both questions with one tool.
