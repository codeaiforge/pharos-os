# Knowledge: shared entries with provenance

## 1. Status

**Planned. Design approved by the maintainer on 2026-11-05 (#141),** with `verify` taking the first 8 hexadecimal digits of the content's hash and staleness derived from versions only (no age). To be built by: the data model (#142), the service (#143), agent access (#144), private memory and promotion (#145), and the access-control, provenance, staleness, and injection tests (#146).

## 2. Context

M3.7 gives agents channels, groups, delegation, and a verifier ([coordination.md](coordination.md)). M3.8 gives them shared knowledge that outlives a task, without giving any of them more authority. D-025 (#140) decides it:

- a new `knowledge` service on its own store namespace, reached by agents only through the runtime, which names each write's author (item 1);
- append-only versions: a correction or retraction adds a version (item 2);
- scopes granted as runtime permissions, `knowledge read <scope>` and `knowledge write <scope>`; a query skips what the caller, or the evidence it cites, cannot read (item 3);
- only the user marks a version verified, on the trusted console, which never shows content (item 4);
- private memory stays the agent's `data` files; promotion is an explicit request; queries are by exact key and tag; stored content is data, never instructions (item 5).

What M3.8 builds on:
- **The store** (M3.0, [storage.md](storage.md)): one namespace per client badge, crash-consistent writes and appends, paths of at most 80 bytes, appends of at most 200 bytes inline, larger data through an attached buffer.
- **The runtime** checks, budgets, and audits every agent request; permissions are runtime grants per task attempt, revocable at once ([capabilities.md](capabilities.md)); each agent's private files are `data/<agent>/<file>` in the runtime's namespace.
- **The trusted path:** `trust` writes every console line from structured fields; it calls the audit service with a bounded wait and never waits on the runtime ([agents.md](agents.md)).
- **Limits:** `spawn` passes at most 8 capabilities (`MAX_SPAWN_CAPS`); the runtime already has 9 at boot, so the boot runtime lacks its network and `files` capabilities.

## 3. Design

### Entries and versions (#142)

- **A scope** is a named area of knowledge (agent-name rules, at most 32 bytes), listed in the service's compiled-in scope table (reviewed code, like the store's namespaces), at most 8, each with its own limits.
- **An entry** is a key in a scope (agent-name rules, at most 32 bytes) with a series of **versions**, numbered from 1, each immutable once stored.
- **A version** holds, in a typed record (D-019, `pharos_proto::knowledge`):
  - `kind`: `claim` (content), or `retraction` (no content: the version it replaces no longer holds);
  - `replaces`: the version this one corrects or retracts, 0 for the first;
  - the content: at most 4 KiB of bytes, never interpreted by the service or the runtime, and its SHA-256, computed by the service;
  - up to 4 **tags** (agent-name rules), for queries;
  - up to 4 **evidence** references, each `scope/key/version`, which must exist when it is written;
  - its **evidence scopes**: the scopes of its evidence and of their evidence scopes, computed by the service when it is written (at most 8; more is refused), so one check covers the whole chain;
  - **provenance**, set by the service from who sent it, never from the content: the author (`agent <name> task <id>` from the runtime, or `user` from the host tool), the source (`written`, `promoted <file>`, or `host`), and the time (the audit trail's boot number and `uptime` microseconds; Pharos has no wall clock yet).
- **Status is derived, never stored in the version:**
  - **heads** are the versions no other version replaces; a key with more than one head that is not a retraction is **conflicting** (two writers corrected the same version without seeing each other); the service keeps both, and a reader sees both;
  - a version is **superseded** when another version replaces it, and **retracted** when that version is a retraction;
  - a version is **stale** when it is superseded, or when any of its evidence is superseded or retracted;
  - a version is **verified** when the scope's marks name its key, number, and hash (below); else **unverified**.
- **Stored** as one store file per version, `<scope>/<key>/<version>`, written once and never rewritten or deleted (the service is the namespace's only writer, and refuses a version number that exists), and one append-only file per scope, `<scope>/marks`, of verification records. At start, the service lists its namespace and rebuilds each key's version index in memory; unreadable files are counted and left in place, as the runtime's tasks are.

### The service (#143)

- **`bin/knowledge`**, a service (class `services`), in new store namespace `knowledge` (8), started by `init` after the store and before `trust` and the runtime. Its interface, version 1:
  - `PUT` (scope, key, kind, replaces, tags, evidence, provenance from the caller's badge and fields, content from the buffer): the new version's number;
  - `GET` (scope, key, version; 0 for the heads): each version's record and status, its content into the buffer;
  - `HISTORY` (scope, key, from): up to 16 version summaries (number, kind, replaces, author, status), no content;
  - `QUERY` (scope, tag): up to 16 keys whose heads carry the tag, with their status;
  - `VERIFY` (scope, key, version, hash prefix): from `trust` only; appends a mark;
  - `ATTACH` (a buffer, as the store's `BUFFER`), and `INFO`.
- **Who may call:** badges name the runtime and `trust` (and the test clients); the runtime's requests carry the author (agent and task) and the caller's **readable scopes** (at most 8). The service answers a read only for a version whose scope and evidence scopes are all readable, and leaves out of `GET`, `HISTORY`, and `QUERY` replies anything else, without saying that it exists. A write's evidence must be readable by the writer.
- **No audit capability:** the service is told who acts and only stores; the runtime records agent updates and `trust` records verifications, as each records the actions it takes today.
- **Limits:** 256 keys per scope and 64 versions per key (each refused past it, `FULL`); a key's versions are numbered by the service.

### Agent access (#144)

- **Two new permissions,** runtime grants like `file` and `channel` (wire kinds 7 and 8, a length and the scope's name): `knowledge read <scope>` and `knowledge write <scope>`. Given at the attempt's start from the policy entry's new `knowledge_read` and `knowledge_write` lists (the manifest may ask for fewer); askable through the entry's `ask_knowledge`; revoked like any other (`revoke <agent> knowledge read <scope>`). `knowledge write` does not imply read.
- **New runtime requests:**
  - `KNOWLEDGE_PUT` (28): needs `knowledge write <scope>`; the runtime sends `PUT` with the agent's name and task as author, and its readable scopes;
  - `KNOWLEDGE_GET` (29), `KNOWLEDGE_HISTORY` (30), `KNOWLEDGE_QUERY` (31): need `knowledge read <scope>`; the runtime passes the agent's readable scopes, and copies the reply into the agent's buffer.
- **Audited:** each put is a consequential action, new action `knowledge` (18): an `INTENT` naming the agent, `knowledge write <scope>`, the key, the version it replaces, the kind, and the length (never the content), stored before the request is sent (else `NO_AUDIT`), then its `OUTCOME` with the new version. Reads are not audited (they change nothing), except their refusals, recorded once per kind per attempt as today.
- **Budgeted:** a new per-attempt budget field, `knowledge`, counts puts and promotions; every request counts against `rate`.
- **Content is data:** an agent gets content only in its buffer, with the status and provenance in the reply's structured fields; a model that reads it reads untrusted text, as with a file or a message, and anything it then does goes through its own grants.

### Private memory and promotion (#145)

- **Private memory is the agent's `data` files** (D-012), unchanged: never seen by another agent and never in a scope by itself.
- **`PROMOTE` (32):** the agent names one of its `data` files, a scope, a key, the version it replaces, and tags; it needs `data read` and `knowledge write <scope>`. The runtime reads the file itself and sends `PUT` with the source `promoted <file>`; the new version is unverified like any other. Audited as a `knowledge` intent with the detail `promote <file>`.

### Verification on the trusted path (#144)

- **`verify <scope> <key> <version> <hash>`** on the trusted console: the user types the first 8 hexadecimal digits of the content's SHA-256, read where the user read the content (for now the host tool, `cargo xtask knowledge`, on the store image), so a mark binds to the exact bytes the user checked. `trust` calls the service with a bounded wait (as it calls the audit service), which appends the mark only if the version exists and the prefix matches, then shows `verified <scope>/<key> version <n> by <author>` or why not (`no version`, `hash differs`). Content never reaches the console. Recorded by `trust` as a `verify` (17) by the user.
- **Host-loaded entries:** `cargo xtask` can write versions with author `user` and source `host`, each with its mark, into a test store image; they start verified.

### Kernel

- **`MAX_SPAWN_CAPS` raised from 8 to 12,** so the runtime holds the knowledge capability, and the boot runtime gets its network and `files` capabilities too; `trust` gets a fifth. The `spawn` test kernels check 12 passed and 13 refused.

## 4. Security

- **No authority from content:** knowledge is data on both paths; no request reads a permission, a policy, or an instruction from an entry, and the trusted console never shows one.
- **No reading around a grant:** the service answers only for scopes the runtime says the caller can read, and leaves out anything whose evidence chain reaches another scope, so a query, history, or summary cannot leak content or its existence; revoking `knowledge read` takes effect on the next request.
- **No forged provenance:** the author comes from the runtime's badge and the task it runs, the hash and time from the service, and the verified status only from a user's mark; an agent cannot write a version as another agent, as the user, or as verified.
- **No rewritten history:** versions are written once; a correction or retraction is a new version, and a conflict keeps both sides.
- **Trusted:** the service (stores what it is told, enforces scopes, versions, and evidence), the runtime (authorship, readable scopes), and `trust` (marks).
- **Carried:** a poisoned but unverified entry can still mislead an agent that reads it (its status and author say what it is); a supervisor can delegate `knowledge read` or `write` (as any permission it holds, #135); staleness by age needs a wall clock (planned).

## 5. Testing

| Where | What |
| --- | --- |
| Host, `pharos_proto` (#142, #143, #144) | version records, the service's requests and replies, the new permissions, and the runtime's requests round-trip; truncated, trailing, and over-limit fields refused; fuzzed |
| Host, `pharos_programs` (#142) | heads, conflicts, superseded, retracted, stale through evidence, verified only with a matching mark, evidence scopes computed and bounded, readable-scope filtering, rebuilding the index from files (cut at every point) |
| Pharos, `knowledge` kernel (#143) | a test client puts, corrects, retracts, conflicts, gets, queries, and verifies; everything survives a service restart; mutation-checked |
| Pharos, `knowledge_agents` kernel (#144, #145) | a granted agent reads and writes; one without a grant cannot; a revoked grant stops at once; a query leaves out what the caller cannot read; a private file is invisible until promoted; `verify` on the console; every put audited without its content; mutation-checked |
| Pharos, `poison` kernel (#146) | an agent tries to read around its scopes, forge an author or a verified status, overwrite a version, and act on instructions stored as an entry; stale and conflicting entries stay marked; each refused and recorded once |

## 6. Alternatives

- **Knowledge inside the runtime** and **a current value with a change log:** rejected in D-025 items 1 and 2.
- **Per-entry access lists** and **the D-024 verifier marking results verified:** rejected in D-025 items 3 and 4.
- **The console showing content to verify:** agent text would reach the trusted path (D-018).
- **Age-based staleness now:** Pharos has only `uptime`; derived staleness (superseded evidence) needs no clock.
- **The service auditing on its own:** a fourth audit client for actions the runtime and `trust` already record.

## 7. Open questions

- None yet; the review (#147) may add some.
