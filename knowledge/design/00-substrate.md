# Memory Substrate — Spec

> **Naming note.** "Substrate" is a working title. The final module/repo name is
> decided at extraction time (see §12). Nothing in this spec depends on the name.

## Project context

Agent systems and the humans around them accumulate two kinds of institutional
memory: **what we've decided about how to work** (procedures, judgment calls,
priorities — authored by people) and **what we've actually done** (summaries of
past cases, past runs — derived by machines from completed work). Both are
worthless at rest and valuable at decision time, when a small number of relevant
entries — or the verified *absence* of any — should inform whoever (or whatever)
is deciding.

The substrate is a storage and retrieval component for exactly that. It is not
an agent framework, not a RAG pipeline, not a vector database. It stores prose
entries with light structure, recalls the few most relevant ones with an
explanation of why, answers "how similar is this to what we already have," and
can always prove, byte-for-byte, what it returned at any point in the past.

It is designed to be consumed at arm's length by unrelated products. The first
consumer is an AI-native investigation platform (whose agent loop consults
procedures during reasoning and audit-links every consultation). The second is a
workflow-automation platform (microservices on Kubernetes) that uses procedures
to guide workflow construction and similarity search to detect duplicate
solutions across teams. Neither consumer's vocabulary appears in the substrate's
contract.

## Acceptance scenarios — the scope fence

v1 of the substrate answers exactly three questions, for exactly two kinds of
corpus. **Anything that does not serve one of these three questions is out of
scope**, however useful it might be to some hypothetical consumer.

1. **"What is our documented procedure for this problem?"**
   Ranked recall over a *curated* corpus: human-authored prose, retrieved by a
   short free-text query plus tag filters, returned with an excerpt, a match
   rationale, and a coverage verdict.

2. **"Have we handled something like this before?"**
   Ranked recall over a *derived* corpus: machine-extracted summaries of
   completed work, stamped with provenance, retrieved the same way.

3. **"How similar is this to what we already know?"**
   Similarity assessment of a candidate *document* (not a short query — a whole
   draft procedure, case description, or workflow summary) against a corpus,
   returning matches classified into stable similarity bands.

## Out of scope

- **Extraction and summarization.** Producing derived entries (LLM
  summarization, structured extraction from source systems) is the consumer's
  job. The substrate stores derived entries and their provenance stamps; it
  never runs an LLM, and has no inference dependency of any kind.
- **Authentication and authorization.** Namespaces are opaque, caller-asserted
  keys. Who may assert which namespace, and which principals may author or sign
  entries, is enforced by the consumer or the deployment (service mesh, gateway,
  IdP). The substrate records principals; it never validates them.
- **Namespace provisioning.** There is no create/list-namespaces API. A
  namespace exists by virtue of rows carrying it.
- **Cross-corpus recall.** Every recall names one corpus. (Additive later if a
  real consumer needs it; see §13.)
- **Cross-namespace anything.** Not expressible, at any layer. See commitment 5.
- **Non-Go client SDKs.** The wire contract (§8) is plain versioned HTTP+JSON;
  any language can speak it. Generated clients are a consumer concern.
- **Ranking as control flow.** The substrate returns context; it never decides,
  executes, or orchestrates anything based on what it stores.

---

## 1. Architectural commitments

These are the substrate's identity — the properties that distinguish it from a
generic search index, and the ones consumers may build audit trails on.

**1. Memory is context, not control.** Entries are unparsed prose plus opaque
structured metadata. The substrate never interprets, executes, or acts on entry
content. Consumers (typically LLMs or humans) read entries as context and make
their own decisions.

**2. `EMPTY` is evidence of absence.** A recall that executes over an indexed
corpus and matches nothing returns `coverage: EMPTY` — a first-class, meaningful
signal ("we have no procedure for this"), never an error and never conflated
with one. Errors are errors.

**3. Recall is tamper-evident.** Every recall result carries a `content_hash`
over the entry content it was drawn from. The substrate can return the exact
hashed bytes for any hash it ever served (§6), regardless of later edits,
retirement, or supersession. "What did the consumer see at time T?" is always
answerable — the property audit trails are built on.

**4. Results explain themselves.** Every result carries a `match_rationale`: a
short prose account of why it ranked where it did (which filters matched, what
drove the score). A consuming LLM weighs relevance from the rationale rather
than trusting a bare number.

**5. Namespace isolation is structural.** Every row carries a namespace key;
every call requires one; no query can span namespaces. This is enforced by
construction (the key participates in every index and every WHERE clause), not
by policy.

**6. Scores are opaque; bands are contractual.** Numeric scores order results
*within one response* and mean nothing beyond that — not across calls, not
across backend versions, not as thresholds. The stable vocabulary for "how
similar" is the banded classification (§5.4). Swapping the ranking backend
(keyword → embeddings → better embeddings) recalibrates bands internally and
never breaks a consumer.

**7. Storage is ranking-backend-agnostic.** The entry store is independent of
how recall ranks. Backends are versioned; embeddings (when present) are
versioned by the model that produced them; switching backends triggers
re-indexing but no schema migration of entries and no contract change.

**8. The consumer owns meaning.** Tags, the `meta` blob, the `advice` token,
principal identifiers, and the namespace key are all opaque to the substrate.
It stores, filters, and returns them; it never interprets them.

---

## 2. Concepts

### 2.1 Namespace

An opaque non-empty string key (≤128 bytes). Consumers assign meaning: a tenant
UUID, an org slug, a team id. The substrate treats it as a partition key and
nothing else.

### 2.2 Corpus

A named collection of entries within a namespace, declared at deployment time
(embedded: registered via the Go API; service: listed in config). A corpus
declaration is:

```
CorpusDef
  name             string            # e.g. "procedures", "case-summaries"
  archetype        CURATED | DERIVED
  governance       LIGHTWEIGHT | GATED   # curated only; derived is implicitly lightweight
```

Two archetypes, deliberately no more:

- **CURATED** — human-authored standing knowledge. Versioned prose with
  authoring governance (author, optional signoff). The "what's our procedure"
  corpus.
- **DERIVED** — machine-extracted case knowledge. Entries are produced by a
  consumer-side pipeline from completed work and stamped with provenance
  (producer, producer version, generator model if an LLM was involved, source
  reference). The "have we seen this before" corpus.

There is no schema-definition machinery. Corpora differ only in archetype and
governance; the per-domain structure consumers care about lives in `tags` and
`meta` on each entry.

### 2.3 Entry

```
Entry
  id               UUID (random v4, minted by the store)
  namespace        string
  corpus           string
  title            string
  body             text        # unparsed prose; never executed or interpreted
  tags             list<string>            # hard-filterable facets
  meta             JSON object (optional)  # opaque structured metadata
  advice           string (optional)       # structured hint token, consumer-interpreted
                                           # (e.g. "isolate", "do-not-act")
  status           DRAFT | IN_REVIEW | PUBLISHED | RETIRED
  revision         int         # monotonic within a lineage, starts at 1
  supersedes_ref   UUID (optional)         # previous revision's entry id
  version_label    string (optional)       # corpus convention (e.g. semver); not interpreted

  # curated governance (archetype CURATED)
  authored_by      string (optional)       # opaque principal
  signed_off_by    list<string> (optional) # opaque principals

  # derived provenance (archetype DERIVED)
  provenance       {
                     producer          string   # e.g. "case-summarizer"
                     producer_version  string
                     generator_model   string (optional)  # if LLM-generated
                     source_ref        string (optional)  # consumer-side pointer
                   }

  content_hash     hex sha256 (computed by the store; §3)
  hash_version     int
  created, updated, published_at, retired_at   timestamps
```

**Identity is random, not deterministic.** Entries are documents, not
observable facts; two identical bodies in different namespaces (or the same
one) are deliberately distinct. Deduplication is a *recall* concern (similarity
bands), never an identity concern.

---

## 3. Content hash — ONE-WAY DOOR

Consumers record content hashes in their own immutable audit trails. The scheme
therefore cannot change silently — it is versioned from day one and computed
exclusively by the store (consumers never compute hashes; they verify).

**`hash_version: 1`** — SHA-256 over the UTF-8 bytes of the RFC 8785 (JCS)
canonical JSON of the content object:

```
{ "advice": ..., "body": ..., "meta": ..., "tags": [...], "title": ... }
```

with `tags` sorted lexicographically and deduplicated, and absent optional
fields omitted entirely (never null). The hash covers *content only* — not
status, revision, principals, provenance, or timestamps. A revision that
changes any content field produces a new hash; a lifecycle transition does not.

Every stored hash and every hash returned on the wire is accompanied by its
`hash_version`. A future scheme is a new version computed alongside, never a
reinterpretation of v1 hashes.

## 4. Lifecycle and governance

Revisions never mutate served content: a revision creates a new entry row
(revision N+1, `supersedes_ref` → prior) and the prior revision's content
snapshot remains hash-addressable (§6). Prior revisions are excluded from
recall by default.

**CURATED / LIGHTWEIGHT** (default): `Put` lands directly at PUBLISHED;
`PUBLISHED → RETIRED` is the only transition. Write-it-use-it, for solo
operators and small teams.

**CURATED / GATED**: `DRAFT → IN_REVIEW → PUBLISHED → RETIRED`, with
`IN_REVIEW → DRAFT` on request-changes. The PUBLISHED transition requires ≥1
signer principal on the call; the substrate records the signoff, and *whether
that principal was entitled to sign* is the deployment's concern (out of
scope). Switching a corpus between modes requires no migration — the status
field exists in both.

**DERIVED**: entries arrive PUBLISHED (the consumer's pipeline decides when to
write). Re-derivation of the same source is a revision. Retirement and purging
follow the consumer's retention of the source work — driven by consumer calls,
never by substrate-side policy.

**Purge vs. retire.** Retire is the soft terminal state; content stays
hash-addressable for audit. Purge (explicit, for compliance) removes content
*and* its snapshots, leaving a tombstone keyed by the hash: a snapshot lookup
then answers "content existed and was purged at T" rather than pretending the
hash was never served. Tamper-evidence and right-to-forget compose instead of
conflicting.

---

## 5. Recall

One verb, two modes, one corpus per call.

### 5.1 Query

```
RecallQuery
  corpus           string (required)
  mode             RANK (default) | SIMILARITY
  query            string      # RANK: short free text. SIMILARITY: a whole document.
  tags             list<string>   # hard filter (overlap), applied before ranking
  limit            int (default 5)
  include_retired  bool (default false; audit/research only)
```

**Documents are first-class queries.** SIMILARITY mode exists precisely for
"here is a 3-page draft; what do we already have like it?" Backends must accept
long inputs from v1 of the contract even while early backends rank them
crudely; quality improves with the backend, the contract doesn't move.

### 5.2 Result

```
RecallResult
  results        list<{
                   entry_id, revision, title, excerpt,
                   score            # opaque; orders THIS response only (commitment 6)
                   band             # SIMILARITY mode only; §5.4
                   match_rationale  # why it ranked here (commitment 4)
                   content_hash, hash_version,
                   tags, advice, status
                 }>
  coverage       COMPLETE | EMPTY      # §5.5
  ranker         {backend, backend_version}   # attribution for audit trails
  retrieval_at   timestamp
```

### 5.3 Ranking (RANK mode)

Tag hard-filter, then backend-ranked relevance of `query` against title+body,
with recency as tiebreak. The v0 backend is Postgres full-text (`ts_rank`);
the v1 backend adds vector similarity over embeddings (§10). Ranking internals
are explicitly non-contractual — rationale and ordering are the interface.

### 5.4 Similarity bands (SIMILARITY mode) — ONE-WAY DOOR

Each result carries a band:

```
NEAR_DUPLICATE   # substantially the same thing; a consolidation/dedup candidate
RELATED          # same problem space; worth reading before proceeding
DISTINCT         # returned only to show the nearest neighbors are far away
```

Bands are the *contract*; the numeric cutoffs behind them are calibrated per
`{backend, backend_version}` and shift when the backend does. Consumers must
never persist raw scores as thresholds or facts; they may persist bands
*together with* the `ranker` attribution from the result envelope.

### 5.5 Coverage — ONE-WAY DOOR

```
COMPLETE   # executed over an indexed corpus, ≥1 result
EMPTY      # executed over an indexed corpus, zero matches — evidence of absence
```

Failures (backend down, corpus unknown, malformed query) are errors, never
`EMPTY`. Consumers are entitled to treat `EMPTY` as a real-world signal.

### 5.6 Excerpts

An excerpt is drawn from the hashed content within a size budget (v0: rune
budget; later: token budget, most-relevant-section selection). The attestation
claim attaches to the *content*, not the excerpt: the excerpt is a view over
bytes whose hash the result carries.

## 6. Attestation

`Snapshot(namespace, content_hash)` returns the full content object (the §3
canonical fields) whose hash was ever served in a recall result or entry read —
across revisions, retirement, and supersession — or a purge tombstone (§4).

Consumers with self-contained audit requirements (audit trail must survive the
substrate being repointed or unavailable) may additionally copy retrieved bytes
into their own stores; the substrate's guarantee makes that a redundancy choice,
not a necessity.

---

## 7. Go contract

The substrate is consumed embedded (import the module) or as a service (§9);
the Go interface is the source of truth and the wire contract (§8) is its
projection.

```go
type Store interface {
    // Write side
    Put(ctx context.Context, ns, corpus string, e Entry) (Entry, error)
    Revise(ctx context.Context, ns, corpus string, id uuid.UUID, r Revision) (Entry, error)
    Transition(ctx context.Context, ns, corpus string, id uuid.UUID, t Transition) error
    Purge(ctx context.Context, ns, corpus string, id uuid.UUID) error

    // Read side
    Get(ctx context.Context, ns, corpus string, id uuid.UUID) (Entry, error)
    List(ctx context.Context, ns, corpus string, f ListFilter) ([]Entry, error)
    Recall(ctx context.Context, ns string, q RecallQuery) (RecallResult, error)
    Snapshot(ctx context.Context, ns string, hash ContentHash) (Snapshot, error)
}
```

`Transition` carries the target status and the acting principal(s); the store
validates the state machine (per the corpus's governance mode), not the
principal. The reference implementation is Postgres; migrations are exported as
an embedded `fs.FS` so hosts apply them with their own tooling (an embedded
supervisor, a k8s job, the service binary's `migrate` subcommand).

## 8. Wire contract (v1) — ONE-WAY DOOR

A thin, versioned HTTP+JSON projection of §7. The path prefix is the
compatibility promise: breaking changes mean `/v2`, additive evolution stays in
`/v1`.

```
POST   /v1/namespaces/{ns}/corpora/{corpus}/entries              # Put
GET    /v1/namespaces/{ns}/corpora/{corpus}/entries              # List (?status=&tag=&include_retired=)
GET    /v1/namespaces/{ns}/corpora/{corpus}/entries/{id}         # Get
POST   /v1/namespaces/{ns}/corpora/{corpus}/entries/{id}/revisions   # Revise
POST   /v1/namespaces/{ns}/corpora/{corpus}/entries/{id}/transition  # Transition
DELETE /v1/namespaces/{ns}/corpora/{corpus}/entries/{id}         # Purge
POST   /v1/namespaces/{ns}/corpora/{corpus}/recall               # Recall (both modes)
GET    /v1/namespaces/{ns}/snapshots/{hash}                      # Snapshot
GET    /healthz
```

The namespace is asserted in the path. The server does not authenticate it
(out of scope, by commitment 8): deployments enforce "who may assert which
namespace" via mesh mTLS, network policy, a gateway, or the optional
static-token middleware — all outside the substrate's contract. JSON field
names match the Go contract's serialized forms exactly; there is no separate
wire schema to drift.

## 9. Hosting shapes

One module, two shapes; consumers pick per their architecture.

- **Embedded.** Import the Go module; construct the store over a `*sql.DB`;
  the host owns process lifecycle and migration application. Suits bundled
  single-binary products.
- **Service.** `cmd/substrated` (name provisional): the same library behind the
  §8 handlers, plus `migrate` and `serve` subcommands and `/healthz`. One
  container image, own Postgres, standard Kubernetes citizen. Suits
  microservice estates where many services share one memory deployment.

The service binary adds *no* behavior beyond transport — anything the service
can do, an embedded consumer can do, and vice versa.

## 10. Ranking backends and embeddings

- **v0 backend:** Postgres full-text (`ts_rank` over title+body), tag
  hard-filter, recency tiebreak. SIMILARITY mode functions but bands are
  coarse.
- **v1 backend:** pgvector embeddings from a small bundled local ONNX model;
  optional provider embeddings (BYOK) per deployment for sharper retrieval.
  Embedding rows are keyed by `(entry_id, revision, model, model_version)`;
  switching models re-embeds the corpus with old and new rows coexisting
  through the migration window.

Backends are named and versioned; every `RecallResult` attributes itself to
`{backend, backend_version}` (§5.2). Band calibration is part of a backend
version's definition (§5.4).

## 11. Staging

| Stage | Scope |
|---|---|
| **v0** (exists today, pre-boundary) | Curated corpus, CRUD + lightweight governance, RANK-mode keyword recall, coverage, rationale. No hashes, no snapshots, no revisions, no derived archetype yet. |
| **v1** (the contract in this spec) | Both archetypes; revisions + supersedes chain; content hash + `Snapshot`; SIMILARITY mode with bands; embeddings backend; gated governance; the wire contract + service shape. |
| **Later, only on demonstrated need** | Cross-corpus recall; sub-document embedding; LLM-assisted reranking (would be the substrate's first — and only optional — inference dependency, off by default); additional archetypes. |

v0 → v1 is additive plus one hard obligation: the moment hashes ship, snapshot
preservation ships with them (a hash the store cannot replay is a broken
commitment 3).

## 12. Residence and extraction

This spec currently lives in-tree in its first consumer's repository, alongside
the v0 implementation, as a deliberate staging choice: the contract is expected
to move while the first consumer builds against it, and in-tree iteration is
cheap. The boundary is enforced now as if the split had already happened:

- The substrate's packages import stdlib and third-party modules only — never
  the host's packages. (CI-enforced in the host repo.)
- The host consumes the substrate through a provider interface at its
  composition root; host call sites never depend on substrate internals.
- This document uses no host vocabulary; the host's own design docs may
  reference this one, never the reverse.

Extraction to a standalone repository (module + `cmd/substrated` + this
`design/` directory, layout per §7–§9) happens at the first of: a second
consumer ready to integrate; the host repository becoming public; or the
contract surviving a full development cycle unchanged. Because of the import
boundary, extraction is a move, not a redesign.

## 13. Open questions / deferred

- **Final name and module path.** Decided at extraction; grep-friendly
  placeholder "substrate" until then.
- **Band calibration method for the v0 keyword backend.** Full-text scores are
  weakly comparable even within a response; v0 may legitimately return only
  `RELATED`/`DISTINCT` and reserve `NEAR_DUPLICATE` for the embeddings backend.
  Honest coarseness beats false precision.
- **List pagination.** v1 ships `limit/offset`; keyset pagination if a real
  corpus outgrows it (curated corpora are hundreds of entries, not millions).
- **Snapshot storage economics.** Every revision's content is retained
  indefinitely (minus purges). Fine at expected scale; revisit if a derived
  corpus with high re-derivation churn appears.
- **Bundled embedding model choice.** Same trade as any local-model bundle:
  binary size vs retrieval quality; deferred to the v1 backend implementation.
- **Multi-signer thresholds in gated governance.** v1 records signers and
  requires ≥1; "N signers for high-severity entries" is consumer policy layered
  on `Transition` calls vs. a substrate-side rule — leaning consumer-side, per
  commitment 8.

---

*End of spec.*
