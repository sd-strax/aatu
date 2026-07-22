# Adapter Distribution and Validation — Spec

## 0. Framing

This spec defines how an adapter travels from its author's build to a verified directory under
`<data>/adapters/` — packaging, the index model, signing and provenance, the install/verification
flow, upgrade, and revocation. It is the upstream half of the plugin story: `11-adapter-plugins.md`
begins at "an installed, verified adapter directory" and deliberately does not care how it got
there; this spec is the how. It absorbs and replaces the distribution sketch that previously lived
in `05 §6.3`.

The one-sentence summary: **adapters are content-addressed, signed artifacts listed in git-repo
indexes; the canonical index is one index among many, not a registry service; and verification is
a chain of independent gates, each answering exactly one question.**

| Owned here (`12`) | Owned elsewhere (authoritative) |
|---|---|
| Artifact packaging format and platform matrix | Install layout and manifest contents (`11 §3`) |
| The index entry format and the multi-index model | The plugin protocol, handshake, config delivery (`11 §2`–`§4`) |
| Signing, provenance, digest verification | Enablement and the per-op gates (`11 §5`) |
| The install/upgrade/revocation flows (`reckon adapter install`) | Conformance semantics — what `reckon adapter test` asserts (`11 §7`) |
| The authoring pipeline (scaffold → conformance → publish) | Credential and secret handling (`05 §10.2`, `11 §4.3`) |

### Out of scope

- **Curation policy.** Who reviews index submissions, what acceptance standards an index applies
  beyond the mechanical gates, and how differently-gated indexes relate — policy questions for
  each index's operator. This spec defines the *format and verification mechanism*, which are the
  same for every index.
- **What happens after install.** Discovery, enablement, spawning, configuration: `11`.
- **The engine's own distribution.** This spec covers adapters only.

---

## 1. Posture

Three principles, each ruling out a tempting alternative:

**Content-addressed and signed, not "trust the transport."** Every artifact is identified by its
sha256 digest, recorded in the index entry and re-verified at install. Signatures bind artifacts
to a publisher identity. TLS to a hosting provider is never the trust anchor; the hosting is
deliberately untrusted, which is what makes mirrors and airgapped transfer safe.

**An index is a format, not a singleton service.** The reckon project operates the canonical
public index, but the index format is the unit of design — any git repo (or static URL serving
the same layout) is an index, and an install resolves against a configured list of them. This is
what makes internal-only adapters, differently-gated indexes, and airgapped mirrors the same
mechanism rather than three features.

**No language package managers as the distribution channel.** An adapter is an executable in any
language (`11 §1`); distributing through per-ecosystem registries (pip, npm, …) would fragment
the install story per language, import N ecosystems' supply-chain postures into a product whose
adapters hold vendor credentials and dispatch containment actions, and make the
`<data>/adapters/` layout underivable from any single source. Language tooling has exactly one
role here: *inside the author's build*, vendoring an adapter's dependencies into its artifact
(`§2`).

The result deliberately has no server-side moving parts: indexes are git repos, artifacts are
files on any content-addressable host, verification is client-side. There is no registry service
to operate, scale, or compromise.

---

## 2. Packaging

An artifact is a platform-tagged archive that unpacks to exactly the install layout of `11 §3`:

```
reckon-adapter-okta-0.3.1-darwin-arm64.tar.gz
  └── manifest.yaml
      reckon-adapter-okta
      …                      # anything else the executable needs, vendored
```

Rules:

- **Self-contained.** The archive carries everything the executable needs that an author *can*
  bundle: vendored libraries, embedded interpreters where practical, static linking where
  possible. What an author genuinely cannot bundle (a system JVM, a Python runtime) is declared
  in the manifest's `requires` block (`11 §3`) and checked by `reckon check` — visible
  prerequisites, never silent assumptions.
- **Platform-tagged.** One artifact per `os-arch` pair the author supports. The index entry
  (`§3`) lists them; the installer selects by host platform. An unsupported platform is an
  install-time error naming the supported set, not a runtime surprise.
- **The archive is the whole interface.** Nothing about packaging leaks into the engine: the
  installer unpacks, verifies the manifest parses, and is done. No install scripts, no hooks, no
  post-install execution of any kind — the first time adapter code runs is the first enabled
  spawn (`11 §2`), never at install.

---

## 3. The index

### 3.1 Entry format

One file per adapter version in a git repo:

```yaml
# index/okta/0.3.1.yaml
name: okta
version: 0.3.1
publisher: github.com/example/reckon-adapter-okta   # the identity signatures verify against (§4)
protocol_versions: [1]
class: NATIVE_API
summary: "Okta identity provider — logon telemetry, account containment"
artifacts:
  linux-amd64:
    url: https://github.com/example/reckon-adapter-okta/releases/download/v0.3.1/reckon-adapter-okta-0.3.1-linux-amd64.tar.gz
    sha256: "9f2c…"
  darwin-arm64:
    url: https://github.com/example/reckon-adapter-okta/releases/download/v0.3.1/reckon-adapter-okta-0.3.1-darwin-arm64.tar.gz
    sha256: "41ab…"
```

The entry is metadata plus digests. Artifact hosting is wherever the publisher likes —
release-asset hosting, object storage, an OCI registry (`§8`) — because digests make the host
irrelevant to trust. Yanked versions (`§6`) move to an `advisories/` directory in the same repo
rather than being deleted, so history is auditable.

### 3.2 The multi-index model

Tenant config holds an ordered index list:

```yaml
adapter_indexes:
  - https://github.com/sd-strax/reckon-adapter-index   # canonical, the default
  - git@github.com:acme-soc/internal-adapters          # a tenant's own
```

`reckon adapter search` / `install` resolve across all configured indexes; a name collision across
indexes is an error requiring an index-qualified name, never a silent precedence pick. Three
consumers fall out of one mechanism:

- **The canonical index**, operated by the reckon project: submissions by PR, mechanically gated
  (`§5.1`), reviewed by maintainers. Its static hosting rides the reckon-operated surface
  (`05 §11.1`).
- **Private indexes** for adapters that will never be public — an internal team's CMDB adapter
  lives in the org's own index repo, same entry format, the org's own review process. Trust is
  per-index: the verification mechanics are identical; what differs is whose curation the
  operator chose to configure.
- **Mirrors.** An airgapped or egress-restricted site clones the index repo and caches artifacts
  inside the boundary. Content-addressing means the mirror operator is not a trust decision —
  digests and signatures verify exactly as they would against the origin.

An index with a stricter acceptance gate than the canonical one is just another index; nothing in
the mechanism distinguishes indexes by anything except their URL and their contents.

---

## 4. Signing and provenance

Artifacts are signed with **sigstore (cosign), keyless**: the signature binds the artifact to the
publisher's CI identity — "built by the release workflow of `github.com/example/reckon-adapter-okta`
at tag `v0.3.1`" — and is verified against the `publisher` field of the index entry. This buys
provenance without reckon operating key infrastructure, without publishers managing long-lived
private keys, and with revocation of a compromised identity handled by the identity provider
rather than a key-rotation ceremony.

What the signature does and does not attest:

- It attests **origin**: these bytes came from that publisher's release process.
- It does **not** attest quality, safety, or conformance — those are the index's acceptance gates
  (`§5.1`) and the engine's own gates (`11 §7`, `§5`). Keeping the attestations separate is
  deliberate: a signature that implied "reviewed and safe" would be a claim nobody verifying it
  could check.

Signature verification is per-artifact at install time (`§5.2`) and is not skippable for
index-sourced installs. Manually-installed adapters (`§5.3`) skip it by construction and lose
only what it provides.

---

## 5. Install and verification

### 5.1 Index acceptance (publish-time gates)

The canonical index's CI verifies, before any entry merges:

1. Signature validates against the claimed `publisher`.
2. Every listed artifact downloads and matches its digest.
3. Each artifact unpacks to a parseable manifest consistent with the entry (name, version,
   class, protocol versions).
4. **Conformance**: `reckon adapter test` (`11 §7`) runs against each artifact in a sandbox.
   Passing conformance is a listing requirement, not a courtesy — the suite is the gatekeeper,
   which is precisely what makes it worth maintaining.

Private indexes get the same CI as reusable tooling; whether they run it is their curation
policy.

### 5.2 Install (operator-side gates)

```
reckon adapter install okta@0.3.1
```

resolves the entry across configured indexes, selects the host-platform artifact, then:
fetch → **digest verify** → **signature verify** → unpack to `<data>/adapters/okta/` → record the
pin (`okta: {version: 0.3.1, sha256: "41ab…"}`) in tenant config. Any failure leaves nothing on
disk. Per `11 §6.1`, a successful install changes nothing but the output of `reckon check` — no
spawn, no catalog entry, no enablement.

The pin makes installs reproducible and transfers portable: an airgapped install is "carry the
artifact across, `reckon adapter install --from-file`, verify against the pinned digest" — the
network was never the trust anchor, so its absence changes nothing.

The full gate chain, assembled across both specs — each gate answers one question and no gate
trusts a previous gate beyond its scope:

| Gate | Question it answers | Spec |
|---|---|---|
| digest match | are these the bytes the index promised? | `§5.2` |
| signature | did they come from who the index says? | `§4` |
| conformance | do they speak the protocol? | `11 §7` |
| handshake | what can this adapter actually do? | `11 §4` |
| catalog authority | how much of that is trusted, at what tier? | `11 §4.2` |
| enablement | what did this tenant explicitly expose? | `11 §5` |
| Gate 2 + tiers | may *this particular request* proceed? | `04` |

### 5.3 Non-index installs

`git clone && make && cp -r` into `<data>/adapters/` is supported and deliberately loses only the
first two gates: conformance can still be run locally, and enablement plus Gate 2 hold
unconditionally. This settles the local-trust question `11 §8` deferred — the answer is that the
gates are independent, so a manual install is not a bypass of the security posture, just a
narrower slice of it, appropriate for the operator-built adapters it serves. `reckon check`
labels such installs `unverified-origin` so the narrowing is visible, not silent.

---

## 6. Upgrade and revocation

**Upgrade** is an install with a pin update: new version resolved, verified through the same
gates, unpacked over the old directory only after full verification. The post-upgrade handshake
diffs `describe` output against enablement per `11 §6.3` — new capability arrives disabled, and a
config-schema change that invalidates the tenant's config marks the instance unavailable with a
diagnostic. Rollback is an install of the previously pinned version.

**Revocation.** Yanking a version moves its index entry to `advisories/` with a reason:

```yaml
# advisories/okta/0.3.1.yaml
yanked: true
reason: "0.3.x logs API tokens at debug level"
reference: GHSA-xxxx-xxxx
```

New installs of a yanked version fail (overridable only with an explicit
`--allow-yanked`, for forensic reproduction). For already-installed versions, `reckon check`
consults the advisories of every configured index and flags matches. Revocation cannot reach into
a running process and does not pretend to — the claim is visibility, not remote kill, the same
honest-residual posture as `08 §6c`: never imply an effect that was not verified.

---

## 7. The authoring pipeline

The distribution mechanism exists to make this loop short, for an author who has never read the
engine source:

1. **Scaffold** — `reckon adapter scaffold` emits the JSON-RPC skeleton, a stub manifest, and a
   fixture scenario in the author's language of choice.
2. **Implement** — the vendor API calls and the OCSF shaping (`03 §5.2`); `describe` output
   including default bindings and the config schema (`11 §4`).
3. **Conform** — `reckon adapter test` locally until green (`11 §7`).
4. **Release** — CI builds the platform matrix with dependencies vendored (`§2`), signs each
   artifact (`§4`), publishes them as hosted release assets.
5. **Publish** — one PR to an index adding the entry file (`§3.1`); index CI re-runs the gates
   (`§5.1`); merge is listing.

Steps 1–4 involve no coordination with anyone. Step 5 is one reviewed file. That asymmetry —
heavy machinery on the verification side, one YAML file on the contribution side — is the point
of the design.

---

## 8. Open questions / deferred to v1+

- **Publisher namespaces in the canonical index.** v0: flat names, PR review resolves disputes.
  Whether publishers get reserved prefixes (and whether `name` should be index-scoped in tenant
  config from day one to ease a later migration) is deferred until collision pressure is real.
- **OCI artifacts as a carrier.** The entry format's `url + sha256` accommodates OCI registries
  as artifact hosts today; whether to adopt OCI as the *preferred* carrier (richer mirroring and
  garbage-collection tooling) is deferred — it changes hosting, not trust.
- **Advisory propagation latency.** `reckon check` polls configured indexes' advisories;
  whether an installed-adapter advisory warrants a louder surface than `check` output (a status
  line in the extension, a startup warning) is a UX question for the extension design.
- **Index countersignatures.** Whether the canonical index should additionally sign accepted
  entries (attesting "passed this index's gates at merge time"), so that offline verification can
  distinguish index-accepted artifacts from merely publisher-signed ones. Leans yes; deferred
  until the airgapped-mirror path is exercised for real.
- **Conformance-version skew.** An artifact conformance-tested against engine v0.N installs
  against engine v0.N+1. Protocol versioning (`11 §4.1`) bounds the breakage; whether the index
  should record the conformance-suite version per entry (and `reckon check` warn on skew) is
  deferred until the suite itself has versions worth distinguishing.

---

*End of spec. The downstream half — what happens to an installed adapter directory — is
`11-adapter-plugins.md`; the conformance suite it relies on is `11 §7`; the reckon-operated
static surface that hosts the canonical index is `05 §11.1`.*
