<!--
SPDX-License-Identifier: AGPL-3.0-or-later
SPDX-FileCopyrightText: OpenCloudMesh Go contributors
-->

# Changelog

OpenCloudMesh Go - a runnable Open Cloud Mesh peer in Go, focused on a
strict, WebDAV-centered subset of the protocol

All notable changes to this project are documented using changie.
See `.changie.yaml` for the configuration and the changie workflow for how
fragments are authored and released.

## v1.2.2

### Fixed

* Docker image publish job failed to resolve the semver tag when the release lane ran on a push to master, because reusable workflows inherit the caller's GITHUB_EVENT_NAME (push) and GITHUB_REF_TYPE (branch); the resolver now uses the explicit semver input, so release images publish again
## v1.2.1

### Fixed

* GoReleaser archive config used an invalid `info` field that aborted binary release builds; archives now pin file mtimes via `builds_info` and per-file `info` so binary releases publish again
## v1.2.0

### Added

* automation and release tooling: dependabot config, changie changelog system with PR gate, release workflow with --version, PR and issue templates, and CI workflow name and badge cleanup

* dependabot auto-merge for patch and minor go module and security updates (major bumps stay manual), gated by required CI checks via native GitHub auto-merge; contributor changelog guide posted as a sticky PR comment with changie install and usage instructions when a fragment is missing

* release, lint, and security CI: add a GoReleaser binary release lane with semver tag validation and third-party license bundling, group linters under a ci-lint dispatcher (golangci, fmt-vet, shellcheck, actionlint, yamllint, hadolint, markdownlint, typos), and split security checks into per-tool leaves (gosec, govulncheck, zizmor, codeql, scorecard, dependency-review)

* governance and security documentation: GOVERNANCE.md, MAINTAINERS.md, .github/CODEOWNERS, CODE_OF_CONDUCT.md (Contributor Covenant 2.1, official text), ROADMAP.md, docs/security-requirements.md, docs/assurance-case.md, and a formal test policy section in docs/testing.md

* maintainer succession plan in GOVERNANCE.md and MAINTAINERS.md naming Giuseppe Lo Presti, Micke Nordin, and Michiel de Jong as successors; achievement badges (CII Best Practices, OpenSSF Scorecard) in the README; and a cryptographic algorithm agility note in docs/crypto-agility.md

* coverage threshold gate: `make coverage-check` enforces a minimum 80% unit statement coverage floor (COVERAGE_THRESHOLD), wired into the ci-test-unit-integration workflow after the unit tests, with a Coverage policy section in docs/testing.md

* reproducible builds: goreleaser mod_timestamp + archive info.mtime pin release archive mtimes, a `make reproduce` target verifies the binary is bit-for-bit identical across two builds, documented in docs/reproducible-builds.md

* signed releases: cosign keyless (Sigstore) signing of release archives and checksums via goreleaser signs, attaching .sigstore.json bundles to the GitHub Release; documented verification in docs/verification.md (also closes the OpenSSF Scorecard signed-releases gap)

* signed version tags: release workflow signs the release tag with gitsign keyless (Sigstore X.509) via git tag -s, using GitHub Actions OIDC (id-token: write); documented tag verification in docs/verification.md

* contributor onboarding docs: CONTRIBUTING.md now identifies small tasks for new or casual contributors (good first issue / help wanted labels and example tasks) and documents the code review process (how review is conducted, what must be checked, and the acceptance bar)

* release-time dynamic analysis: the release workflow now runs the Go race detector (make test-go) and the fuzz targets (make fuzz) before tagging a release, asserting parser invariants at run time as a release gate

* scorecard branch-protection: the Scorecard workflow now passes the SCORECARD_TOKEN PAT (Administration: Read-only) to the scorecard-action so the Branch-Protection check can read classic branch-protection rules, which the default GITHUB_TOKEN cannot

* Outgoing shares now default to a managed content root at .ocm/files (config persistence.content_dir) instead of ad-hoc /tmp paths: the root is created on boot, a hello-ocm.txt seed file is written if absent, and the share allowlist defaults to it, so a share can be created by entering a filename relative to the managed root.

* OCM federation notifications are now supported. A POST /ocm/notifications inbound handler accepts SHARE_ACCEPTED, SHARE_DECLINED, and SHARE_UNSHARED notifications over HTTP Message Signatures: ACCEPTED and DECLINED update the matching outgoing share's status (terminal, with sender-host authorization), and UNSHARED revokes local access on the matching incoming share. The inbox accept and decline flows now post a best-effort SHARE_ACCEPTED or SHARE_DECLINED notification to the original sender asynchronously when that peer advertises the notifications capability, without blocking the local response. The notifications capability is advertised in discovery. Experimental notification types are rejected. Outbound SHARE_UNSHARED is deferred.

### Changed

* enable the wrapcheck linter project-wide and wrap every external error return with fmt.Errorf using the %w verb and the subsystem voice convention so merges fail on unwrapped external errors

* build foundation: switch the SQLite driver to pure-Go glebarez to drop the CGO dependency, add a reusable build-go composite action and a reusable docker-build workflow, add a ci-build dispatcher, and pin the install-nushell action archive digest with a verify step

* test, policy, and rollup CI: group test workflows under a ci-test dispatcher (unit, e2e, and scheduled native Go fuzz targets), extract the reuse and action-pins checks into reusable workflows with hierarchical ci-*/policy-*/scheduled-* naming, slim the ci.yml rollup with hardened !cancelled() gating and a parity invariant across CI jobs, and declare minimal contents:read permission scope on reusable build, test, fmt-vet, and shellcheck workflows

* ci and tooling polish: derive the lint-new base ref from the master merge-base (replacing the pinned SHA), consolidate the unreleased changelog, extend Dependabot to the uv ecosystem (gomod retained), switch the ci.yml rollup gate from always() to !cancelled(), pin hadolint with a SHA256-verified direct CI install and add hygiene pre-commit hooks for markdownlint, typos, hadolint, and yamllint, migrate the markdown linter from markdownlint-cli2 to rumdl with hierarchical .rumdl.toml config and a SHA256-verified CI install, rename the markdownlint workflow to rumdl, and document the unit, e2e, and fuzz CI wiring in docs/testing.md

* enable thelper, modernize, usetesting, and godoclint in golangci-lint and burn down their findings tree-wide; document the globally disabled linters (paralleltest, err113, goconst, funcorder) in docs/lint-policy.md with paralleltest framed as a structural integration-harness constraint (process-global chdir and env scrub at tests/integration/harness/subprocess.go) rather than a deferred-readiness waiver; add a lint-policy drift check (nu script plus CI step) that treats .golangci.yml as the single source of truth and fails when the generated disable-inventory block in docs/lint-policy.md drifts

* split 22 Go files that exceeded the 500-line cap and add a blocking file-length gate (make file-length plus nested CI lint job under ci-lint.yml) so merges fail when any tracked Go file exceeds the limit

* enable the nlreturn, perfsprint, and godot style linters project-wide and auto-fix all violations so CI enforces blank-line-before-return, strconv over fmt.Sprintf, and comment-ending punctuation.

* enable the funcorder linter project-wide and auto-fix all violations to enforce constructor-then-method function ordering, reversing the prior permanent-disable decision.

* enable the goconst and mnd linters project-wide; goconst excludes test files and extracts production repeated strings to constants, and mnd uses an idiomatic-value allowlist so only genuine magic numbers (HTTP statuses, ports, bit masks) require named constants.

* enable the paralleltest linter project-wide so CI enforces t.Parallel() in every test; the 26 tests that genuinely cannot run concurrently (t.Setenv, t.Chdir, slog.SetDefault, shared parent env/cwd, package-level hooks) carry justified //nolint:paralleltest exceptions verified at their exact finding lines, and the module-root resolvers (testsupport/modroot and the integration harness) are made CWD-independent via runtime.Caller so parallel subtests no longer race with the harness os.Chdir.

* narrow the gosec global excludes (G304, G306, G104, G101, G115) into a scoped policy: G104 stays suppressed by its text exclusion as redundant with the strict errcheck, test and testsupport findings are suppressed by a path-scoped exclusion, and the 13 real-production G304/G306/G101 findings carry inline //nolint:gosec directives naming the specific accepted constraint while the one G115 finding is fixed with a bounds check.

* The rate-limit middleware now fails closed with 503 when the counter cache errors instead of allowing the request through. Latent until a Redis cache is wired; in-memory caches never error.

* Documented that a nil peer-trust policy engine means peer-trust is off (test-skip), not a fail-closed state.

* ocmgo now advertises and accepts only the "file" OCM resource type. Discovery no longer lists "folder", incoming shares with resourceType "folder" are rejected with 501 RESOURCE_TYPE_NOT_SUPPORTED, and outgoing share creation refuses directory paths and explicit non-"file" resource types with 400. This aligns the advertised contract with what the single-file WebDAV server actually serves, so peers no longer receive folder shares they cannot honor.

* The inbox verify-access endpoint no longer routes webapp shares through a dead selector that always failed with a confusing "access protocol must be webdav" error. Webapp shares now return an explicit 501 unsupported_protocol before any remote access attempt, matching the advertised file-only contract. The discovery documentation for the must-invite criterion is also corrected: it is advertised and enforced by default and cleared by ocm.invite.enforce_must_invite=false, replacing the stale "omitted (not yet enforced)" wording.

### Fixed

* CodeQL SAST fixes: stop logging auto-generated admin passwords to slog/stdout/stderr and write them to a mode-0600 file with only the path logged; harden external base-path redirect validation with backslash rejection, a shared validator, and safe fallback to close the open-redirect vector

* Dependabot config: add a grouping criterion (patterns: ["*"]) to the security-update groups for gomod and uv so the config validates; a group with only applies-to is rejected by Dependabot's schema and broke the .github/dependabot.yml CI check

* JSON and mirror stores now fsync the data directory after the temp-file rename so crashes do not lose the directory entry linking the new file.

* OutgoingShare.Requirements and IncomingShare.WebappTargets are deep-copied at store boundaries so callers cannot mutate cached share state.

* Driver Register panics on nil factory or empty name at startup; duplicate registration overwrites. Added Unregister for test isolation.

* Auth, session, and recipient-lookup handlers now return 500 on non-sentinel repository errors instead of masking them as 401/400, so a real backend outage is no longer indistinguishable from a missing user.

* OCM token exchange now returns the OAuth 2.0 server_error code (RFC 6749 5.2) on internal 500 errors instead of invalid_request, while keeping the 501 not_implemented path unchanged.

* Discovery capability lookups no longer panic on a nil receiver.

* Peer-trust refresh now claims the refresh flag and releases the lock before spawning the refresh goroutine, so concurrent stale triggers coordinate as single-flight and exactly one refresh runs.

* Outgoing shares are now persisted locally before being delivered to the receiver, with a pending/sent/failed state machine, so a successful delivery can no longer leave an orphan share that the sender has no record of; failed deliveries retain the delivery error on the share record for audit.

* Incoming duplicate shares (same senderHost and providerId) are now compared against the stored payload: an identical retransmission returns 201 idempotently, while a re-send with changed material fields (name, resourceType, shareWith, WebDAV URI/secret/permissions/requirements, etc.) returns 409 instead of silently keeping the stale stored row. Create success is aligned with the spec-normative 201.

### Security

* CI workflow security hardening: pin every GitHub Action to an immutable commit SHA with a stale-pin freshness gate, add go-licenses checks, container image attestations with report-only trivy scanning (continue-on-error, fails only on CRITICAL findings), a security policy with private vulnerability reporting, and blocking hygiene linters (typos, yamllint, hadolint, shellcheck, markdownlint, actionlint)

* CI/CD security polish: install Go before CodeQL init and fix the stale CodeQL workflow header; pin Docker base images by digest; bump dorny/paths-filter to v4.0.3; scope GITHUB_TOKEN permissions to least privilege across workflows; disable the setup-go cache in the release workflow to mitigate zizmor's cache-poisoning finding; tighten dependency-review to moderate severity and runtime, development, unknown scopes; document OpenSSF Scorecard and dependency-review posture in SECURITY.md

* JWK verification now rejects RSA keys below 2048 bits by default (configurable via signature.min_rsa_modulus_bits). Breaking for weak RSA peers that remain OCM-valid; lower the floor to interoperate with legacy 1024-bit RSA peers.

* HTTP servers now set ReadHeaderTimeout (10s) on both the main and ACME challenge listeners to bound slowloris-style header reads.

* ACME HTTPS redirect now builds the Location from the configured ACME domain instead of the request Host, preventing Host-header spoofing from redirecting clients to an attacker-chosen host. ACME mode now requires tls.acme.domain.

* POST /api/auth/login now bounds the request body to 4096 bytes and returns 413 on overflow, mirroring the OCM body-limit pattern.

* Outgoing share delivery no longer echoes the peer response body in error messages; only the peer HTTP status and response size are logged, and the client receives a stable message.

* WebDAV shared-secret comparison now uses constant-time comparison.
<!--
SPDX-License-Identifier: AGPL-3.0-or-later
SPDX-FileCopyrightText: OpenCloudMesh Go contributors
-->

## v1.1.0

This is a pre-changelog bootstrap stub. Releases v1.0.0 and v1.1.0 predate
the changie changelog system, so no retroactive changelog is reconstructed
here. See the git history for the changes that landed before changie was
introduced. From this point on, per-release notes are generated by changie
from the fragments under `.changes/unreleased/`.
