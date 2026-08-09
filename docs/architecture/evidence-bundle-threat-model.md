# Evidence bundle persistence threat model

Evidence bundles are pure records, not a claim that Containerlab, Docker, traffic, or a
target device ran.  Their canonical UTF-8 JSON uses sorted keys, compact separators, and
`allow_nan=False`; the SHA-256 is lowercase and content-addresses the envelope.  Requirements
have an independent canonical hash which the envelope binds, so observed results cannot alter
the required evidence contract.  A bundle is not an approval, promotion, or trusted-authority
token; consumers must make any operational decision outside this format.

Persistence accepts only an existing absolute non-symlink root.  Each component is opened with
directory-FD-relative `O_DIRECTORY`/`O_NOFOLLOW`, so validation and use share the same verified
directory descriptors.  The store derives its filename solely from the canonical hash; it never
accepts a caller-provided relative path.  It creates an `O_EXCL`/`O_NOFOLLOW` temporary file in
that directory, fsyncs it, creates the final name with a no-replace hard link, fsyncs the
directory, and removes only its own temporary file.  Existing files, collisions, traversal, and
root symlinks are rejected.

Command transcripts contain only closed command-kind metadata, never argv or redacted argv.
Captures are immutable references (SHA-256, media type, size, role), never arbitrary file paths.
`structurally_complete()` reports missing links rather than granting authority: each required
axis needs clause coverage, a `PASS` observation, and a referenced capture; required provenance
clauses must also be present.  Image and component digests use strict OCI `sha256:` digests.
