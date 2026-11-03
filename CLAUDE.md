# Working rules for cephadm-talos

## Permission

- Never commit to `main` without explicit permission from the user, given for that commit. Never push without it either.
- Otherwise work autonomously: research, draft, edit and test without asking.

## Roadmap work

- Before implementing a roadmap item ([ROADMAP.md](ROADMAP.md)), write a plan for it (one item, or several related items together) and get the user's sign-off. No implementation before sign-off.
- Every change to the roadmap, its plans or its implementation goes through a fix-or-refute loop with Codex: Codex reviews, each finding is fixed or refuted with evidence, then Codex reviews again. Leave the loop only when a round has nothing left to fix. Report which findings were fixed and which refuted, and why.
- Use Codex for consults too (design questions, second opinions), not only reviews, next to the advisor.

## Versions

- Until Talos 1.15.0 is released, always use the latest Talos pre-release (alpha or beta) for `pkg/machinery` and the test cluster. Supported: Talos 1.15 or later.
- Exception (plan 03, signed off 2026-10-30): while our Talos PRs (#14775, #14781, #14788, #14795) are unmerged, `pkg/machinery` and the test cluster come from one combined build of those branches, always the same commit for both. The supported Talos release becomes the first one containing them.
- Ceph: only the latest release is supported (today v21.2.0). Check `crane ls quay.io/ceph/ceph` before relying on the pinned version; a release may have no git tag (v21.2.0), then its source commit is the image's `CEPH_SHA1` label.
- amd64 only for now; arm64 later.
- No migration or backwards compatibility is needed before the first tagged release.

## Codex

- Run it with `node ~/.claude/plugins/cache/openai-codex/codex/<version>/scripts/codex-companion.mjs task --fresh "<prompt>"` in the foreground (timeout up to 600000 ms); tell it not to edit files when reviewing.
- Codex has no internet. Give it local sources: the Talos source at the pinned commit, Omni and Ceph checkouts (`/home/nicob/repo/ceph`, and the supported release's sources in `/home/nicob/repo/ceph-v21.2.0`), and excerpts of GitHub issues saved to the session scratchpad.
- Pass previous rounds' findings to the next round, and ask it to say "clean" when nothing substantive remains.

## Writing

- Talos issues and comments (`upstream/talos/`): terse, the feature first, generic use cases before "Our case", reference existing Talos mechanisms, no asks a maintainer can easily knock down. The user files them; record filed links in `upstream/talos/README.md`.
- No em or en dashes, straight quotes only, one paragraph per line.
