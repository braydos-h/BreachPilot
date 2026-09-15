# P1: Public release state lags source substantially

## Problem
Source is at version 0.68.4 on HEAD 995759f (reliability-focused 0.69 beta), while the public release remains at v0.49.2. There is no atomic tag-to-publish path, so source advances have not produced a corresponding public release.

## Why it matters
Users evaluating or installing the public release see a version substantially older than source, understating current reliability work and overstating staleness. Without an atomic tag-to-publish lifecycle, each release risks partial or inconsistent publication.

## Recommended action
Complete the release publication lifecycle for 0.69: cut, verify, tag, and publish so the public release matches source.

## Acceptance criteria
- [ ] Public release version matches the 0.69 source version
- [ ] Release tag exists for the published 0.69 commit
- [ ] Tag-to-publish steps complete atomically with no partial publication
- [ ] Published release artifacts verified installable and version-consistent
- [ ] Public release notes reflect the reliability-focused 0.69 scope

## Audit ref
Secs 23, 33 + commit 995759f
