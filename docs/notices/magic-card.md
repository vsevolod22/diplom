# Magic UI MagicCard — third-party notice

Source: https://github.com/magicuidesign/magicui/blob/d7207e5692d14c00dceafa8488d6d01f197fa0e4/apps/www/registry/magicui/magic-card.tsx (commit `d7207e5692d14c00dceafa8488d6d01f197fa0e4`, Git blob `3b022df0d33bbf21b05a386a56860c6ad887edb0`). Registry endpoint: https://magicui.design/r/magic-card.json. Original source SHA-256: `6139e78ed228ebca18ed144f4a2714a89214c2ef604f1f82bc2f61204c3f3fa3` (6314 bytes); fetched registry JSON SHA-256: `d487ae39795640bd3fbb467a5a98285a4c803036d71e5b1a9a06cb7d26c2a755` (7066 bytes). Both measured 2026-09-29. Local adaptation: `src/features/scans/MagicCard.tsx`, retains upstream pointer-tracking `useMotionValue`/`useMotionTemplate` gradient mode and layered spotlight; omits unused orb/theme mode and global listeners, replaces unavailable `@/lib/utils` alias and global theme tokens with scan-scoped CSS variables, marks decoration aria-hidden and disables spotlight for reduced motion. No upstream AnimatedGroup, BlurFade or BorderBeam code was copied.

Copyright (c) Magic UI. Upstream license: https://github.com/magicuidesign/magicui/blob/d7207e5692d14c00dceafa8488d6d01f197fa0e4/LICENSE.md (MIT). The upstream registry declares `motion` and `next-themes` dependencies. This adaptation uses `motion/react` only, already installed in this project (its resolved version and integrity are pinned in `pnpm-lock.yaml`; the lockfile does not contain license text. Installed `motion` and `next-themes` package metadata both report MIT (checked 2026-09-29)); `next-themes` is already installed but not imported here. No new package was installed.

## MIT License — Magic UI

Copyright (c) Magic UI

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
