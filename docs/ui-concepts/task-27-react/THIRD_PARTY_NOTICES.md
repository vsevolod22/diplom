# Prototype component provenance

`blur-fade.tsx` is adapted from Magic UI's Blur Fade registry source: https://magicui.design/r/blur-fade.json (retrieved 2026-09-29). Adaptations: simplified props, `initial=false` so essential text is never initially hidden, reduced-motion branch and lower-cost scroll reveal. Upstream registry JSON was not immutable/pinned; do not treat this copy as a production-approved component. Dependency: `motion` (already declared in this repository). The prototype also imports `@radix-ui/react-tabs` and `@radix-ui/react-accordion` directly; these are upstream Radix primitives (not copies of shadcn/ui registry wrapper source). No Magic UI component is imported into production pages.

## Magic UI license

MIT License

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

License source: https://raw.githubusercontent.com/magicuidesign/magicui/main/LICENSE.md (retrieved 2026-09-29). Verify exact upstream registry commit/hash and dependency notices before production reuse.
