# Motion Primitives GlowEffect — third-party notice

Source: https://raw.githubusercontent.com/ibelick/motion-primitives/120f64f6ca60348e251f929e9c81f11ccbe45eda/components/core/glow-effect.tsx (commit `120f64f6ca60348e251f929e9c81f11ccbe45eda`). SHA-256 of original raw source: `cd9f31a6d7cf261801569547241530794f578b37b946ff320bd6192897658949` (measured 2026-09-29). Upstream license: https://raw.githubusercontent.com/ibelick/motion-primitives/120f64f6ca60348e251f929e9c81f11ccbe45eda/LICENCE.md. Local adaptation: `src/features/scans/GlowEffect.tsx`, retaining upstream `motion.div`, `colors`, `mode`-driven conic/radial gradients and repeat transitions. Removed unused modes, transition/style passthrough, dynamic Tailwind blur classes and `@/lib/utils`; blur, scope and viewport/reduced-motion controls live in scan-specific CSS and `ScanScene.tsx` (the latter is original project code, not a copied InView). `motion/react` is already installed; package metadata reports MIT. The lockfile pins version/integrity, not license terms. No upstream InView implementation was copied.

## MIT License — Motion Primitives

Copyright (c) 2024 ibelick

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
