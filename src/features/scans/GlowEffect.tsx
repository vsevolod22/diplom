// Adapted from Motion Primitives GlowEffect (MIT); provenance: docs/notices/motion-primitives.md.
import type { CSSProperties } from 'react';
import { motion } from 'motion/react';

type GlowEffectProps = {
  colors: string[];
  mode?: 'rotate' | 'pulse' | 'static';
  duration?: number;
  blur?: 'soft' | 'strong';
  scale?: number;
};

export function GlowEffect({
  colors,
  mode = 'rotate',
  duration = 8,
  blur = 'soft',
  scale = 1,
}: GlowEffectProps) {
  const baseTransition = { repeat: Infinity, duration, ease: 'linear' as const };
  const animations = {
    rotate: {
      background: [
        `conic-gradient(from 0deg at 50% 50%, ${colors.join(', ')})`,
        `conic-gradient(from 360deg at 50% 50%, ${colors.join(', ')})`,
      ],
      transition: baseTransition,
    },
    pulse: {
      background: colors.map((color) => `radial-gradient(circle at 50% 50%, ${color} 0%, transparent 100%)`),
      scale: [scale, scale * 1.1, scale],
      opacity: [0.5, 0.8, 0.5],
      transition: { ...baseTransition, repeatType: 'mirror' as const },
    },
  };

  return (
    <motion.div
      data-scan-glow={mode}
      aria-hidden="true"
      className={`scan-a1__glow-effect ${blur === 'strong' ? 'scan-a1__glow-effect--strong' : ''}`}
      style={
        {
          '--scale': scale,
          backfaceVisibility: 'hidden',
          ...(mode === 'static' ? { background: `linear-gradient(to right, ${colors.join(', ')})` } : {}),
        } as CSSProperties
      }
      animate={mode === 'static' ? undefined : animations[mode]}
    />
  );
}
