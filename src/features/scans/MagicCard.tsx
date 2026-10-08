// Adapted from Magic UI MagicCard (MIT); provenance and full notice: docs/notices/magic-card.md.
import type { PointerEvent, ReactNode } from 'react';
import { motion, useMotionTemplate, useMotionValue, useReducedMotion } from 'motion/react';

type MagicCardProps = {
  children: ReactNode;
  className?: string;
  gradientSize?: number;
  gradientColor?: string;
  gradientFrom?: string;
  gradientTo?: string;
};

// Gradient mode of the upstream component. Orb/theme mode is not used by scan surfaces.
export function MagicCard({
  children,
  className = '',
  gradientSize = 200,
  gradientColor = '#51476b',
  gradientFrom = '#d1ff5e',
  gradientTo = '#9e7aff',
}: MagicCardProps) {
  const mouseX = useMotionValue(-gradientSize);
  const mouseY = useMotionValue(-gradientSize);
  const reducedMotion = useReducedMotion();
  const border = useMotionTemplate`linear-gradient(var(--color-background) 0 0) padding-box, radial-gradient(${gradientSize}px circle at ${mouseX}px ${mouseY}px, ${gradientFrom}, ${gradientTo}, var(--color-border) 100%) border-box`;
  const spotlight = useMotionTemplate`radial-gradient(${gradientSize}px circle at ${mouseX}px ${mouseY}px, ${gradientColor}, transparent 100%)`;
  const reset = () => {
    mouseX.set(-gradientSize);
    mouseY.set(-gradientSize);
  };
  const move = (event: PointerEvent<HTMLDivElement>) => {
    if (
      event.pointerType !== 'mouse' ||
      reducedMotion ||
      window.matchMedia('(prefers-reduced-motion: reduce)').matches
    )
      return;
    const rect = event.currentTarget.getBoundingClientRect();
    mouseX.set(event.clientX - rect.left);
    mouseY.set(event.clientY - rect.top);
  };

  return (
    <motion.div
      className={`scan-a1__magic relative isolate border border-transparent ${className}`}
      onPointerMove={move}
      onPointerLeave={reset}
      onPointerCancel={reset}
      style={{ background: border }}
    >
      <div
        aria-hidden="true"
        className="pointer-events-none absolute inset-px z-20 bg-[var(--color-background)]"
      />
      <motion.div
        aria-hidden="true"
        className="scan-a1__spotlight pointer-events-none absolute inset-px z-30 opacity-0 transition-opacity duration-200"
        style={{ background: spotlight }}
      />
      <div className="relative z-40">{children}</div>
    </motion.div>
  );
}
