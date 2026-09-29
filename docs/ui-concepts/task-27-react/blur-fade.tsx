// Adapted from Magic UI Blur Fade (https://magicui.design/r/blur-fade.json).
// MIT License © Magic UI; full permission notice: ./THIRD_PARTY_NOTICES.md.
// Adaptation: reduced-motion renders immediately; no hidden essential content on intersection.
import { useRef, type ReactNode } from 'react';
import { motion, useInView, useReducedMotion } from 'motion/react';

export function BlurFade({
  children,
  className,
  delay = 0,
}: {
  children: ReactNode;
  className?: string;
  delay?: number;
}) {
  const ref = useRef<HTMLDivElement>(null);
  const visible = useInView(ref, { once: true, margin: '-40px' });
  const reduced = useReducedMotion();
  return (
    <motion.div
      ref={ref}
      className={className}
      initial={false}
      animate={
        reduced || visible
          ? { opacity: 1, y: 0, filter: 'blur(0px)' }
          : { opacity: 0.65, y: 14, filter: 'blur(3px)' }
      }
      transition={{ duration: reduced ? 0 : 0.65, delay: reduced ? 0 : delay }}
    >
      {children}
    </motion.div>
  );
}
