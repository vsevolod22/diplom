import { useRef } from 'react';
import { motion, useInView, useReducedMotion } from 'motion/react';
import { GlowEffect } from './GlowEffect';

type ScanSceneProps = {
  variant: 'list' | 'create' | 'detail';
  className?: string;
};

const sceneCopy = {
  list: { word: 'АРХИВ', code: '01 / RECORD', steps: ['ЦЕЛЬ', 'ГРАНИЦЫ', 'ОТЧЁТ'] },
  create: { word: 'ОБЛАСТЬ', code: '02 / SCOPE', steps: ['ОБРАЗ', 'ДОСТУП', 'ЗАПУСК'] },
  detail: { word: 'ФАКТЫ', code: '03 / EVIDENCE', steps: ['ЦЕЛЬ', 'ПОКРЫТИЕ', 'ВЫВОД'] },
};

const palettes = {
  list: ['#d1ff5e', '#8d7bec', '#46406a', '#d1ff5e'],
  create: ['#a692ff', '#fa8a77', '#503766', '#a692ff'],
  detail: ['#71d7db', '#8d7bec', '#353960', '#71d7db'],
};

// Only this non-semantic artwork is allowed to enter on scroll. Real content is never its child.
export function ScanScene({ variant, className = '' }: ScanSceneProps) {
  const ref = useRef<HTMLDivElement>(null);
  const visible = useInView(ref, { amount: 0.15 });
  const reduced = useReducedMotion();
  const copy = sceneCopy[variant];
  return (
    <div ref={ref} aria-hidden="true" className={`scan-a1__scene scan-a1__scene--${variant} ${className}`}>
      <GlowEffect
        colors={palettes[variant]}
        mode={reduced || !visible ? 'static' : variant === 'create' ? 'pulse' : 'rotate'}
        duration={variant === 'detail' ? 12 : 8}
        blur="soft"
        scale={1.2}
      />
      <motion.div
        data-scan-scene-art={variant}
        className="scan-a1__scene-art"
        initial={false}
        animate={{
          opacity: reduced ? 1 : visible ? 1 : 0.25,
          y: reduced ? 0 : visible ? 0 : 36,
          rotate: reduced ? 0 : visible ? 0 : -12,
        }}
        transition={{ duration: reduced ? 0 : 0.85, ease: 'easeOut' }}
      >
        <span className="scan-a1__scene-code">{copy.code}</span>
        <span className="scan-a1__scene-word">{copy.word}</span>
        <span className="scan-a1__scene-tracks">
          {copy.steps.map((step, index) => (
            <span className="scan-a1__scene-track" key={step}>
              <span>0{index + 1}</span>
              <span>{step}</span>
            </span>
          ))}
        </span>
        <span className="scan-a1__scene-footnote">СИГНАЛ / КАРТА ЧТЕНИЯ</span>
      </motion.div>
    </div>
  );
}
