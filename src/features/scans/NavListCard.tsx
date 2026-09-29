// Adapted from Spectrum UI Nav List Card (Apache-2.0); see docs/notices/spectrum-ui.md.
import { useId, type ReactNode } from 'react';
import { motion, useReducedMotion } from 'motion/react';
import { Link } from 'react-router-dom';

type NavItem = { label: string; to: string; icon: ReactNode; current?: boolean; description: string };

export function NavListCard({ items }: { items: NavItem[] }) {
  const reducedMotion = useReducedMotion();
  const id = useId();

  return (
    <nav aria-label="Разделы сканирования" className="scan-shell__nav scan-nav-card">
      <p className="scan-nav-card__label">МАРШРУТ / ВЫБЕРИТЕ РАЗДЕЛ</p>
      <ul className="scan-nav-card__items">
        {items.map((item, index) => (
          <li key={item.to}>
            <Link
              to={item.to}
              aria-labelledby={`${id}-label-${index}`}
              aria-describedby={`${id}-description-${index}`}
              aria-current={item.current ? 'page' : undefined}
            >
              <motion.span
                className="scan-nav-card__item"
                whileHover={reducedMotion ? undefined : { x: 4 }}
                whileTap={reducedMotion ? undefined : { scale: 0.98 }}
                transition={{ type: 'spring', bounce: 0.4, duration: 0.3 }}
              >
                <span className="scan-nav-card__number" aria-hidden="true">
                  0{index + 1}
                </span>
                <span className="scan-nav-card__copy">
                  <strong id={`${id}-label-${index}`}>{item.label}</strong>
                  <small id={`${id}-description-${index}`}>{item.description}</small>
                </span>
                <span className="scan-nav-card__icon" aria-hidden="true">
                  {item.icon}
                </span>
              </motion.span>
            </Link>
          </li>
        ))}
      </ul>
    </nav>
  );
}
