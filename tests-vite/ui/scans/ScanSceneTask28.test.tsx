import { cleanup, render, screen } from '@testing-library/react';
import { renderToStaticMarkup } from 'react-dom/server';
import { afterEach, describe, expect, it } from 'vitest';
import { GlowEffect } from '@/features/scans/GlowEffect';
import { MagicCard } from '@/features/scans/MagicCard';
import { ScanScene } from '@/features/scans/ScanScene';

afterEach(cleanup);

describe('TASK28 static scene contract', () => {
  for (const variant of ['list', 'create', 'detail'] as const) {
    it(`${variant}: immediate nested route illustration without interactive or animated content`, () => {
      const html = renderToStaticMarkup(<ScanScene variant={variant} className="caller-class" />);
      const { container } = render(<ScanScene variant={variant} className="caller-class" />);
      const scene = container.querySelector('.scan-a1__scene');
      expect(scene?.getAttribute('aria-hidden')).toBe('true');
      expect(scene?.classList.contains('caller-class')).toBe(true);
      expect(scene?.querySelector(`[data-scan-scene-art="${variant}"]`)).not.toBeNull();
      expect(scene?.querySelector('.scan-a1__passport-scope .scan-a1__passport-rows')).not.toBeNull();
      expect(scene?.querySelectorAll('a, button, input, [tabindex], canvas')).toHaveLength(0);
      expect(scene?.querySelectorAll('svg')).toHaveLength(3);
      expect(scene?.textContent).toContain('Цель');
      expect(scene?.textContent).toContain('Отчёт');
      expect(scene?.textContent).toContain('не результат');
      expect(html).not.toMatch(/opacity:0|transform:|data-scan-glow|\d+%|progressbar/);
      expect(scene?.querySelectorAll('[role]')).toHaveLength(0);
    });
  }
  it('GlowEffect is static by default, including server render', () => {
    const html = renderToStaticMarkup(<GlowEffect colors={['#fff', '#000']} />);
    expect(html).toContain('data-scan-glow="static"');
    expect(html).toContain('linear-gradient');
    expect(html).not.toMatch(/conic|transform|opacity:0/);
  });
  it('MagicCard keeps facts and keyboard controls outside hidden decoration', () => {
    const { container } = render(
      <MagicCard>
        <p>Прогресс: неизвестен</p>
        <a href="#report">Читать отчёт</a>
      </MagicCard>,
    );
    expect(screen.getByRole('link', { name: 'Читать отчёт' })).toBeTruthy();
    expect(screen.getByText('Прогресс: неизвестен').closest('[aria-hidden]')).toBeNull();
    expect(container.querySelectorAll('[aria-hidden="true"]')).toHaveLength(2);
    expect(container.querySelector('[aria-hidden] a')).toBeNull();
  });
});
