import '@testing-library/jest-dom/vitest';
import { act, cleanup, render, screen, within } from '@testing-library/react';
import { afterEach, describe, expect, it, vi } from 'vitest';
import { RouteLoading } from '@/shared/ui/RouteLoading';

const cases = [
  {
    name: 'default route fallback',
    props: {},
    label: 'Загрузка страницы',
    title: 'Загружаем страницу…',
    description: 'Содержимое появится, когда страница будет готова.',
  },
  {
    name: 'pending session',
    props: {
      label: 'Проверка сессии',
      title: 'Проверяем сессию…',
      description: 'Данные скрыты до успешной проверки.',
    },
    label: 'Проверка сессии',
    title: 'Проверяем сессию…',
    description: 'Данные скрыты до успешной проверки.',
  },
  {
    name: 'session identity confirmation',
    props: {
      label: 'Подтверждение сессии',
      title: 'Подтверждаем сессию…',
      description: 'Данные скрыты до успешной проверки.',
    },
    label: 'Подтверждение сессии',
    title: 'Подтверждаем сессию…',
    description: 'Данные скрыты до успешной проверки.',
  },
];

function expectNoFabricatedProgress(container: HTMLElement) {
  expect(screen.queryByRole('progressbar', { hidden: true })).not.toBeInTheDocument();
  expect(screen.queryByRole('timer', { hidden: true })).not.toBeInTheDocument();
  expect(container.querySelector('progress, meter, [aria-valuenow], [aria-valuetext]')).toBeNull();
  expect(container.textContent).not.toMatch(/\d+(?:[.,]\d+)?\s*%|\d+\s*(?:сек|мин|sec|min)|\b\d{1,2}:\d{2}\b/i);
}

afterEach(() => {
  cleanup();
  vi.useRealTimers();
});

describe.each(cases)('RouteLoading: $name', ({ props, label, title, description }) => {
  it('retains the accessible label, polite atomic status and explanatory text', () => {
    render(<RouteLoading {...props} />);
    const main = screen.getByRole('main', { name: label });
    expect(main).toBeVisible();
    const status = within(main).getByRole('status');
    expect(status).toBeVisible();
    expect(status).toHaveAttribute('aria-live', 'polite');
    expect(status).toHaveAttribute('aria-atomic', 'true');
    expect(status).toHaveTextContent(title);
    expect(within(main).getByText(description)).toBeVisible();
  });

  it('does not render skeleton placeholders, including aria-hidden ones', () => {
    const { container } = render(<RouteLoading {...props} />);
    // Inspect hidden DOM too: removing placeholders from the accessibility tree is not removing them.
    expect(container.querySelector('[class*="skeleton"], [class*="placeholder"], [data-slot="skeleton"]')).toBeNull();
    expect(container.querySelector('.route-loading__line')).toBeNull();
  });

  it('does not invent progress or schedule timers while waiting', () => {
    vi.useFakeTimers();
    const timersBefore = vi.getTimerCount();
    const { container, unmount } = render(<RouteLoading {...props} />);
    expectNoFabricatedProgress(container);
    expect(vi.getTimerCount()).toBe(timersBefore);
    const initialText = container.textContent;

    act(() => { vi.advanceTimersByTime(120_000); });

    expect(container.textContent).toBe(initialText);
    expectNoFabricatedProgress(container);
    expect(vi.getTimerCount()).toBe(timersBefore);
    unmount();
    expect(vi.getTimerCount()).toBe(timersBefore);
  });
});
