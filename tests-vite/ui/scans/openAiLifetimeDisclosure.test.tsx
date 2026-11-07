import '@testing-library/jest-dom/vitest';
import { cleanup, fireEvent, render, screen } from '@testing-library/react';
import { afterEach, expect, it } from 'vitest';
import { OpenAiDisclosure } from '@/features/scans/OpenAiDisclosure';
import { lifetimeContext } from './lifetimeBudgetFixtures';

const base = lifetimeContext.disclosure;
if (base?.provider !== 'OpenAI' || base.monetaryLimit !== 'uncapped')
  throw new Error('Expected uncapped disclosure');
const disclosure = { ...base, lifetimeUserCostMicros: 5000000 };

afterEach(cleanup);

it.each([false, true])('shows the lifetime cap from disclosure before usage or consent, chat=%s', (chat) => {
  const view = render(<OpenAiDisclosure disclosure={disclosure} chat={chat} />);
  expect(screen.getByText(/Платный ИИ: \$5 на аккаунт за всё время/)).toBeVisible();
  expect(screen.getByText(/не счёт провайдера/)).toBeVisible();
  expect(screen.getByText(/ZDR не подтверждён/)).toBeVisible();
  fireEvent.click(screen.getByText('Стоимость и ограничения', { selector: 'summary' }));
  expect(
    screen.getByText(/Бюджет аккаунта — \$5 на аккаунт за всё время, без сброса со сменой суток/),
  ).toBeVisible();
  expect(screen.getByText(/Денежные лимиты запроса и суток не установлены/)).toBeVisible();
  expect(screen.getByText(/Оконные счётчики токенов — статистика, не блокирующие бюджеты/)).toBeVisible();
  expect(view.container).not.toHaveTextContent('без локального денежного лимита');
  expect(view.container).not.toHaveTextContent('Локальный предел расходов не установлен');
  expect(view.container).not.toHaveTextContent('токенные квоты');
  expect(screen.getByText(/Отмена не возвращает уже возможный расход/)).toBeVisible();
  expect(view.container.textContent).toContain(chat ? 'история пользовательских сообщений' : 'Без исходных');
});

it.each([
  [1, '$0.000001'],
  [5000001, '$5.000001'],
  [1_000_000_000, '$1000'],
] as const)('renders the declared lifetime limit %i exactly, without hardcoding $5', (limit, amount) => {
  render(<OpenAiDisclosure disclosure={{ ...disclosure, lifetimeUserCostMicros: limit }} />);
  expect(
    screen.getByText((content) => content.includes(`Платный ИИ: ${amount} на аккаунт за всё время`)),
  ).toBeVisible();
});

it('keeps legacy uncapped disclosure without inventing a lifetime amount', () => {
  const legacy = { ...base };
  delete legacy.lifetimeUserCostMicros;
  render(<OpenAiDisclosure disclosure={legacy} />);
  expect(screen.getByText(/без локального денежного лимита — это не бесплатный режим/)).toBeVisible();
  fireEvent.click(screen.getByText('Стоимость и ограничения', { selector: 'summary' }));
  expect(screen.getByText(/Локальный предел расходов не установлен/)).toBeVisible();
  expect(screen.queryByText(/\$5 на аккаунт за всё время/)).not.toBeInTheDocument();
});

it('preserves capped disclosure and does not let additive metadata relabel its mode', () => {
  const capped = {
    ...disclosure,
    monetaryLimit: 'capped' as const,
    requestBudgetMicros: 10000,
    userBudgetMicros: 100000,
    scanBudgetMicros: 50000,
  };
  render(<OpenAiDisclosure disclosure={capped} />);
  expect(screen.getByText(/с серверными денежными лимитами/)).toBeVisible();
  fireEvent.click(screen.getByText('Стоимость и ограничения', { selector: 'summary' }));
  expect(screen.getByText(/запрос — 10000; пользователь — 100000; скан — 50000/)).toBeVisible();
  expect(screen.queryByText(/\$5 на аккаунт за всё время/)).not.toBeInTheDocument();
});
