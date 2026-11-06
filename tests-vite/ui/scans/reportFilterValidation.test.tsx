import '@testing-library/jest-dom/vitest';
import { cleanup, render, screen, within } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { afterEach, describe, expect, it, vi } from 'vitest';
import { SbomReportControls, SecretReportControls } from '@/pages/scans/ReportViewControls';

const scenarios = [
  {
    kind: 'sbom',
    field: 'Название пакета',
    submit: 'Найти пакет',
    reset: 'Сбросить название',
    valid: '@scope/package',
    invalid: 'bad package',
  },
  {
    kind: 'secret',
    field: 'Код правила',
    submit: 'Найти по правилу',
    reset: 'Сбросить правило',
    valid: 'rule.with-dashes_1',
    invalid: 'bad rule',
  },
] as const;

afterEach(() => {
  cleanup();
  vi.restoreAllMocks();
});

function mount(kind: 'sbom' | 'secret') {
  const onChange = vi.fn();
  render(
    kind === 'sbom' ? (
      <SbomReportControls
        query={{ view: 'report-v1', limit: 10, sort: 'name:desc', ecosystem: 'npm', name: 'applied' }}
        onChange={onChange}
        disabled={false}
      />
    ) : (
      <SecretReportControls
        query={{ view: 'report-v1', limit: 10, sort: 'line:desc', linePresence: 'known', ruleId: 'applied' }}
        onChange={onChange}
        disabled={false}
      />
    ),
  );
  return onChange;
}

async function open(kind: 'sbom' | 'secret') {
  const user = userEvent.setup();
  await user.click(
    screen.getByText(`Фильтры и сортировка · ${kind === 'sbom' ? 'Пакеты' : 'Возможные секреты'}`),
  );
  return user;
}

describe.each(scenarios)('$kind filter validation through native interactions', (scenario) => {
  it.each(['click', 'Enter'] as const)(
    'shows an associated Russian error on invalid %s submit without dispatching a query or losing the draft',
    async (method) => {
      const onChange = mount(scenario.kind);
      const user = await open(scenario.kind);
      const input = screen.getByRole('textbox', { name: scenario.field });
      await user.clear(input);
      await user.type(input, scenario.invalid);
      if (method === 'click') await user.click(screen.getByRole('button', { name: scenario.submit }));
      else await user.keyboard('{Enter}');
      const error = await screen.findByRole('alert');
      expect(error).toHaveTextContent(/буквы|латин/);
      expect(error).toHaveTextContent(scenario.kind === 'sbom' ? /128/ : /80/);
      expect(input).toHaveAttribute('aria-invalid', 'true');
      expect(input.getAttribute('aria-describedby')?.split(' ')).toContain(error.id);
      expect(error.id).not.toBe('');
      expect(input).toHaveValue(scenario.invalid);
      expect(onChange).not.toHaveBeenCalled();

      await user.clear(input);
      await user.type(input, scenario.valid);
      expect(input).toHaveAttribute('aria-invalid', 'false');
      expect(screen.queryByRole('alert')).toBeNull();
      await user.keyboard('{Enter}');
      expect(onChange).toHaveBeenCalledExactlyOnceWith(
        scenario.kind === 'sbom'
          ? { view: 'report-v1', limit: 10, sort: 'name:desc', ecosystem: 'npm', name: scenario.valid }
          : {
              view: 'report-v1',
              limit: 10,
              sort: 'line:desc',
              linePresence: 'known',
              ruleId: scenario.valid,
            },
      );
    },
  );

  it('clears invalid feedback and only its own applied text filter on reset', async () => {
    const onChange = mount(scenario.kind);
    const user = await open(scenario.kind);
    const input = screen.getByRole('textbox', { name: scenario.field });
    await user.clear(input);
    await user.type(input, scenario.invalid);
    await user.click(screen.getByRole('button', { name: scenario.submit }));
    await screen.findByRole('alert');
    await user.click(screen.getByRole('button', { name: scenario.reset }));
    expect(input).toHaveValue('');
    expect(input).toHaveAttribute('aria-invalid', 'false');
    expect(screen.queryByRole('alert')).toBeNull();
    expect(onChange).toHaveBeenCalledExactlyOnceWith(
      scenario.kind === 'sbom'
        ? { view: 'report-v1', limit: 10, sort: 'name:desc', ecosystem: 'npm', name: null }
        : { view: 'report-v1', limit: 10, sort: 'line:desc', linePresence: 'known', ruleId: null },
    );
  });

  it('keeps search, reset and input disabled while a confirmed-page query is pending', async () => {
    const onChange = vi.fn();
    render(
      scenario.kind === 'sbom' ? (
        <SbomReportControls query={{ view: 'report-v1' }} onChange={onChange} disabled />
      ) : (
        <SecretReportControls query={{ view: 'report-v1' }} onChange={onChange} disabled />
      ),
    );
    const user = await open(scenario.kind);
    const input = screen.getByRole('textbox', { name: scenario.field });
    expect(input).toBeDisabled();
    for (const button of within(input.closest('form')!).getAllByRole('button')) {
      expect(button).toBeDisabled();
      await user.click(button);
    }
    expect(onChange).not.toHaveBeenCalled();
  });
});
