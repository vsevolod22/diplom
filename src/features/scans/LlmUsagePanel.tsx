import { useEffect, useMemo, useRef, useState } from 'react';
import { subscribeScanSession } from '@/shared/api/auth/scanSession';
import {
  createUsageClient,
  type LifetimeBudget,
  type LlmUsage,
  type UsageBinding,
  type UsageClient,
} from '@/shared/api/scans/llmUsageClient';
import { Button } from '@/shared/ui/scan-primitives';

type Props = { binding: UsageBinding | null; refreshVersion: number; client?: UsageClient };
const reasons = {
  ready: 'Полный резерв текущего запроса помещается; снимок не гарантирует допуск следующего запроса.',
  warning: 'Предупреждение: использовано не менее 80% установленного лимита.',
  exhausted: 'Установленная квота исчерпана.',
  policy_fault: 'Учёт заблокирован из-за расхождения с политикой.',
  disabled: 'Продуктовые квоты выключены оператором.',
  unavailable: 'Счётчики временно недоступны; остаток неизвестен.',
};
export function LifetimeBudgetDetails({ budget }: { budget: LifetimeBudget }) {
  const usd = (micros: number) => {
    const amount = BigInt(micros);
    const fraction = (amount % 1_000_000n).toString().padStart(6, '0').replace(/0+$/, '');
    return `$${amount / 1_000_000n}${fraction ? `.${fraction}` : ''}`;
  };
  return (
    <section aria-label="Бюджет ИИ за всё время">
      <h4>{usd(budget.limitMicros)} на аккаунт за всё время</h4>
      <dl>
        <div>
          <dt>Использовано по оценке сервера</dt>
          <dd>{usd(budget.usedMicros)}</dd>
        </div>
        <div>
          <dt>В резерве, включая неопределённый расход</dt>
          <dd>{usd(budget.heldMicros)}</dd>
        </div>
        <div>
          <dt>Осталось по оценке сервера</dt>
          <dd>{usd(budget.remainingMicros)}</dd>
        </div>
      </dl>
      <p>
        Это серверная оценка, не счёт провайдера. Резерв включает ожидающие запросы и расход, который пока
        неизвестен; это не подтверждённое списание и не свободный остаток.
      </p>
      <p>
        Бюджет общий для аккаунта за всё время и не обновляется со сменой суток, провайдера или политики.
        Исторические расходы и неопределённые обязательства сохраняются. Остаток не гарантирует допуск
        следующего полного запроса.
      </p>
    </section>
  );
}
export function LlmUsagePanel({ binding, refreshVersion, client: supplied }: Props) {
  const client = useMemo(() => supplied ?? createUsageClient(), [supplied]);
  const key = binding ? JSON.stringify(binding) : '';
  const [value, setValue] = useState<{ key: string; usage: LlmUsage } | null>(null);
  const [pending, setPending] = useState(false);
  const [failed, setFailed] = useState(false);
  const activated = useRef(false);
  const request = useRef<AbortController | null>(null);
  const generation = useRef(0);
  function clear() {
    generation.current++;
    request.current?.abort();
    request.current = null;
    setValue(null);
    setPending(false);
    setFailed(false);
  }
  async function refresh() {
    if (!binding || !client.current()) return;
    clear();
    activated.current = true;
    const controller = new AbortController();
    request.current = controller;
    const version = ++generation.current;
    setPending(true);
    try {
      const usage = await client.get(binding, controller.signal);
      if (generation.current === version && !controller.signal.aborted && client.current())
        setValue({ key, usage });
    } catch {
      if (generation.current === version && !controller.signal.aborted) setFailed(true);
    } finally {
      if (generation.current === version) {
        request.current = null;
        setPending(false);
      }
    }
  }
  useEffect(() => {
    clear();
    activated.current = false;
    const unsubscribe = subscribeScanSession(() => {
      clear();
      activated.current = false;
    });
    return () => {
      // This is a request fence, not a DOM ref: cleanup invalidates the latest generation.
      // eslint-disable-next-line react-hooks/exhaustive-deps
      generation.current++;
      request.current?.abort();
      unsubscribe();
    };
    // Binding, including report/access context, invalidates every old snapshot.
  }, [key, client]);
  useEffect(() => {
    if (activated.current) void refresh();
    // Only an explicitly opened counter view refreshes after a summary request.
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [refreshVersion]);
  useEffect(() => {
    const focus = () => {
      if (activated.current && !request.current) void refresh();
    };
    window.addEventListener('focus', focus);
    return () => window.removeEventListener('focus', focus);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [key, client]);
  const usage = value?.key === key && binding && client.current() ? value.usage : null;
  const next = usage?.available ? usage.admission : null;
  const dimensionLabel = (dimension: string) =>
    dimension === 'input'
      ? 'входные токены'
      : dimension === 'output'
        ? 'выходные токены'
        : dimension === 'costMicros'
          ? 'стоимость'
          : 'весь бюджет';
  return (
    <section aria-label="Продуктовые квоты ИИ" aria-busy={pending}>
      <h4>Учёт ИИ: пользователь и этот скан</h4>
      <p>
        {usage?.available && usage.monetaryLimit
          ? 'Платный ИИ: стоимость оценена сервером по настроенным ставкам, не счёт провайдера.'
          : 'Токены и стоимость сообщены провайдером и проверены сервером; оценка продукта, не подтверждённый счёт.'}
      </p>
      <Button
        type="button"
        variant="secondary"
        disabled={!binding || !client.current() || pending}
        onClick={() => void refresh()}
      >
        Обновить остаток ИИ
      </Button>
      {pending ? <p role="status">Читаем счётчики…</p> : null}
      {failed ? <p role="status">{reasons.unavailable}</p> : null}
      {usage ? (
        <>
          <p role="status">
            {next?.status === 'insufficient'
              ? 'Полный резерв следующего запроса не помещается в квоту.'
              : next?.status === 'policy_fault'
                ? reasons.policy_fault
                : usage.available && usage.reason === 'ready' && next?.status !== 'fits'
                  ? 'Счётчики доступны; ёмкость следующего полного запроса неизвестна.'
                  : reasons[usage.reason]}
          </p>
          {next?.status === 'unavailable' && usage.reason !== 'ready' ? (
            <p>Ёмкость следующего полного запроса неизвестна; это не разрешение генерации.</p>
          ) : null}
          {next && next.status !== 'unavailable' ? (
            <ul aria-label="Допуск полного резерва">
              {next.signals.map((signal, index) => (
                <li key={index}>
                  {signal.scope === 'user' ? 'Пользователь' : 'Этот скан'} ·{' '}
                  {dimensionLabel(signal.dimension)}:
                  {signal.reason === 'insufficient'
                    ? ` требуется ${signal.required}, осталось ${signal.remaining}; полный резерв не помещается.`
                    : ` ${reasons.policy_fault}`}
                </li>
              ))}
            </ul>
          ) : null}
          {!usage.integrationEnabled ? <p>Генерация выключена; просмотр счётчиков её не включает.</p> : null}
          {usage.available ? (
            <>
              {usage.lifetimeBudget ? <LifetimeBudgetDetails budget={usage.lifetimeBudget} /> : null}
              {usage.lifetimeBudget ? (
                <p>
                  Оконные счётчики токенов и стоимости — статистика, не блокирующие бюджеты. Допуск
                  определяется отдельным бюджетом аккаунта за всё время.
                </p>
              ) : null}
              <p>
                {usage.lifetimeBudget ? 'Окно счётчиков UTC' : 'Окно UTC'}:{' '}
                {new Date(usage.window.start).toISOString()} — {new Date(usage.window.end).toISOString()}
              </p>
              <ul>
                {usage.signals.map((signal, index) => (
                  <li key={index}>
                    {signal.scope === 'user' ? 'Пользователь' : 'Этот скан'} ·{' '}
                    {signal.dimension === 'input'
                      ? 'входные токены'
                      : signal.dimension === 'output'
                        ? 'выходные токены'
                        : signal.dimension === 'costMicros'
                          ? 'стоимость'
                          : 'весь бюджет'}
                    : {reasons[signal.reason]}
                  </li>
                ))}
              </ul>
              {(['user', 'scan'] as const).map((scope) => (
                <div key={scope}>
                  <h5>
                    {scope === 'user' ? 'Пользователь' : 'Этот скан'}
                    {usage.lifetimeBudget ? ' · оконные счётчики' : ''}
                  </h5>
                  <dl>
                    {(['input', 'output', 'costMicros'] as const).map((d) => (
                      <div key={d}>
                        <dt>
                          {d === 'input'
                            ? 'Входные токены'
                            : d === 'output'
                              ? 'Выходные токены'
                              : 'Стоимость, микро-USD (1 USD = 1 000 000)'}
                        </dt>
                        <dd>
                          {usage[scope].limits[d] === null
                            ? 'Без денежного лимита запроса и суток — платно, не бесплатно; отдельный бюджет аккаунта может ограничивать расход'
                            : usage.lifetimeBudget
                              ? `Оконный счётчик: ${usage[scope].limits[d]}; расчётный остаток счётчика ${usage[scope].remaining[d]} (не бюджет допуска)`
                              : `Осталось ${usage[scope].remaining[d]} из ${usage[scope].limits[d]}`}
                          ; учтено {usage[scope].used[d]}; резерв {usage[scope].held[d]}; перенос
                          неопределённого расхода {usage[scope].carried[d]}
                        </dd>
                      </div>
                    ))}
                  </dl>
                </div>
              ))}
            </>
          ) : (
            <p>Остаток неизвестен, а не равен нулю.</p>
          )}
        </>
      ) : !pending && !failed ? (
        <p>Остаток пока не загружен. Просмотр не вызывает модель и не выдаёт согласие.</p>
      ) : null}
      <small>
        Отмена генерации не возвращает уже возможный расход. Findings и coverage сканеров не зависят от этой
        панели.
      </small>
    </section>
  );
}
