import {
  LEGACY_SCANNER_DISCLOSURE,
  type PaidDisclosure as Disclosure,
} from '@/shared/api/scans/llmPublicContract';

type Props = { disclosure: Disclosure & { lifetimeUserCostMicros?: number }; chat?: boolean };

/** Cost and egress stay visible; only low-level policy details are collapsed. */
export function OpenAiDisclosure({ disclosure, chat = false }: Props) {
  const lifetime =
    disclosure.monetaryLimit === 'uncapped' &&
    Number.isSafeInteger(disclosure.lifetimeUserCostMicros) &&
    disclosure.lifetimeUserCostMicros !== undefined &&
    disclosure.lifetimeUserCostMicros >= 1 &&
    disclosure.lifetimeUserCostMicros <= 1_000_000_000
      ? disclosure.lifetimeUserCostMicros
      : undefined;
  const lifetimeUsd =
    lifetime === undefined ? null : `$${(lifetime / 1_000_000).toFixed(6).replace(/\.?0+$/, '')}`;
  return (
    <div aria-label={`Условия ${disclosure.provider}`}>
      <p>
        {disclosure.provider} · {disclosure.model}. Платный ИИ:{' '}
        {lifetimeUsd
          ? `${lifetimeUsd} на аккаунт за всё время — это не бесплатный режим.`
          : disclosure.monetaryLimit === 'uncapped'
            ? 'без локального денежного лимита — это не бесплатный режим.'
            : 'с серверными денежными лимитами.'}{' '}
        Стоимость рассчитывается сервером по настроенным ставкам, это оценка, не счёт провайдера.
      </p>
      <p>
        {disclosure.provider === 'ModuleAPI' ? 'Стороннему провайдеру ModuleAPI передаются' : 'Передаются'}{' '}
        очищенные находки и покрытие проверок
        {disclosure.data === LEGACY_SCANNER_DISCLOSURE
          ? ''
          : ', имена пакетов, установленные и сообщённые исправленные версии'}
        {chat ? ', вопрос, история пользовательских сообщений и принятые решения' : ''}. Без исходных
        свидетельств и ключей.{' '}
        {disclosure.provider === 'ModuleAPI'
          ? 'Условия хранения и использования данных для обучения неизвестны. Отсутствие обучения, хранения и Zero Data Retention (ZDR) не подтверждены. Одобрение маршрута оператором не доказывает соблюдение приватности и соответствие модели её названию.'
          : 'Запрет обучения (no-training) не гарантирует отсутствия хранения: ZDR не подтверждён. Декларация и одобрение оператора не доказывают соблюдение.'}
      </p>
      {disclosure.provider === 'ModuleAPI' ? (
        <p>
          Тариф аккаунта и группы ModuleAPI не проверен. Настроенные ставки — не подтверждённый тариф и не
          счёт; название gpt-5.4-mini — обозначение модели у стороннего провайдера, не гарантия
          эквивалентности прямому OpenAI.
        </p>
      ) : null}
      <details>
        <summary>Стоимость и ограничения</summary>
        <p>
          За миллион токенов: вход — {disclosure.estimatedPrice.input} микро-USD, выход —{' '}
          {disclosure.estimatedPrice.output} микро-USD. 1 USD = 1 000 000 микро-USD.
        </p>
        {disclosure.monetaryLimit === 'capped' ? (
          <p>
            Денежные лимиты, микро-USD: запрос — {disclosure.requestBudgetMicros}; пользователь —{' '}
            {disclosure.userBudgetMicros}; скан — {disclosure.scanBudgetMicros}.
          </p>
        ) : lifetimeUsd ? (
          <p>
            Бюджет аккаунта — {lifetimeUsd} на аккаунт за всё время, без сброса со сменой суток. Денежные
            лимиты запроса и суток не установлены; отдельный бюджет аккаунта ограничивает расход. Оконные
            счётчики токенов — статистика, не блокирующие бюджеты; ограничения отдельных запросов сохраняются.
            Учитываются исторические расходы всех провайдеров и резервы, включая неопределённый расход; смена
            провайдера или политики не сбрасывает этот бюджет.
          </p>
        ) : (
          <p>Локальный предел расходов не установлен; токенные квоты и ограничения запросов сохраняются.</p>
        )}
        <p>
          Без автоматической замены провайдера и повторов после ошибки. Отмена не возвращает уже возможный
          расход.
        </p>
      </details>
    </div>
  );
}
