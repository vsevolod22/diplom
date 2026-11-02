import {
  LEGACY_SCANNER_DISCLOSURE,
  type OpenAiDisclosure as Disclosure,
} from '@/shared/api/scans/llmPublicContract';

/** Cost and egress stay visible; only low-level policy details are collapsed. */
export function OpenAiDisclosure({ disclosure, chat = false }: { disclosure: Disclosure; chat?: boolean }) {
  return (
    <div aria-label="Условия OpenAI">
      <p>
        OpenAI · {disclosure.model}. Платный ИИ:{' '}
        {disclosure.monetaryLimit === 'uncapped'
          ? 'без локального денежного лимита — это не бесплатный режим.'
          : 'с серверными денежными лимитами.'}{' '}
        Стоимость рассчитывается сервером по настроенным ставкам, это оценка, не счёт провайдера.
      </p>
      <p>
        Передаются очищенные находки и покрытие проверок
        {disclosure.data === LEGACY_SCANNER_DISCLOSURE
          ? ''
          : ', имена пакетов, установленные и сообщённые исправленные версии'}
        {chat ? ', вопрос, история пользовательских сообщений и принятые решения' : ''}. Без исходных
        свидетельств и ключей. Запрет обучения (no-training) не гарантирует отсутствия хранения: ZDR не
        подтверждён. Декларация и одобрение оператора не доказывают соблюдение.
      </p>
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
