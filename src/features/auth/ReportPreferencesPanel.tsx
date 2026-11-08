import { useState, type FormEvent } from 'react';
import { scanSession } from '@/shared/api/auth/scanSession';
import {
  readReportPreferences,
  REPORT_AUTOMATION_REVISION,
  saveReportPreferences,
  useReportPreferences,
  type ReportPreferences,
  type ReportPreferencesInput,
} from '@/shared/api/preferences/reportPreferences';
import { OpenAiDisclosure } from '@/features/scans/OpenAiDisclosure';
import './ReportPreferencesPanel.css';

export function ReportPreferencesPanel({
  subject,
  disabled = false,
}: {
  subject: string;
  disabled?: boolean;
}) {
  const preferences = useReportPreferences();
  const session = scanSession();
  const [draft, setDraft] = useState({ source: preferences, ...preferences });
  const [feedback, setFeedback] = useState<{ source: ReportPreferences; failed: boolean } | null>(null);
  const selection = draft.source === preferences ? draft : preferences;
  const active = session.subject === subject;
  const paidConsent = preferences.moduleApiSummaryConsent ?? preferences.openAiSummaryConsent;

  function select(patch: Partial<ReportPreferencesInput>) {
    setDraft({ ...selection, source: preferences, ...patch });
    setFeedback(null);
  }

  function save(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    if (!active || disabled) return;
    const saved = saveReportPreferences(
      {
        language: selection.language,
        autoSummary: selection.autoSummary,
        ...(selection.autoSummary && preferences.openAiSummaryConsent
          ? { openAiSummaryConsent: preferences.openAiSummaryConsent }
          : {}),
        ...(selection.autoSummary && preferences.moduleApiSummaryConsent
          ? { moduleApiSummaryConsent: preferences.moduleApiSummaryConsent }
          : {}),
      },
      session,
    );
    setFeedback({ source: readReportPreferences(), failed: !saved });
  }

  return (
    <section className="report-preferences" aria-labelledby="report-preferences-title">
      <h3 id="report-preferences-title">Настройки отчётов</h3>
      <p>Настройки действуют только для аккаунта в этом браузере, не на других устройствах.</p>
      <form onSubmit={save} aria-describedby="report-preferences-disclosure">
        <label htmlFor="report-preferences-language">Язык исходных описаний уязвимостей</label>
        <select
          id="report-preferences-language"
          aria-describedby="report-preferences-language-description"
          value={selection.language}
          disabled={!active || disabled}
          onChange={(event) => select({ language: event.target.value as ReportPreferencesInput['language'] })}
        >
          <option value="original">Оригинал — без автоматического перевода</option>
          <option value="ru">Русский — автоматический перевод выбранного описания</option>
        </select>

        <p id="report-preferences-language-description">
          Эта настройка относится только к заголовкам и описаниям уязвимостей из источников. ИИ-отчёт и ответы
          в чате сразу формируются на русском — отдельный перевод для них не нужен.
        </p>

        <label htmlFor="report-preferences-summary">ИИ-разбор</label>
        <select
          id="report-preferences-summary"
          value={selection.autoSummary ? 'on' : 'off'}
          disabled={!active || disabled}
          onChange={(event) => select({ autoSummary: event.target.value === 'on' })}
        >
          <option value="off">Выключен</option>
          <option value="on">Включён — разбирать новые отчёты автоматически</option>
        </select>

        <div
          id="report-preferences-disclosure"
          className="report-preferences__disclosure"
          data-automation-revision={REPORT_AUTOMATION_REVISION}
        >
          {paidConsent ? (
            <>
              <OpenAiDisclosure disclosure={paidConsent.disclosure} />
              <p>
                Платный авторазбор разрешён только для сохранённой политики {paidConsent.disclosure.provider}.
                Смена условий требует нового согласия в отчёте; сохранение этих настроек не подтверждает новую
                политику.
              </p>
            </>
          ) : (
            <p>
              Эта настройка разрешает только прежний бесплатный профиль OpenRouter. Для платного OpenAI или
              ModuleAPI откройте отчёт, прочитайте условия и отдельно включите платный авторазбор. Старые
              предпочтения его не включают. Согласие OpenAI не переносится на стороннего провайдера ModuleAPI.
            </p>
          )}
          <p>
            При включённом ИИ-разборе находки отчёта, имена пакетов и версии передаются внешней модели. Модель
            может сохранять данные. Выбор начнёт действовать после сохранения.
          </p>
          <p>
            Сохраняя «Русский», вы разрешаете передать внешнему ИИ только исходные заголовок и описание
            выбранной уязвимости для перевода. Данные могут сохраняться.
          </p>
          <details>
            <summary>Условия ИИ-разбора и перевода</summary>
            <p>
              Сохранение включённого ИИ-разбора разрешает автоматически передавать очищенные находки, имена
              пакетов, установленные и сообщённые исправленные версии и покрытие проверок. Свободный текст
              находок, ссылки, учётные данные, переменные окружения и исходный вывод сканеров исключены; имена
              пакетов и версии — санитизированные факты сканера. Разбор запрашивается один раз для отчёта и
              текущей политики. После ошибки или отмены — только ручной повтор. Это ответ модели, не гарантия
              безопасности или устранения уязвимостей.
            </p>
            <p>
              Прежний бесплатный ИИ-разбор и отдельный перевод используют профиль ниже; это не разрешение
              платного OpenAI или ModuleAPI. Сохранение «Русский» разрешает ограниченный автоматический
              перевод только исходных заголовка и описания выбранной уязвимости (advisory), не всего отчёта.
              Эти данные передаются через OpenRouter только модели Dots
              (dots-studio/dots-3-note-preview:free), провайдеру Atlas Cloud (atlas-cloud/fp8), только в
              бесплатном режиме, без автоматической замены модели или провайдера. Провайдер декларирует
              отсутствие обучения (no-training), но не отсутствие хранения: запросы могут сохраняться, это не
              Zero Data Retention (ZDR). Декларация и одобрение оператора не доказывают соблюдение; качество в
              продукте ещё не проверено.
            </p>
            <p>
              Результат — машинная интерпретация, а не подтверждение безопасности. Действуют серверные квоты
              пользователя и отчёта; бесплатный профиль не отменяет лимиты и не гарантирует доступность. Смена
              модели, провайдера, состава передаваемых данных или условий требует новой версии согласия:
              прежняя версия отключает автоматику до повторного сохранения.
            </p>
            <p>
              До сохранения выбора внешняя отправка не разрешена. Чтобы отключить авторазбор, выберите
              «Выключен» в настройке «ИИ-разбор» и сохраните. Для отключения перевода выберите «Оригинал» и
              сохраните. Это останавливает будущие автоматические запросы, но не отзывает уже отправленные
              данные. Локально хранятся только эти настройки и версия согласия, без паролей, ключей и
              содержимого отчётов.
            </p>
          </details>
        </div>
        {!preferences.authorized ? (
          <p className="report-preferences__notice">
            Автоматические функции отключены: сохраните выбор, чтобы подтвердить текущие условия.
          </p>
        ) : null}
        {feedback?.source === preferences ? (
          feedback.failed ? (
            <p role="alert" className="demo-auth__error">
              Не удалось сохранить настройки. Автоматические функции отключены; проверьте доступ к хранилищу
              браузера.
            </p>
          ) : (
            <p role="status">Настройки сохранены для аккаунта в этом браузере.</p>
          )
        ) : null}
        <button className="demo-auth__submit" type="submit" disabled={!active || disabled}>
          Сохранить настройки отчётов
        </button>
      </form>
    </section>
  );
}
