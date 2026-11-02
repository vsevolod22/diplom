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
          {preferences.openAiSummaryConsent ? (
            <>
              <OpenAiDisclosure disclosure={preferences.openAiSummaryConsent.disclosure} />
              <p>
                Платный авторазбор разрешён только для сохранённой политики OpenAI. Смена условий требует
                нового согласия в отчёте; сохранение этих настроек не подтверждает новую политику.
              </p>
            </>
          ) : (
            <p>
              Эта настройка разрешает только прежний бесплатный профиль OpenRouter. Для платного OpenAI
              откройте отчёт, прочитайте условия и отдельно включите платный авторазбор. Старые предпочтения
              его не включают.
            </p>
          )}
          {!preferences.openAiSummaryConsent ? <p>
            Бесплатный ИИ-разбор передаёт только очищенные находки сканера и сведения о покрытии проверок.
            Имена пакетов, установленные и исправленные версии не входят в это согласие.
          </p> : null}
          <p>
            Сохраняя «Русский», вы разрешаете ограниченный автоматический перевод только исходных заголовка
            и описания выбранной уязвимости, не всего отчёта. Перевод использует только бесплатный OpenRouter:
            Xing (xingchen-agi/xing4.0-29b-a4b:free), Phala, профиль no-storage, без замены модели или провайдера.
            Отсутствие хранения и обучения — декларация провайдера, не доказательство соблюдения.
          </p>
          <details>
            <summary>Условия ИИ-разбора и перевода</summary>
            {!preferences.openAiSummaryConsent ? <p>
              Включение бесплатного ИИ-разбора разрешает один автоматический запрос на отчёт: очищенные находки
              и сведения о покрытии через OpenRouter только модели Xing (xingchen-agi/xing4.0-29b-a4b:free),
              провайдеру Phala, в режиме no-storage. Исходный вывод сканеров, учётные данные и содержимое
              окружения не передаются. Это согласие не разрешает платный OpenAI или расширенный состав данных.
            </p> : <p>
              Для платного ИИ-разбора действуют только показанные выше сохранённые условия OpenAI и точная
              версия политики. Сохранение настроек не разрешает новую платную политику и не переключает
              согласие обратно на бесплатного провайдера. Перевод остаётся отдельной бесплатной функцией.
            </p>}
            <p>
              Результат — машинная интерпретация, а не подтверждение безопасности. Действуют серверные квоты;
              бесплатный профиль не отменяет лимиты и не гарантирует доступность. Смена модели, провайдера,
              состава передаваемых данных или условий требует нового согласия. После ошибки или отмены —
              только ручной повтор.
            </p>
            <p>
              До сохранения выбора автоматическая отправка не разрешена. Для отзыва выберите «Оригинал» и
              «Выключен» и сохраните. Это останавливает будущие автоматические запросы, но не отзывает уже
              отправленные данные. Локально хранятся настройки, версия согласия и при отдельном платном
              согласии — его условия, без паролей, ключей и содержимого отчётов.
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
