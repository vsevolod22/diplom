import { useState, type FormEvent } from 'react';
import { scanSession } from '@/shared/api/auth/scanSession';
import {
  readReportPreferences,
  saveReportPreferences,
  useReportPreferences,
  type ReportPreferences,
  type ReportPreferencesInput,
} from '@/shared/api/preferences/reportPreferences';
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
    const saved = saveReportPreferences(selection, session);
    setFeedback({ source: readReportPreferences(), failed: !saved });
  }

  return (
    <section className="report-preferences" aria-labelledby="report-preferences-title">
      <h3 id="report-preferences-title">Язык и сводка отчётов</h3>
      <p>Настройки действуют только для аккаунта в этом браузере, не на других устройствах.</p>
      <form onSubmit={save} aria-describedby="report-preferences-disclosure">
        <label htmlFor="report-preferences-language">Язык отчёта</label>
        <select
          id="report-preferences-language"
          value={selection.language}
          disabled={!active || disabled}
          onChange={(event) => select({ language: event.target.value as ReportPreferencesInput['language'] })}
        >
          <option value="original">Оригинал — без автоматического перевода</option>
          <option value="ru">Русский — автоматический перевод выбранного описания</option>
        </select>
        <label htmlFor="report-preferences-summary">Краткая ИИ-сводка</label>
        <select
          id="report-preferences-summary"
          value={selection.autoSummary ? 'on' : 'off'}
          disabled={!active || disabled}
          onChange={(event) => select({ autoSummary: event.target.value === 'on' })}
        >
          <option value="off">Выключена</option>
          <option value="on">Автоматически один раз для каждого отчёта</option>
        </select>
        <div id="report-preferences-disclosure" className="report-preferences__disclosure">
          <p>
            Сохранение «Русский» разрешает ограниченный автоматический перевод только заголовка и описания
            выбранной рекомендации (advisory), не всего отчёта. Включение сводки разрешает один автоматический
            запрос на отчёт: очищенные находки и сведения о покрытии проверок. Эти данные передаются через
            OpenRouter только модели Xing (xingchen-agi/xing4.0-29b-a4b:free), провайдеру Phala, только в
            бесплатном режиме, без автоматической замены модели или провайдера.
          </p>
          <p>
            Результат — машинная интерпретация, а не подтверждение безопасности. Действуют серверные квоты
            пользователя и отчёта; бесплатный профиль не отменяет лимиты и не гарантирует доступность. Смена
            модели, провайдера, состава передаваемых данных или условий требует новой версии согласия: прежняя
            версия отключает автоматику до повторного сохранения.
          </p>
          <p>
            До сохранения выбора внешняя отправка не разрешена. Для отзыва выберите «Оригинал» и «Выключена» и
            сохраните. Это останавливает будущие автоматические запросы, но не отзывает уже отправленные
            данные. Локально хранятся только эти настройки и версия согласия, без паролей, ключей и
            содержимого отчётов.
          </p>
        </div>
        {!preferences.authorized ? (
          <p className="report-preferences__notice">
            Автоматика отключена: сохраните выбор, чтобы подтвердить текущие условия.
          </p>
        ) : null}
        {feedback?.source === preferences ? (
          feedback.failed ? (
            <p role="alert" className="demo-auth__error">
              Не удалось сохранить настройки. Автоматика отключена; проверьте доступ к хранилищу браузера.
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
