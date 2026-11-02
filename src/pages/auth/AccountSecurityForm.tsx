import { useLayoutEffect, useRef, useState, type FormEvent } from 'react';
import { ChevronDown, KeyRound, MonitorSmartphone } from 'lucide-react';
import { Link } from 'react-router-dom';
import { PASSWORD_HINT } from '@/shared/api/auth/accountSecurity';

export type AccountSecurityDraft = {
  currentPassword: string;
  newPassword: string;
  confirmation: string;
};
export type AccountSecurityAction = 'change-password' | 'revoke-all';

type Props = {
  draft: AccountSecurityDraft;
  disabled: boolean;
  pendingAction: AccountSecurityAction | 'logout' | null;
  openSection: AccountSecurityAction | null;
  onSectionChange: (section: AccountSecurityAction | null) => void;
  onSuspendFocus: (id: string) => void;
  onChange: (draft: AccountSecurityDraft) => void;
  onSubmit: (action: AccountSecurityAction) => void;
};

export function AccountSecurityForm({
  draft,
  disabled,
  pendingAction,
  openSection,
  onSectionChange,
  onSuspendFocus,
  onChange,
  onSubmit,
}: Props) {
  const [confirmedAction, setConfirmedAction] = useState<AccountSecurityAction | null>(null);
  const root = useRef<HTMLDivElement>(null);
  useLayoutEffect(() => {
    const element = root.current;
    return () => {
      // Capture before the private gate removes the focused control, never its value.
      const focused = document.activeElement;
      if (focused instanceof HTMLElement && focused.id && element?.contains(focused)) {
        onSuspendFocus(focused.id);
      }
    };
  }, [onSuspendFocus]);

  function change(patch: Partial<AccountSecurityDraft>) {
    setConfirmedAction(null);
    onChange({ ...draft, ...patch });
  }

  function submit(event: FormEvent<HTMLFormElement>, action: AccountSecurityAction) {
    event.preventDefault();
    if (disabled || confirmedAction !== action) return;
    // Confirmation is for one attempt only, never an authorization to retry a mutation.
    setConfirmedAction(null);
    onSubmit(action);
  }

  return (
    <div className="demo-auth__security" ref={root}>
      <details className="demo-auth__security-section" open={openSection === 'change-password'}>
        <summary
          id="account-password-section"
          className="demo-auth__disclosure"
          onClick={(event) => {
            event.preventDefault();
            onSectionChange(openSection === 'change-password' ? null : 'change-password');
          }}
        >
          <KeyRound size={20} aria-hidden="true" />
          <span>
            <span className="demo-auth__disclosure-title">Сменить пароль</span>
            <span className="demo-auth__disclosure-description">Понадобится текущий пароль</span>
          </span>
          <ChevronDown className="demo-auth__chevron" size={20} aria-hidden="true" />
        </summary>
        <form
          className="demo-auth__security-form"
          onSubmit={(event) => submit(event, 'change-password')}
          aria-label="Смена пароля"
          aria-busy={pendingAction === 'change-password'}
          aria-describedby="account-password-effect"
        >
          <p id="account-password-effect">
            После смены пароля все сеансы завершатся, в том числе в этом браузере. Для следующего входа
            используйте новый пароль.
          </p>
          <fieldset disabled={disabled}>
            <legend className="sr-only">Текущий и новый пароль</legend>
            <label htmlFor="account-current-password">Текущий пароль</label>
            <input
              id="account-current-password"
              name="currentPassword"
              type="password"
              autoComplete="current-password"
              required
              maxLength={128}
              value={draft.currentPassword}
              onChange={(event) => change({ currentPassword: event.target.value })}
            />
            <label htmlFor="account-new-password">Новый пароль</label>
            <input
              id="account-new-password"
              name="newPassword"
              type="password"
              autoComplete="new-password"
              required
              maxLength={128}
              aria-describedby="account-password-hint"
              value={draft.newPassword}
              onChange={(event) => change({ newPassword: event.target.value })}
            />
            <p id="account-password-hint" className="demo-auth__hint">
              {PASSWORD_HINT}
            </p>
            <label htmlFor="account-confirm-password">Повторите новый пароль</label>
            <input
              id="account-confirm-password"
              name="confirmation"
              type="password"
              autoComplete="new-password"
              required
              maxLength={128}
              value={draft.confirmation}
              onChange={(event) => change({ confirmation: event.target.value })}
            />
            <label className="demo-auth__confirmation">
              <input
                id="account-change-confirmation"
                type="checkbox"
                required
                checked={confirmedAction === 'change-password'}
                onChange={(event) => setConfirmedAction(event.target.checked ? 'change-password' : null)}
              />
              <span>Подтверждаю смену пароля и выход на всех устройствах, включая это.</span>
            </label>
            <button
              id="account-change-submit"
              className="demo-auth__submit demo-auth__submit--secondary"
              type="submit"
            >
              {pendingAction === 'change-password' ? 'Меняем пароль…' : 'Сменить пароль и выйти везде'}
            </button>
          </fieldset>
        </form>
      </details>
      <details className="demo-auth__security-section" open={openSection === 'revoke-all'}>
        <summary
          id="account-revoke-section"
          className="demo-auth__disclosure"
          onClick={(event) => {
            event.preventDefault();
            onSectionChange(openSection === 'revoke-all' ? null : 'revoke-all');
          }}
        >
          <MonitorSmartphone size={20} aria-hidden="true" />
          <span>
            <span className="demo-auth__disclosure-title">Выйти со всех устройств</span>
            <span className="demo-auth__disclosure-description">Завершить все сеансы, включая текущий</span>
          </span>
          <ChevronDown className="demo-auth__chevron" size={20} aria-hidden="true" />
        </summary>
        <form
          className="demo-auth__security-form"
          onSubmit={(event) => submit(event, 'revoke-all')}
          aria-label="Выход со всех устройств"
          aria-busy={pendingAction === 'revoke-all'}
          aria-describedby="account-revoke-effect"
        >
          <p id="account-revoke-effect">
            Используйте, если входили на чужом устройстве. Пароль не изменится, но везде потребуется войти
            заново. Уже выполненные действия не отменяются.
          </p>
          <fieldset disabled={disabled}>
            <legend className="sr-only">Подтверждение выхода со всех устройств</legend>
            <label htmlFor="account-revoke-password">Текущий пароль для выхода</label>
            <input
              id="account-revoke-password"
              name="currentPassword"
              type="password"
              autoComplete="current-password"
              required
              maxLength={128}
              value={draft.currentPassword}
              onChange={(event) => change({ currentPassword: event.target.value })}
            />
            <label className="demo-auth__confirmation">
              <input
                id="account-revoke-confirmation"
                type="checkbox"
                required
                checked={confirmedAction === 'revoke-all'}
                onChange={(event) => setConfirmedAction(event.target.checked ? 'revoke-all' : null)}
              />
              <span>Подтверждаю выход на всех устройствах, включая это.</span>
            </label>
            <button
              id="account-revoke-submit"
              className="demo-auth__submit demo-auth__submit--danger"
              type="submit"
            >
              {pendingAction === 'revoke-all' ? 'Завершаем сеансы…' : 'Выйти со всех устройств'}
            </button>
          </fieldset>
        </form>
      </details>
      <p className="demo-auth__recovery-note">
        Не помните пароль? <Link to="/forgot-password">Проверить доступность восстановления</Link>.{' '}
        Восстановление по email доступно только после настройки доставки; переход не отправляет письмо.
      </p>
    </div>
  );
}
