import { useCallback, useLayoutEffect, useRef, useState, type FormEvent } from 'react';
import { useQuery, useQueryClient } from '@tanstack/react-query';
import {
  ArrowLeft,
  ArrowRight,
  Check,
  ChevronDown,
  LockKeyhole,
  LogOut,
  ScanLine,
  Settings2,
  UserRound,
} from 'lucide-react';
import { Link, useLocation, useNavigate } from 'react-router-dom';
import { ReportPreferencesPanel } from '@/features/auth/ReportPreferencesPanel';
import { currentDemoUser, logoutDemoUser, submitDemoCredentials } from '@/shared/api/auth/demoAuth';
import { scanSession, subscribeScanSession, transitionScanSession } from '@/shared/api/auth/scanSession';
import { useScanSession } from '@/shared/api/auth/useScanSession';
import { safeAuthReturnTo } from '@/shared/api/auth/authReturnTo';
import { useSessionRecovery } from '@/shared/api/auth/useSessionRecovery';
import {
  invalidateConfirmedBrowserSession,
  revalidateBrowserSession,
} from '@/shared/api/auth/revalidateBrowserSession';
import {
  changePassword,
  revokeAllSessions,
  normalizeAuthEmail,
  PASSWORD_HINT,
  validAuthPassword,
  securityErrorMessage,
  shouldRecheckSession,
} from '@/shared/api/auth/accountSecurity';
import {
  AccountSecurityForm,
  type AccountSecurityAction,
  type AccountSecurityDraft,
} from './AccountSecurityForm';
import './demo-auth.css';

type Mode = 'register' | 'login' | 'account';
const emptySecurityDraft: AccountSecurityDraft = { currentPassword: '', newPassword: '', confirmation: '' };

export function DemoAuthPage({ mode }: { mode: Mode }) {
  const location = useLocation();
  // Route/mode changes retire the old form even when React would reuse its component.
  return <AuthPageScope key={JSON.stringify([mode, location.key])} mode={mode} />;
}

function AccountSessionPending({ message }: { message: string }) {
  return (
    <section
      className="demo-auth__panel demo-auth__account-state demo-auth__pending"
      aria-label="Проверка входа"
    >
      <p className="demo-auth__pending-status" role="status" aria-atomic="true">
        <span className="demo-auth__pending-indicator" aria-hidden="true" />
        {message}
      </p>
      <p className="demo-auth__pending-description">Данные аккаунта скрыты до успешной проверки.</p>
      <div className="demo-auth__pending-placeholder" aria-hidden="true">
        <span />
        <span />
      </div>
    </section>
  );
}

function AuthPageScope({ mode }: { mode: Mode }) {
  const mounted = useRef(false);
  const operation = useRef<symbol | null>(null);
  useLayoutEffect(() => {
    mounted.current = true;
    return () => {
      mounted.current = false;
      operation.current = null;
    };
  }, []);
  const [email, setEmail] = useState('');
  const [password, setPassword] = useState('');
  const [busy, setBusy] = useState(false);
  const [pendingAction, setPendingAction] = useState<AccountSecurityAction | 'logout' | null>(null);
  const [error, setError] = useState('');
  // Kept above the private-data gate so an ambiguous request does not erase a draft.
  const [securityDraft, setSecurityDraft] = useState({ owner: null as string | null, ...emptySecurityDraft });
  const [securitySection, setSecuritySection] = useState<{
    owner: string | null;
    section: AccountSecurityAction | null;
  }>({ owner: null, section: null });
  const [preferencesSection, setPreferencesSection] = useState<{ owner: string | null; open: boolean }>({
    owner: null,
    open: false,
  });
  const securityContainer = useRef<HTMLElement>(null);
  const suspendedSecurityFocus = useRef<{ owner: string; generation: number; id: string } | null>(null);
  const navigate = useNavigate();
  const location = useLocation();
  const returnTo = safeAuthReturnTo(location.state?.returnTo);
  const authState = { returnTo };
  const queryClient = useQueryClient();
  const session = useQuery({
    queryKey: ['demo-auth', 'me'],
    queryFn: async ({ signal }) => {
      try {
        const user = await currentDemoUser(signal);
        if (signal.aborted) throw new Error('Проверка сессии отменена');
        transitionScanSession(user?.id ?? null, queryClient);
        return user;
      } catch (reason) {
        if (!signal.aborted) transitionScanSession(null, queryClient, false, 'unverified');
        throw reason;
      }
    },
    retry: false,
    staleTime: 30_000,
    refetchOnWindowFocus: 'always',
    refetchInterval: mode === 'account' ? 30_000 : false,
  });
  useSessionRecovery(mode === 'account' && session.isError);
  const identity = useScanSession();
  const checkingSession = session.isPending || session.isFetching || session.isPaused;
  const confirmedOwner =
    mode === 'account' && !checkingSession && session.isSuccess && session.data?.id === identity.subject
      ? identity.subject
      : null;
  const suspendSecurityFocus = useCallback(
    (id: string) => {
      if (operation.current || !identity.subject) return;
      suspendedSecurityFocus.current = { owner: identity.subject, generation: identity.generation, id };
    },
    [identity.subject, identity.generation],
  );

  useLayoutEffect(() => {
    const focus = suspendedSecurityFocus.current;
    if (!focus) return;
    if (
      operation.current ||
      session.isError ||
      focus.owner !== identity.subject ||
      focus.generation !== identity.generation
    ) {
      suspendedSecurityFocus.current = null;
      return;
    }
    if (checkingSession) {
      // Listen only across this GET; footer/browser interactions must also cancel restoration.
      const cancel = () => {
        suspendedSecurityFocus.current = null;
      };
      document.addEventListener('focusin', cancel, true);
      document.addEventListener('pointerdown', cancel, true);
      document.addEventListener('keydown', cancel, true);
      window.addEventListener('blur', cancel);
      return () => {
        document.removeEventListener('focusin', cancel, true);
        document.removeEventListener('pointerdown', cancel, true);
        document.removeEventListener('keydown', cancel, true);
        window.removeEventListener('blur', cancel);
      };
    }
    suspendedSecurityFocus.current = null;
    if (confirmedOwner !== focus.owner || !document.hasFocus() || document.activeElement !== document.body)
      return;
    const target = document.getElementById(focus.id);
    if (
      target &&
      securityContainer.current?.contains(target) &&
      !target.matches(':disabled') &&
      (target.matches('summary') || !target.closest('details:not([open])'))
    ) {
      target.focus({ preventScroll: true });
    }
  }, [checkingSession, confirmedOwner, identity.subject, identity.generation, session.isError]);

  useLayoutEffect(
    () =>
      subscribeScanSession(() => {
        const owner = scanSession().subject;
        suspendedSecurityFocus.current = null;
        if (owner) {
          setSecurityDraft((previous) =>
            previous.owner && previous.owner !== owner ? { owner: null, ...emptySecurityDraft } : previous,
          );
          setSecuritySection((previous) =>
            previous.owner && previous.owner !== owner ? { owner: null, section: null } : previous,
          );
          setPreferencesSection((previous) =>
            previous.owner && previous.owner !== owner ? { owner: null, open: false } : previous,
          );
        }
      }),
    [],
  );
  useLayoutEffect(() => {
    const confirmedAnonymous = session.isSuccess && session.data === null && !session.isFetching;
    if (confirmedAnonymous || (identity.subject && securityDraft.owner !== identity.subject)) {
      setSecurityDraft((previous) =>
        previous.owner === null &&
        !previous.currentPassword &&
        !previous.newPassword &&
        !previous.confirmation
          ? previous
          : { owner: null, ...emptySecurityDraft },
      );
    }
  }, [identity.subject, securityDraft.owner, session.isSuccess, session.data, session.isFetching]);
  useLayoutEffect(() => {
    const confirmedAnonymous = session.isSuccess && session.data === null && !checkingSession;
    if (
      confirmedAnonymous ||
      (identity.subject && securitySection.owner && securitySection.owner !== identity.subject)
    ) {
      setSecuritySection((previous) => (previous.owner === null ? previous : { owner: null, section: null }));
      suspendedSecurityFocus.current = null;
    }
  }, [checkingSession, identity.subject, securitySection.owner, session.isSuccess, session.data]);
  useLayoutEffect(() => {
    const confirmedAnonymous = session.isSuccess && session.data === null && !checkingSession;
    if (
      confirmedAnonymous ||
      (identity.subject && preferencesSection.owner && preferencesSection.owner !== identity.subject)
    ) {
      setPreferencesSection((previous) =>
        previous.owner === null ? previous : { owner: null, open: false },
      );
    }
  }, [checkingSession, identity.subject, preferencesSection.owner, session.isSuccess, session.data]);

  async function secureAccount(action: AccountSecurityAction) {
    if (operation.current || !mounted.current) return;
    const initial = scanSession();
    if (!initial.subject || session.data?.id !== initial.subject || securityDraft.owner !== initial.subject) {
      setError('Введите текущий пароль для подтверждённого аккаунта.');
      return;
    }
    if (
      !validAuthPassword(securityDraft.currentPassword) ||
      (action === 'change-password' && !validAuthPassword(securityDraft.newPassword))
    ) {
      setError(PASSWORD_HINT);
      return;
    }
    if (action === 'change-password' && securityDraft.newPassword !== securityDraft.confirmation) {
      setError('Новый пароль и его повтор не совпадают.');
      return;
    }
    const token = Symbol();
    operation.current = token;
    const current = () => mounted.current && operation.current === token;
    setBusy(true);
    setPendingAction(action);
    setError('');
    let completed = false;
    try {
      if (action === 'change-password')
        await changePassword(securityDraft.currentPassword, securityDraft.newPassword);
      else await revokeAllSessions(securityDraft.currentPassword);
      completed = true;
      if (current()) setSecurityDraft({ owner: null, ...emptySecurityDraft });
      const invalidated =
        current() && scanSession().generation === initial.generation
          ? await invalidateConfirmedBrowserSession(queryClient)
          : false;
      if (current() && invalidated) {
        navigate('/login', {
          replace: true,
          state: {
            sessionNotice:
              action === 'change-password'
                ? 'Пароль изменён. Все сессии завершены — войдите с новым паролем.'
                : 'Все сессии завершены. Войдите заново.',
          },
        });
      } else {
        // A late response may clear the cookie, but cannot act for a newly displayed owner.
        await revalidateBrowserSession(queryClient);
        if (current()) setError('Запрос выполнен. Сессия изменилась; проверьте текущий вход в аккаунт.');
      }
    } catch (reason) {
      let message = completed
        ? 'Запрос выполнен, но текущую сессию проверить не удалось. Повторите только проверку сессии.'
        : securityErrorMessage(reason);
      if (!completed && shouldRecheckSession(reason)) {
        try {
          await revalidateBrowserSession(queryClient);
        } catch {
          message += ' Сессию проверить не удалось. Данные скрыты до успешной проверки.';
        }
      }
      if (current()) setError(message);
    } finally {
      if (current()) {
        operation.current = null;
        setBusy(false);
        setPendingAction(null);
      }
    }
  }

  async function authenticate(action: 'login' | 'register' | 'logout') {
    if (operation.current || !mounted.current) return;
    if (action !== 'logout' && (!normalizeAuthEmail(email) || !validAuthPassword(password))) {
      setError(
        !normalizeAuthEmail(email)
          ? 'Введите корректный email длиной не более 254 байт UTF-8.'
          : PASSWORD_HINT,
      );
      return;
    }
    const token = Symbol();
    operation.current = token;
    const current = () => mounted.current && operation.current === token;
    setBusy(true);
    setPendingAction(action === 'logout' ? 'logout' : null);
    setError('');
    let expectedSubject: string | null = null;
    let failure = '';
    try {
      if (action === 'logout') await logoutDemoUser();
      else expectedSubject = (await submitDemoCredentials(action, email, password)).id;
    } catch (reason) {
      failure = reason instanceof Error ? reason.message : 'Не удалось выполнить запрос.';
    }
    try {
      // Do not publish the POST payload. Even a lost/late reply may have set a server cookie.
      const verified = await revalidateBrowserSession(queryClient);
      if (!current()) return;
      if (failure) setError(failure);
      else if (verified === undefined || (verified?.id ?? null) !== expectedSubject)
        setError('Сессия изменилась. Проверьте текущий аккаунт; автоматический переход отменён.');
      else {
        setPassword('');
        navigate(action === 'logout' ? '/login' : returnTo, { replace: true });
      }
    } catch {
      if (current())
        setError(
          failure ||
            'Запрос выполнен, но проверить сессию не удалось. Откройте аккаунт и повторите проверку сессии.',
        );
    } finally {
      if (current()) {
        operation.current = null;
        setBusy(false);
        setPendingAction(null);
      }
    }
  }

  function submit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    void authenticate(mode === 'register' ? 'register' : 'login');
  }

  function logout() {
    if (operation.current) return;
    setSecuritySection({ owner: null, section: null });
    setPreferencesSection({ owner: null, open: false });
    suspendedSecurityFocus.current = null;
    void authenticate('logout');
  }

  return (
    <main className={mode === 'account' ? 'demo-auth demo-auth--account' : 'demo-auth'}>
      <div className="demo-auth__frame">
        <header className="demo-auth__header">
          <Link to="/" className="demo-auth__brand" aria-label="OCI / VISION — на главную">
            <span className="demo-auth__brand-mark">
              <ScanLine size={22} aria-hidden="true" />
            </span>
            <span>
              OCI <span className="demo-auth__brand-slash">/</span> VISION
            </span>
          </Link>
          <Link to="/" className="demo-auth__back">
            <ArrowLeft size={17} aria-hidden="true" /> На главную
          </Link>
        </header>
        {mode === 'account' ? (
          <div className="demo-auth__account">
            <header className="demo-auth__account-heading">
              <span className="demo-auth__eyebrow">ЛИЧНЫЙ КАБИНЕТ</span>
              <h1 id="auth-title">
                Ваш аккаунт<span>.</span>
              </h1>
              <p>Ваши проверки и управление доступом — в одном месте.</p>
            </header>
            {error ? (
              <p role="alert" className="demo-auth__error">
                {error}
              </p>
            ) : null}
            {pendingAction ? (
              <p role="status" className="demo-auth__notice">
                {pendingAction === 'logout'
                  ? 'Выходим из аккаунта…'
                  : pendingAction === 'change-password'
                    ? 'Меняем пароль и завершаем все сеансы…'
                    : 'Завершаем сеансы на всех устройствах…'}
              </p>
            ) : null}
            {checkingSession ? (
              <AccountSessionPending
                message={session.isPaused ? 'Ждём подключения для проверки входа…' : 'Проверяем сессию…'}
              />
            ) : session.isError ? (
              <section
                className="demo-auth__panel demo-auth__account-state"
                aria-labelledby="account-session-title"
              >
                <h2 id="account-session-title">Не удалось проверить вход</h2>
                <p role="alert">Данные скрыты до успешной проверки. Выход из аккаунта не выполнялся.</p>
                <button
                  className="demo-auth__submit"
                  type="button"
                  disabled={busy || session.isFetching}
                  onClick={() => void session.refetch({ cancelRefetch: false })}
                >
                  {session.isFetching ? 'Проверяем сессию…' : 'Повторить проверку сессии'}
                </button>
                <Link className="demo-auth__text-link" to="/login" state={authState}>
                  Перейти ко входу
                </Link>
              </section>
            ) : session.data && identity.subject !== session.data.id ? (
              <AccountSessionPending message="Подтверждаем сессию…" />
            ) : session.data && identity.subject === session.data.id ? (
              <>
                <section
                  className="demo-auth__panel demo-auth__identity"
                  aria-labelledby="account-identity-title"
                >
                  <div className="demo-auth__identity-copy">
                    <span className="demo-auth__avatar" aria-hidden="true">
                      <UserRound size={28} />
                    </span>
                    <div>
                      <span className="demo-auth__session-badge">
                        <Check size={14} aria-hidden="true" /> Вы вошли
                      </span>
                      <h2 id="account-identity-title">Email аккаунта</h2>
                      <p className="demo-auth__email">{session.data.email}</p>
                    </div>
                  </div>
                  <div className="demo-auth__scan-actions">
                    <Link className="demo-auth__submit" to="/scans/new">
                      <ScanLine size={19} aria-hidden="true" /> Проверить образ{' '}
                      <ArrowRight size={18} aria-hidden="true" />
                    </Link>
                    <Link className="demo-auth__text-link" to="/scans">
                      Мои проверки <ArrowRight size={16} aria-hidden="true" />
                    </Link>
                    <p className="demo-auth__hint">Для реальной проверки нужно разрешение сервера.</p>
                  </div>
                </section>
                <section
                  className="demo-auth__panel demo-auth__account-settings"
                  aria-labelledby="account-settings-title"
                  ref={securityContainer}
                >
                  <div className="demo-auth__section-heading">
                    <span className="demo-auth__section-icon" aria-hidden="true">
                      <LockKeyhole size={21} />
                    </span>
                    <div>
                      <h2 id="account-settings-title">Безопасность</h2>
                      <p>Управляйте паролем и доступом с других устройств.</p>
                    </div>
                  </div>
                  <AccountSecurityForm
                    key={session.data.id}
                    draft={securityDraft.owner === identity.subject ? securityDraft : emptySecurityDraft}
                    disabled={busy}
                    pendingAction={pendingAction}
                    openSection={securitySection.owner === identity.subject ? securitySection.section : null}
                    onSectionChange={(section) => setSecuritySection({ owner: identity.subject, section })}
                    onSuspendFocus={suspendSecurityFocus}
                    onChange={(draft) => setSecurityDraft({ ...draft, owner: identity.subject })}
                    onSubmit={(action) => void secureAccount(action)}
                  />
                  <div className="demo-auth__logout">
                    <div>
                      <h3>Выйти на этом устройстве</h3>
                      <p>Сеансы на других устройствах останутся открыты.</p>
                    </div>
                    <button
                      className="demo-auth__submit demo-auth__submit--secondary"
                      type="button"
                      onClick={logout}
                      disabled={busy}
                    >
                      <LogOut size={17} aria-hidden="true" />{' '}
                      {pendingAction === 'logout' ? 'Выходим…' : 'Выйти из аккаунта'}
                    </button>
                  </div>
                </section>
                <details
                  className="demo-auth__panel demo-auth__preferences"
                  key={session.data.id}
                  open={preferencesSection.owner === identity.subject && preferencesSection.open}
                >
                  <summary
                    className="demo-auth__disclosure"
                    onClick={(event) => {
                      event.preventDefault();
                      if (!confirmedOwner) return;
                      setPreferencesSection((previous) => ({
                        owner: confirmedOwner,
                        open: previous.owner !== confirmedOwner || !previous.open,
                      }));
                    }}
                  >
                    <Settings2 size={21} aria-hidden="true" />
                    <span>
                      <span className="demo-auth__disclosure-title">Настройки отчётов</span>
                      <span className="demo-auth__disclosure-description">
                        Язык и автоматический разбор в этом браузере
                      </span>
                    </span>
                    <ChevronDown className="demo-auth__chevron" size={20} aria-hidden="true" />
                  </summary>
                  <ReportPreferencesPanel key={session.data.id} subject={session.data.id} disabled={busy} />
                </details>
                <p className="demo-auth__account-demo">
                  Хотите посмотреть пример? <Link to="/demo/scans">Открыть демо</Link> — вымышленные данные,
                  без запуска проверки.
                </p>
              </>
            ) : (
              <section
                className="demo-auth__panel demo-auth__account-state"
                aria-labelledby="account-signin-title"
              >
                <LockKeyhole size={26} aria-hidden="true" />
                <h2 id="account-signin-title">Войдите в свой аккаунт</h2>
                <p>
                  Вход не выполнен или сессия истекла. Войдите, чтобы открыть свои проверки и настройки
                  безопасности.
                </p>
                <Link className="demo-auth__submit" to="/login" state={authState}>
                  Войти <ArrowRight size={18} aria-hidden="true" />
                </Link>
                <Link className="demo-auth__text-link" to="/register" state={authState}>
                  Создать аккаунт
                </Link>
                <p className="demo-auth__hint">
                  <Link to="/demo/scans">Демо доступно без входа</Link>
                </p>
              </section>
            )}
          </div>
        ) : (
          <div className="demo-auth__grid">
            <section
              className={mode === 'login' ? 'demo-auth__intro demo-auth__intro--login' : 'demo-auth__intro'}
              aria-labelledby="auth-title"
            >
              <span className="demo-auth__eyebrow">ДОСТУП / СТЕНДОВЫЙ РЕЖИМ</span>
              <h1 id="auth-title">
                {mode === 'register' ? 'Создайте аккаунт.' : 'Рады вас видеть.'}
                <span> Демо открыто каждому.</span>
              </h1>
              <p>
                Знакомство с интерфейсом не требует регистрации. Вымышленные записи доступны всем; вход сам по
                себе не даёт права на реальное сканирование.
              </p>
              <Link className="demo-auth__demo-link" to="/demo/scans">
                Смотреть демо без регистрации <ArrowRight size={18} aria-hidden="true" />
              </Link>
            </section>
            <section className="demo-auth__panel" aria-label="Учётная запись">
              <span className="demo-auth__eyebrow">
                {mode === 'register' ? '01 / РЕГИСТРАЦИЯ' : '02 / ВХОД'}
              </span>
              <h2>{mode === 'register' ? 'Регистрация' : 'Вход'}</h2>
              {mode === 'login' && typeof location.state?.sessionNotice === 'string' ? (
                <p role="status" className="demo-auth__success">
                  <Check size={18} aria-hidden="true" /> {location.state.sessionNotice}
                </p>
              ) : null}
              <form onSubmit={submit}>
                <label htmlFor="demo-auth-email">Email</label>
                <input
                  id="demo-auth-email"
                  name="email"
                  type="email"
                  autoComplete="email"
                  required
                  maxLength={254}
                  value={email}
                  disabled={busy}
                  onChange={(event) => setEmail(event.target.value)}
                />
                <label htmlFor="demo-auth-password">Пароль</label>
                <input
                  id="demo-auth-password"
                  name="password"
                  type="password"
                  autoComplete={mode === 'register' ? 'new-password' : 'current-password'}
                  aria-describedby="auth-password-hint"
                  maxLength={128}
                  required
                  value={password}
                  disabled={busy}
                  onChange={(event) => setPassword(event.target.value)}
                />
                <p id="auth-password-hint" className="demo-auth__hint">
                  {PASSWORD_HINT}
                </p>
                {error ? (
                  <p role="alert" className="demo-auth__error">
                    {error}
                  </p>
                ) : null}
                <button className="demo-auth__submit" type="submit" disabled={busy}>
                  <LockKeyhole size={18} aria-hidden="true" />{' '}
                  {busy ? 'Подождите…' : mode === 'register' ? 'Создать аккаунт' : 'Войти'}
                </button>
              </form>
              {mode === 'login' ? (
                <p>
                  <Link to="/forgot-password">Забыли пароль?</Link>
                </p>
              ) : null}
              <p className="demo-auth__switch">
                {mode === 'register' ? (
                  <>
                    Уже есть аккаунт?{' '}
                    <Link to="/login" state={authState}>
                      Войти
                    </Link>
                  </>
                ) : (
                  <>
                    Нет аккаунта?{' '}
                    <Link to="/register" state={authState}>
                      Зарегистрироваться
                    </Link>
                  </>
                )}
              </p>
              <p className="demo-auth__hint">
                Пароль не передаётся в интерфейс после входа. Сканы доступны только при действующей сессии и
                разрешении сервера.
              </p>
            </section>
          </div>
        )}
      </div>
    </main>
  );
}
