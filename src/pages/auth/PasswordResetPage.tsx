import { useLayoutEffect, useRef, useState, type FormEvent } from 'react';
import { useQuery, useQueryClient } from '@tanstack/react-query';
import { Link, useLocation, useNavigate } from 'react-router-dom';
import {
  AuthSecurityError,
  confirmPasswordReset,
  getPasswordResetStatus,
  normalizeAuthEmail,
  PASSWORD_HINT,
  requestPasswordReset,
  securityErrorMessage,
  shouldRecheckSession,
  validAuthPassword,
  validResetToken,
} from '@/shared/api/auth/accountSecurity';
import { invalidateConfirmedBrowserSession, revalidateBrowserSession } from '@/shared/api/auth/revalidateBrowserSession';
import { scanSession } from '@/shared/api/auth/scanSession';
import './demo-auth.css';

type Mode = 'request' | 'confirm';

// Eager route: strip the fragment before any lazy loading or readiness request.
export function PasswordResetPage({ mode }: { mode: Mode }) {
  const location = useLocation();
  const navigate = useNavigate();
  const client = useQueryClient();
  const mounted = useRef(false);
  const operation = useRef<symbol | null>(null);
  const secret = useRef('');
  const scrubbing = useRef(false);
  const [hasToken, setHasToken] = useState(false);
  const [email, setEmail] = useState('');
  const [password, setPassword] = useState('');
  const [confirmation, setConfirmation] = useState('');
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState('');
  const [accepted, setAccepted] = useState(false);
  const [unavailable, setUnavailable] = useState(false);
  useLayoutEffect(() => {
    mounted.current = true;
    return () => { mounted.current = false; operation.current = null; };
  }, []);
  useLayoutEffect(() => {
    if (!location.hash && !location.search && scrubbing.current) {
      scrubbing.current = false;
      return;
    }
    // Neither query tokens nor extra fragment fields are accepted. Never echo the input.
    const candidate = mode === 'confirm' && !location.search && /^#token=[A-Za-z0-9_-]{43}$/.test(location.hash)
      ? location.hash.slice(7) : '';
    secret.current = validResetToken(candidate) ? candidate : '';
    setHasToken(Boolean(secret.current));
    operation.current = null;
    setBusy(false);
    setPassword('');
    setConfirmation('');
    setError('');
    setAccepted(false);
    if (location.hash || location.search) {
      scrubbing.current = true;
      navigate(location.pathname, { replace: true, state: null });
    }
  }, [location.hash, location.search, location.key, location.pathname, mode, navigate]);

  const readiness = useQuery({
    queryKey: ['auth', 'password-reset', 'status'],
    queryFn: ({ signal }) => getPasswordResetStatus(signal),
    retry: false,
    staleTime: 0,
    refetchOnMount: 'always',
    refetchOnWindowFocus: false,
    refetchOnReconnect: false,
    gcTime: 0,
  });
  const ready = readiness.isSuccess && !readiness.isFetching && readiness.data.available && !unavailable;

  async function submit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    if (!ready || operation.current || !mounted.current || accepted) return;
    if (mode === 'request' && !normalizeAuthEmail(email)) {
      setError('Введите корректный email длиной не более 254 байт UTF-8.');
      return;
    }
    if (mode === 'confirm' && (!secret.current || !validAuthPassword(password) || password !== confirmation)) {
      setError(!secret.current ? 'Откройте действительную ссылку из письма.' : !validAuthPassword(password) ? PASSWORD_HINT : 'Пароль и его повтор не совпадают.');
      return;
    }
    const token = Symbol();
    operation.current = token;
    const current = () => mounted.current && operation.current === token;
    const initial = scanSession();
    setBusy(true);
    setError('');
    let completed = false;
    try {
      if (mode === 'request') {
        await requestPasswordReset(email);
        if (current()) setAccepted(true);
        return;
      }
      await confirmPasswordReset(secret.current, password);
      completed = true;
      if (current()) {
        secret.current = '';
        setHasToken(false);
        setPassword('');
        setConfirmation('');
      }
      const invalidated = current() && scanSession().generation === initial.generation
        ? await invalidateConfirmedBrowserSession(client) : false;
      if (current() && invalidated) {
        navigate('/login', { replace: true, state: { sessionNotice: 'Пароль изменён, прежние сессии этого аккаунта завершены. Войдите с новым паролем.' } });
      } else {
        await revalidateBrowserSession(client);
        if (current()) setError('Пароль изменён. Сессия браузера изменилась; перейдите ко входу.');
      }
    } catch (reason) {
      let message = completed ? 'Пароль изменён, но сессию проверить не удалось. Перейдите ко входу; запрос смены повторять не нужно.' : securityErrorMessage(reason);
      if (!completed && mode === 'confirm' && shouldRecheckSession(reason)) {
        try { await revalidateBrowserSession(client); }
        catch { message += ' Сессию проверить не удалось; автоматического повтора не будет.'; }
      }
      if (current()) {
        if (reason instanceof AuthSecurityError && reason.code === 'PASSWORD_RESET_UNAVAILABLE') setUnavailable(true);
        if (reason instanceof AuthSecurityError && reason.code === 'INVALID_RESET_TOKEN') {
          secret.current = '';
          setHasToken(false);
        }
        setError(message);
      }
    } finally {
      if (current()) { operation.current = null; setBusy(false); }
    }
  }

  async function checkAvailability() {
    if (busy || readiness.isFetching) return;
    const result = await readiness.refetch();
    if (mounted.current && result.isSuccess) setUnavailable(false);
  }

  return (
    <main className="demo-auth demo-auth--recovery">
      <div className="demo-auth__frame">
        <header className="demo-auth__header">
          <Link className="demo-auth__brand" to="/">OCI / VISION</Link>
          <Link to="/login">Ко входу</Link>
        </header>
        <section className="demo-auth__panel demo-auth__recovery" aria-labelledby="recovery-title">
          <h1 id="recovery-title">{mode === 'request' ? 'Восстановить доступ' : 'Задать новый пароль'}</h1>
          {readiness.isPending || readiness.isFetching ? <p role="status">Проверяем доступность восстановления…</p> : null}
          {readiness.isError ? <p role="alert">Не удалось проверить доступность восстановления. Запрос на смену пароля не отправлен.</p> : null}
          {unavailable || (readiness.isSuccess && !readiness.data.available) ? (
            <p role="status">Восстановление сейчас недоступно. {readiness.data?.available === false && readiness.data.reason === 'AUTH_UNAVAILABLE'
              ? 'Сервис аккаунтов недоступен; оператору сайта нужно проверить его работу.'
              : 'Оператору сайта нужно настроить и проверить доставку ссылок восстановления.'} Письмо не отправлено.</p>
          ) : null}
          {!ready ? <button className="demo-auth__submit" type="button" disabled={busy || readiness.isFetching} onClick={() => void checkAvailability()}>Повторить проверку доступности</button> : null}
          {mode === 'confirm' && !hasToken ? <p>Действительная ссылка не найдена. Откройте ссылку из письма или <Link to="/forgot-password">запросите новую</Link>. После перезагрузки страницы ссылку нужно открыть заново.</p> : null}
          {accepted ? (
            <p role="status">Запрос принят. Если адрес подходит для восстановления и доставка сработает, вы получите инструкции. Это не подтверждение отправки или доставки письма.</p>
          ) : (
            <form onSubmit={submit} aria-busy={busy} aria-describedby="recovery-help">
              <fieldset disabled={!ready || busy || (mode === 'confirm' && !hasToken)}>
                <legend className="sr-only">{mode === 'request' ? 'Email для восстановления' : 'Новый пароль'}</legend>
                {mode === 'request' ? (
                  <>
                    <label htmlFor="recovery-email">Email аккаунта</label>
                    <input id="recovery-email" type="email" autoComplete="email" required maxLength={254} value={email} onChange={event => setEmail(event.target.value)} />
                    <p id="recovery-help" className="demo-auth__hint">Ответ не раскрывает, зарегистрирован ли этот адрес. Отправка формы не означает доставку письма.</p>
                  </>
                ) : (
                  <>
                    <label htmlFor="recovery-password">Новый пароль</label>
                    <input id="recovery-password" type="password" autoComplete="new-password" required maxLength={128} value={password} onChange={event => setPassword(event.target.value)} />
                    <label htmlFor="recovery-confirmation">Повторите новый пароль</label>
                    <input id="recovery-confirmation" type="password" autoComplete="new-password" required maxLength={128} value={confirmation} onChange={event => setConfirmation(event.target.value)} />
                    <p id="recovery-help" className="demo-auth__hint">{PASSWORD_HINT} После смены нужно войти заново. Сессия в этом браузере тоже завершится, даже если здесь открыт другой аккаунт.</p>
                  </>
                )}
                <button className="demo-auth__submit" type="submit">{busy ? 'Подождите…' : mode === 'request' ? 'Запросить восстановление' : 'Сохранить новый пароль'}</button>
              </fieldset>
            </form>
          )}
          {error ? <p role="alert" className="demo-auth__error">{error}</p> : null}
          <p><Link to="/login">Вернуться ко входу</Link></p>
        </section>
      </div>
    </main>
  );
}
