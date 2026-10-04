import { useState, type FormEvent } from 'react';
import { useQuery, useQueryClient } from '@tanstack/react-query';
import { ArrowLeft, ArrowRight, LockKeyhole, ScanLine } from 'lucide-react';
import { Link, useLocation, useNavigate } from 'react-router-dom';
import { currentDemoUser, logoutDemoUser, submitDemoCredentials } from '@/shared/api/auth/demoAuth';
import { transitionScanSession } from '@/shared/api/auth/scanSession';
import { useSessionRecovery } from '@/shared/api/auth/useSessionRecovery';
import './demo-auth.css';

type Mode = 'register' | 'login' | 'account';

export function DemoAuthPage({ mode }: { mode: Mode }) {
  const [email, setEmail] = useState('');
  const [password, setPassword] = useState('');
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState('');
  const navigate = useNavigate();
  const location = useLocation();
  const queryClient = useQueryClient();
  const session = useQuery({ queryKey: ['demo-auth', 'me'], queryFn: async ({ signal }) => {
      try {
        const user = await currentDemoUser(signal);
        if (signal.aborted) throw new Error('Проверка сессии отменена');
        transitionScanSession(user?.id ?? null, queryClient);
        return user;
      } catch (reason) {
        if (!signal.aborted) transitionScanSession(null, queryClient);
        throw reason;
      }
    }, retry: false, staleTime: 30_000, refetchOnWindowFocus: 'always', refetchInterval: mode === 'account' ? 30_000 : false });
  useSessionRecovery(mode === 'account' && session.isError);

  async function submit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    if (busy) return;
    setBusy(true);
    setError('');
    try {
      const user = await submitDemoCredentials(mode === 'register' ? 'register' : 'login', email, password);
      setPassword('');
      transitionScanSession(user.id, queryClient, true);
      await queryClient.cancelQueries();
      queryClient.clear();
      queryClient.setQueryData(['demo-auth', 'me'], user);
      navigate('/account');
    } catch (reason) {
      setError(reason instanceof Error ? reason.message : 'Не удалось выполнить запрос.');
    } finally {
      setBusy(false);
    }
  }

  async function logout() {
    if (busy) return;
    setBusy(true);
    setError('');
    try {
      await logoutDemoUser();
      transitionScanSession(null, queryClient, true);
      await queryClient.cancelQueries();
      queryClient.clear();
      navigate('/login');
    } catch (reason) {
      setError(reason instanceof Error ? reason.message : 'Не удалось выйти.');
    } finally {
      setBusy(false);
    }
  }

  return (
    <main className="demo-auth">
      <div className="demo-auth__frame">
        <header className="demo-auth__header">
          <Link to="/" className="demo-auth__brand" aria-label="OCI / VISION — на главную">
            <ScanLine size={22} aria-hidden="true" /> OCI / VISION
          </Link>
          <Link to="/" className="demo-auth__back"><ArrowLeft size={17} aria-hidden="true" /> На главную</Link>
        </header>
        <div className="demo-auth__grid">
          <section className="demo-auth__intro" aria-labelledby="auth-title">
            <span className="demo-auth__eyebrow">ДОСТУП / СТЕНДОВЫЙ РЕЖИМ</span>
            <h1 id="auth-title">
              {mode === 'register' ? 'Создайте аккаунт.' : mode === 'login' ? 'С возвращением.' : 'Ваш аккаунт.'}
              <span> Демо открыто каждому.</span>
            </h1>
            <p>Знакомство с интерфейсом не требует регистрации. Вымышленные записи доступны всем; вход сам по себе не даёт права на реальное сканирование.</p>
            <Link className="demo-auth__demo-link" to="/demo/scans">
              Смотреть демо без регистрации <ArrowRight size={18} aria-hidden="true" />
            </Link>
          </section>
          <section className="demo-auth__panel" aria-label="Учётная запись">
            <span className="demo-auth__eyebrow">{mode === 'account' ? 'ВАША СЕССИЯ' : mode === 'register' ? '01 / РЕГИСТРАЦИЯ' : '02 / ВХОД'}</span>
            {mode === 'account' ? (
              session.isPending ? <p role="status">Проверяем сессию…</p> : session.isError ? (
                <p role="status">Проверка сессии не удалась. Закрываем доступ…</p>
              ) : session.data ? (
                <>
                  <h2>Вы вошли</h2>
                  <p className="demo-auth__email">{session.data.email}</p>
                  <p>ID аккаунта для разрешения доступа к сканам: <code className="demo-auth__email">{session.data.id}</code></p>
                  <p>Реальные сканы доступны только аккаунтам с отдельным разрешением сервера. <Link to="/scans">Открыть сканы</Link>.</p>
                  <button className="demo-auth__submit" type="button" onClick={logout} disabled={busy}>Выйти из аккаунта</button>
                </>
              ) : (
                <><h2>Вход не выполнен</h2><Link to="/login">Войти</Link> · <Link to="/register">Создать аккаунт</Link></>
              )
            ) : (
              <>
                <h2>{mode === 'register' ? 'Регистрация' : 'Вход'}</h2>
                {mode === 'login' && typeof location.state?.sessionNotice === 'string' ? (
                  <p role="alert" className="demo-auth__error">{location.state.sessionNotice}</p>
                ) : null}
                <form onSubmit={submit}>
                  <label htmlFor="demo-auth-email">Email</label>
                  <input id="demo-auth-email" name="email" type="email" autoComplete="email" required maxLength={254} value={email} onChange={event => setEmail(event.target.value)} />
                  <label htmlFor="demo-auth-password">Пароль</label>
                  <input id="demo-auth-password" name="password" type="password" autoComplete={mode === 'register' ? 'new-password' : 'current-password'} minLength={12} maxLength={128} required value={password} onChange={event => setPassword(event.target.value)} />
                  {mode === 'register' ? <p className="demo-auth__hint">Не менее 12 символов. Используйте уникальный пароль.</p> : null}
                  {error ? <p role="alert" className="demo-auth__error">{error}</p> : null}
                  <button className="demo-auth__submit" type="submit" disabled={busy}>
                    <LockKeyhole size={18} aria-hidden="true" /> {busy ? 'Подождите…' : mode === 'register' ? 'Создать аккаунт' : 'Войти'}
                  </button>
                </form>
                <p className="demo-auth__switch">
                  {mode === 'register' ? <>Уже есть аккаунт? <Link to="/login">Войти</Link></> : <>Нет аккаунта? <Link to="/register">Зарегистрироваться</Link></>}
                </p>
                <p className="demo-auth__hint">Пароль не передаётся в интерфейс после входа. Сканы доступны только при действующей сессии и разрешении сервера.</p>
              </>
            )}
            {mode === 'account' && error ? <p role="alert" className="demo-auth__error">{error}</p> : null}
          </section>
        </div>
      </div>
    </main>
  );
}
