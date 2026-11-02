import { useEffect, useRef, type ReactNode } from 'react';
import { Link, useLocation } from 'react-router-dom';
import './site-layout.css';

function pageTitle(path: string): string {
  const pathname = path.replace(/\/+$/, '') || '/';
  const titles: Record<string, string> = {
    '/': 'Проверка контейнерных образов',
    '/login': 'Вход',
    '/register': 'Регистрация',
    '/account': 'Аккаунт',
    '/scans': 'Мои проверки',
    '/scans/new': 'Новая проверка',
    '/demo/scans': 'Демонстрация проверок',
    '/demo/scans/new': 'Демонстрация создания проверки',
  };
  if (titles[pathname]) return titles[pathname];
  if (/^\/demo\/scans\/[^/]+$/.test(pathname)) return 'Демонстрационный отчёт';
  if (/^\/scans\/[^/]+$/.test(pathname)) return 'Отчёт по образу';
  return 'Страница не найдена';
}

export function SiteLayout({ children }: { children: ReactNode }) {
  const { pathname } = useLocation();
  const content = useRef<HTMLDivElement>(null);
  const previousPath = useRef(pathname);
  const title = pageTitle(pathname);

  useEffect(() => {
    document.title = `${title} — OCI / VISION`;
    // Route changes only: loading, session checks, query filters and streamed results must not steal focus.
    if (previousPath.current !== pathname) content.current?.focus();
    previousPath.current = pathname;
  }, [pathname, title]);

  return (
    <>
      <a
        className="site-skip-link"
        href="#site-content"
        onClick={(event) => {
          event.preventDefault();
          const target =
            content.current?.querySelector<HTMLElement>(
              '[data-page-focus], main h1:not(.sr-only), main h2',
            ) ?? content.current;
          if (!target) return;
          if (!target.hasAttribute('tabindex')) target.setAttribute('tabindex', '-1');
          target.focus();
        }}
      >
        Перейти к содержимому
      </a>
      <div
        id="site-content"
        ref={content}
        tabIndex={-1}
        role="region"
        aria-label={title}
        className="site-content"
      >
        {children}
      </div>
      <footer className="site-footer">
        <div>
          <strong>OCI / VISION</strong>
          <p>
            Проверка публичных образов Docker Hub. Отчёт помогает разобраться в находках, но не гарантирует
            безопасность.
          </p>
        </div>
        <nav aria-label="Навигация внизу страницы">
          <Link to="/">Главная</Link>
          <Link to="/scans">Мои проверки</Link>
          <Link to="/demo/scans">Демо без входа</Link>
          <Link to="/account">Аккаунт</Link>
        </nav>
        <p>Демо содержит вымышленные данные. Реальные проверки требуют входа и разрешения сервера.</p>
      </footer>
    </>
  );
}
