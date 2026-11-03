import './route-loading.css';

type RouteLoadingProps = {
  label?: string;
  title?: string;
  description?: string;
};

export function RouteLoading({
  label = 'Загрузка страницы',
  title = 'Загружаем страницу…',
  description = 'Содержимое появится, когда страница будет готова.',
}: RouteLoadingProps) {
  return (
    <main className="route-loading" aria-label={label}>
      <div className="route-loading__inner">
        <div className="route-loading__mark" aria-hidden="true">
          <svg viewBox="0 0 24 24" fill="none" focusable="false">
            <path d="M4 7V4h3m10 0h3v3M4 17v3h3m10 0h3v-3M4 12h16" />
          </svg>
        </div>
        <p className="route-loading__brand">
          OCI <span>/</span> VISION
        </p>
        <div className="route-loading__status" role="status" aria-live="polite" aria-atomic="true">
          <h1>{title}</h1>
          <p className="route-loading__description">{description}</p>
        </div>
        <div className="route-loading__activity" aria-hidden="true">
          <span />
          <span />
          <span />
        </div>
      </div>
    </main>
  );
}
