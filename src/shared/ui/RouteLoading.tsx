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
        <div className="route-loading__brand">
          OCI <span>/ VISION</span>
        </div>
        <div className="route-loading__body">
          <p className="route-loading__eyebrow">Проверка контейнерных образов</p>
          <div className="route-loading__status" role="status" aria-live="polite" aria-atomic="true">
            <span className="route-loading__indicator" aria-hidden="true" />
            <h1>{title}</h1>
          </div>
          <p className="route-loading__description">{description}</p>
          <div className="route-loading__skeleton" aria-hidden="true">
            <div className="route-loading__placeholder">
              <span className="route-loading__line route-loading__line--title" />
              <span className="route-loading__line" />
              <span className="route-loading__line route-loading__line--short" />
            </div>
            <div className="route-loading__placeholder">
              <span className="route-loading__line route-loading__line--title" />
              <span className="route-loading__line" />
              <span className="route-loading__line route-loading__line--short" />
            </div>
          </div>
        </div>
      </div>
    </main>
  );
}
