import { Component, type ReactNode } from 'react';
import { Link } from 'react-router-dom';

export class RouteErrorBoundary extends Component<{ children: ReactNode }, { failed: boolean }> {
  state = { failed: false };

  static getDerivedStateFromError() {
    return { failed: true };
  }

  render() {
    if (!this.state.failed) return this.props.children;
    // No raw exception, automatic reload or mutation replay. React.lazy rejects through this boundary too.
    return (
      <main className="route-message" aria-labelledby="route-error-title">
        <h1 id="route-error-title">Не удалось открыть страницу</h1>
        <p role="alert">
          Интерфейс не загрузился или столкнулся с ошибкой. Это не означает, что запущенная проверка
          остановилась.
        </p>
        <p>
          Если вы уже отправили запрос, сначала проверьте список. Не запускайте ту же проверку заново, пока её
          результат неизвестен.
        </p>
        <nav aria-label="Действия при ошибке страницы">
          <Link to="/scans">Проверить список</Link>
          <Link to="/">На главную</Link>
          <button type="button" onClick={() => window.location.reload()}>
            Обновить страницу
          </button>
        </nav>
      </main>
    );
  }
}
