import { Link } from 'react-router-dom';

export function NotFoundPage() {
  return (
    <main className="route-message" aria-labelledby="not-found-title">
      <p>404 · страница не найдена</p>
      <h1 id="not-found-title">Здесь нет такой страницы</h1>
      <p>Проверьте адрес или выберите нужный раздел. Для главной и демо вход не требуется.</p>
      <nav aria-label="Куда перейти">
        <Link to="/">На главную</Link>
        <Link to="/scans">Мои проверки</Link>
        <Link to="/demo/scans">Посмотреть демо</Link>
      </nav>
    </main>
  );
}
