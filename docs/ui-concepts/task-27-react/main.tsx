import { useRef, useState } from 'react';
import { createRoot } from 'react-dom/client';
import * as Tabs from '@radix-ui/react-tabs';
import * as Accordion from '@radix-ui/react-accordion';
import { motion, useReducedMotion, useScroll, useSpring, useTransform } from 'motion/react';
import { ArrowRight, ArrowLeft, ArrowUpRight, ChevronDown, Sparkles, ScanLine } from 'lucide-react';
import { BlurFade } from './blur-fade';
import './style.css';
import './variants.css';

type Screen = 'list' | 'create' | 'detail' | 'live';
const concepts = [
  {
    key: 'a1',
    name: 'A1 / Сигнал',
    description:
      'Графитовый редакционный маршрут. Скролл раскрывает главы, акцентная лента связывает действия.',
  },
  {
    key: 'a2',
    name: 'A2 / Атлас',
    description: 'Светлая полоса-выставка. Номерные дорожки, подвижная типографика и панели состояния.',
  },
  {
    key: 'a3',
    name: 'A3 / Пульс',
    description: 'Тёмная сцена с неоновыми контурами. Линия скролла и мягкие пространственные переходы.',
  },
] as const;
type Concept = (typeof concepts)[number]['key'];
const screens: { key: Screen; title: string }[] = [
  { key: 'list', title: '01 Список' },
  { key: 'create', title: '02 Создать' },
  { key: 'detail', title: '03 Деталь' },
  { key: 'live', title: '04 Реальный режим' },
];

export function App() {
  const [concept, setConcept] = useState<Concept>('a1');
  const [screen, setScreen] = useState<Screen>('list');
  const [scope, setScope] = useState('full');
  const [consent, setConsent] = useState(false);
  const [filter, setFilter] = useState('all');
  const reduced = useReducedMotion();
  const page = useRef<HTMLDivElement>(null);
  const hasNavigated = useRef(false);
  const { scrollYProgress } = useScroll({ target: page, offset: ['start start', 'end end'] });
  const progress = useSpring(scrollYProgress, { stiffness: 100, damping: 28 });
  const drift = useTransform(progress, [0, 1], [0, 105]);
  const navigate = (next: Screen) => {
    if (screen === next) return;
    hasNavigated.current = true;
    setScreen(next);
    window.scrollTo({ top: 0, behavior: 'instant' });
  };
  return (
    <div className={`prototype ${concept}`} ref={page}>
      <motion.div className="scroll-meter" aria-hidden="true" style={{ scaleX: reduced ? 1 : progress }} />
      <header className="topbar">
        <a className="brand" href="/" aria-label="OCI Vision — на главную">
          <ScanLine size={24} aria-hidden="true" /> OCI<span>/</span>VISION
        </a>
        <span className="topbar-label">DIP-TASK-27 / ИЗОЛИРОВАННЫЕ КОНЦЕПТЫ</span>
        <a href="/demo/scans">
          Текущее демо <ArrowUpRight size={15} aria-hidden="true" />
        </a>
      </header>
      <main id="main">
        <div className="notice" role="note">
          <strong>ДЕМО · ВЫМЫШЛЕННЫЕ ДАННЫЕ.</strong> Это дизайн-прототип, не рабочий запуск, сканирование или
          ИИ. Лендинг и продуктовые страницы не изменены.
        </div>
        <section className="intro" aria-labelledby="title">
          <div className="intro-copy">
            <p className="eyebrow">РЕДАКЦИОННЫЙ МАРШРУТ / ТРИ РИТМА</p>
            <h1 id="title">
              СМОТРИ <em>ГЛУБЖЕ.</em>
            </h1>
            <p>
              От списка к новому скану и отчёту — один непрерывный сюжет. Выберите композицию и пройдите все
              четыре экрана.
            </p>
          </div>
          <motion.div className="intro-mark" aria-hidden="true" style={reduced ? undefined : { y: drift }}>
            <span>03</span>
            <span>FRAMES / ONE STORY</span>
          </motion.div>
        </section>
        <Tabs.Root
          className="concept-tabs"
          value={concept}
          onValueChange={(value) => setConcept(value as Concept)}
        >
          <Tabs.List className="concept-list" aria-label="Выбор дизайн-концепта">
            {concepts.map((item) => (
              <Tabs.Trigger key={item.key} value={item.key}>
                {item.name}
              </Tabs.Trigger>
            ))}
          </Tabs.List>
          {concepts.map((item) => (
            <Tabs.Content key={item.key} value={item.key} className="concept-description">
              {item.description}
            </Tabs.Content>
          ))}
        </Tabs.Root>
        <nav className="screen-nav" aria-label="Экраны прототипа">
          {screens.map(({ key, title }) => (
            <button
              key={key}
              type="button"
              aria-current={screen === key ? 'page' : undefined}
              onClick={() => navigate(key)}
            >
              {title}
            </button>
          ))}
        </nav>
        <motion.div
          key={screen}
          ref={(node) => {
            if (node && hasNavigated.current) node.focus({ preventScroll: true });
          }}
          tabIndex={-1}
          role="region"
          aria-label={screens.find((item) => item.key === screen)?.title}
          className="screen"
          initial={reduced ? false : { opacity: 0, y: 16 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ duration: reduced ? 0 : 0.32 }}
        >
          {screen === 'list' && (
            <>
              <div className="chapter-head">
                <span>ГЛАВА 01 / КАТАЛОГ</span>
                <span>ЗАПИСИ ИЗ ФИКСТУР</span>
              </div>
              <div className="list-lead">
                <h2>
                  Каждая проверка —<br />
                  <i>история с границами.</i>
                </h2>
                <button className="primary" onClick={() => navigate('create')}>
                  + Новый скан <ArrowRight size={20} aria-hidden="true" />
                </button>
              </div>
              <div className="record-list">
                <BlurFade>
                  <article className="record">
                    <span className="record-index">01 / В ПРОЦЕССЕ</span>
                    <div>
                      <h3>registry.example/team/api:latest</h3>
                      <p>Этап: анализ слоёв · прогресс неизвестен (`percent=null`)</p>
                    </div>
                    <span className="pill">Running / фикстура</span>
                  </article>
                </BlurFade>
                <BlurFade delay={0.1}>
                  <article className="record featured">
                    <span className="record-index">02 / ЧАСТИЧНО</span>
                    <div>
                      <h3>registry.example/team/worker:v2</h3>
                      <p>Этап: формирование отчёта · есть непроверенные области</p>
                    </div>
                    <button className="text-link" onClick={() => navigate('detail')}>
                      Открыть деталь <ArrowUpRight size={17} aria-hidden="true" />
                    </button>
                  </article>
                </BlurFade>
                <BlurFade delay={0.15}>
                  <article className="record">
                    <span className="record-index">03 / ПРОВЕРЕНО</span>
                    <div>
                      <h3>registry.example/team/secrets:v1</h3>
                      <p>Secrets: проверено · 0 находок только в этой категории</p>
                    </div>
                    <span className="pill">Нет отдельной детали</span>
                  </article>
                </BlurFade>
              </div>
              <p className="footnote">
                Это вымышленные записи. Running не означает доступный live-поток. Кнопка создания ведёт к
                концепту формы и ничего не отправляет.
              </p>
            </>
          )}
          {screen === 'create' && (
            <>
              <div className="chapter-head">
                <span>ГЛАВА 02 / НОВАЯ ПРОВЕРКА</span>
                <button className="text-link" onClick={() => navigate('list')}>
                  <ArrowLeft size={16} /> К списку
                </button>
              </div>
              <div className="split">
                <div>
                  <h2>
                    Задайте <i>границы.</i>
                  </h2>
                  <p className="large-copy">
                    Форма показывает будущий путь, но browser ingress не настроен. Даже POST 202 не
                    подтверждает digest или platform.
                  </p>
                  <span className="big-number" aria-hidden="true">
                    02
                  </span>
                </div>
                <form className="form-panel" onSubmit={(e) => e.preventDefault()}>
                  <label htmlFor="image">Образ / imageReference</label>
                  <input id="image" placeholder="registry.example/team/api:tag" autoComplete="off" />
                  <fieldset>
                    <legend>Scope проверки</legend>
                    <label>
                      <input
                        type="radio"
                        name="scope"
                        checked={scope === 'full'}
                        onChange={() => setScope('full')}
                      />{' '}
                      Полная (при доступности)
                    </label>
                    <label>
                      <input
                        type="radio"
                        name="scope"
                        checked={scope === 'secrets'}
                        onChange={() => setScope('secrets')}
                      />{' '}
                      Только Secrets
                    </label>
                  </fieldset>
                  <label className="checkbox">
                    <input type="checkbox" checked={consent} onChange={(e) => setConsent(e.target.checked)} />{' '}
                    Подтверждаю право проверять этот образ
                  </label>
                  <button className="primary" disabled type="button">
                    Запуск недоступен
                  </button>
                  <button className="text-link" type="button" onClick={() => navigate('detail')}>
                    Посмотреть независимый образец отчёта <ArrowUpRight size={17} aria-hidden="true" />
                  </button>
                  <p>
                    Образец относится к другой готовой фикстуре, а не к введённому образу. В демо форма не
                    отправляет данные. Подтверждение здесь не предоставляет авторизованную сессию и не
                    включает кнопку.
                  </p>
                </form>
              </div>
            </>
          )}
          {screen === 'detail' && (
            <>
              <div className="chapter-head">
                <span>ГЛАВА 03 / ОТЧЁТ</span>
                <button className="text-link" onClick={() => navigate('list')}>
                  <ArrowLeft size={16} /> К списку
                </button>
              </div>
              <div className="detail-title">
                <div>
                  <p className="eyebrow">PARTIAL / ФИКСТУРА · ЭТАП: ФОРМИРОВАНИЕ ОТЧЁТА</p>
                  <h2>
                    Не всё, что
                    <br />
                    <i>видно, проверено.</i>
                  </h2>
                  <p className="digest">registry.example/team/worker:v2 · digest/platform не подтверждены</p>
                </div>
                <div className="summary-badge">
                  PARTIAL <small>прогресс неизвестен</small>
                </div>
              </div>
              <div className="detail-grid">
                <section className="coverage" aria-labelledby="coverage-title">
                  <h3 id="coverage-title">01 / Покрытие</h3>
                  <p>Результат каждой проверки не равен состоянию скана.</p>
                  <div className="coverage-row">
                    <strong>Secrets</strong>
                    <span>Проверено · 0 находок в этой категории</span>
                  </div>
                  <div className="coverage-row">
                    <strong>CVE</strong>
                    <span>Сбой · не проверено: база уязвимостей недоступна</span>
                  </div>
                  <div className="coverage-row">
                    <strong>Конфигурация</strong>
                    <span>Не поддерживается: анализ конфигурации не выполнялся</span>
                  </div>
                  <Accordion.Root type="single" collapsible className="explanation">
                    <Accordion.Item value="notes">
                      <Accordion.Header>
                        <Accordion.Trigger>
                          Что означает неполный отчёт? <ChevronDown size={17} aria-hidden="true" />
                        </Accordion.Trigger>
                      </Accordion.Header>
                      <Accordion.Content>
                        Нельзя считать непроверенные категории безопасными. Причины сбоев остаются видны выше
                        и без раскрытия этого пояснения.
                      </Accordion.Content>
                    </Accordion.Item>
                  </Accordion.Root>
                </section>
                <section className="findings" aria-labelledby="findings-title">
                  <h3 id="findings-title">02 / Находки</h3>
                  <label htmlFor="finding-filter">Фильтр категорий</label>
                  <select id="finding-filter" value={filter} onChange={(e) => setFilter(e.target.value)}>
                    <option value="all">Все</option>
                    <option value="cve">CVE</option>
                    <option value="secrets">Secrets</option>
                  </select>
                  {filter === 'all' ? (
                    <div className="finding-card">
                      <span>НЕПОЛНЫЙ РЕЗУЛЬТАТ</span>
                      <strong>CVE не оценены</strong>
                      <p>Сбой базы не означает 0 CVE. Secrets проверены отдельно: 0 находок.</p>
                    </div>
                  ) : (
                    <div className="finding-card">
                      <strong>Нет совпадений фильтра</strong>
                      <p>
                        {filter === 'cve'
                          ? 'CVE не проверены: результат неизвестен.'
                          : 'Secrets проверены: 0 находок в этой категории.'}
                      </p>
                      <button className="text-link" onClick={() => setFilter('all')}>
                        Сбросить фильтр
                      </button>
                    </div>
                  )}
                </section>
              </div>
              <section className="ai-panel" aria-labelledby="ai-title">
                <div>
                  <p className="eyebrow">03 / КОНТЕКСТНЫЙ ПОМОЩНИК · КОНЦЕПТ</p>
                  <h3 id="ai-title">
                    <Sparkles size={23} aria-hidden="true" /> Спросить об отчёте
                  </h3>
                  <p>
                    Будущий чат должен ссылаться на проверенные finding_id и показывать границы coverage.
                    Здесь нет модели, истории или авторизованной отправки.
                  </p>
                </div>
                <div className="ai-compose">
                  <label htmlFor="ai-prompt">Ваш вопрос</label>
                  <textarea id="ai-prompt" disabled placeholder="Почему CVE не проверены?" />
                  <button disabled>Чат недоступен в прототипе</button>
                  <span>Сообщения не сохраняются и не отправляются.</span>
                </div>
              </section>
            </>
          )}
          {screen === 'live' && (
            <>
              <div className="chapter-head">
                <span>ГЛАВА 04 / РЕАЛЬНЫЙ РЕЖИМ</span>
              </div>
              <div className="unavailable">
                <h2>
                  Данные <i>пока недоступны.</i>
                </h2>
                <p>
                  Для `/scans` нет защищённого browser ingress и GET-списка. Отсутствие ответа не означает,
                  что сканов нет. Демо можно посмотреть отдельно.
                </p>
                <button className="primary" onClick={() => navigate('list')}>
                  Смотреть фикстуры <ArrowRight size={18} />
                </button>
              </div>
            </>
          )}
        </motion.div>
        <footer className="footer">
          <span>OCI / VISION — ИЗОЛИРОВАННОЕ ДИЗАЙН-ИССЛЕДОВАНИЕ</span>
          <span>NO LIVE DATA / NO AI RESPONSES</span>
        </footer>
      </main>
    </div>
  );
}

createRoot(document.getElementById('root')!).render(<App />);
