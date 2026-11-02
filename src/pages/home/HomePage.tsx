import {
  ArrowDownRight,
  ArrowRight,
  ArrowUpRight,
  Box,
  Fingerprint,
  Layers3,
  ScanLine,
  ShieldAlert,
  Sparkles,
} from 'lucide-react';
import * as Tabs from '@radix-ui/react-tabs';
import { useRef } from 'react';
import { motion, useInView, useReducedMotion } from 'motion/react';
import { Link } from 'react-router-dom';
import './HomePage.css';

const reveal = { opacity: 0, y: 28 };

const exploreTabs = [
  {
    value: 'image',
    label: 'Образ',
    number: '01',
    title: 'Выберите образ и версию.',
    description:
      'Найдите публичный репозиторий Docker Hub, выберите тег или введите адрес вручную. Перед запуском сервис проверит доступность выбранной цели.',
    illustration: ['BASE', 'RUNTIME', 'APP'],
    caption: 'Схема слоёв · вымышленный пример',
  },
  {
    value: 'secrets',
    label: 'Секреты',
    number: '02',
    title: 'Секретам не место в образе.',
    description:
      'Проверка ищет возможные ключи и пароли в файлах образа. Находку нужно подтвердить: совпадение не доказывает, что ключ действителен. Если секрет настоящий, отзовите его и удалите из сборки.',
    illustration: ['CONFIG', 'TOKEN?', 'REVIEW'],
    caption: 'Схема проверки · не результат анализа',
  },
  {
    value: 'coverage',
    label: 'Покрытие',
    number: '03',
    title: 'Знай границы видимости.',
    description:
      'Отчёт отдельно показывает выполненные проверки, находки и пробелы. Неполный анализ или отсутствие находок не означает, что образ безопасен. Список пакетов сам по себе не является проверкой уязвимостей.',
    illustration: ['LAYERS', 'PACKAGES', 'GAPS'],
    caption: 'Карта видимости · не SBOM и не скан',
  },
] as const;

export function HomePage() {
  const reducedMotion = useReducedMotion();
  const tickerRef = useRef<HTMLDivElement>(null);
  const outroRef = useRef<HTMLElement>(null);
  const tickerVisible = useInView(tickerRef);
  const outroVisible = useInView(outroRef);

  return (
    <main className="home">
      <div className="home__noise" aria-hidden="true" />
      <div className="home__orb home__orb--one" aria-hidden="true" />
      <div className="home__orb home__orb--two" aria-hidden="true" />

      <div className="home__container">
        <header className="home__header">
          <Link to="/" className="home__brand" aria-label="OCI / VISION — на главную">
            <span className="home__brand-mark" aria-hidden="true">
              <ScanLine size={23} strokeWidth={2.5} />
            </span>
            <span>
              OCI<span className="home__brand-slash">/</span>VISION
            </span>
          </Link>
          <nav className="home__nav" aria-label="Основная навигация">
            <a href="#approach" className="home__nav-about">
              Как начать
            </a>
            <Link to="/scans">
              Мои проверки <ArrowUpRight size={16} aria-hidden="true" />
            </Link>
            <Link to="/account">Аккаунт</Link>
          </nav>
        </header>

        <section className="home__hero" aria-labelledby="home-title">
          <div className="home__hero-copy">
            <motion.div
              className="home__eyebrow"
              initial={reducedMotion ? false : reveal}
              animate={{ opacity: 1, y: 0 }}
              transition={{ duration: 0.6 }}
            >
              <span className="home__eyebrow-icon" aria-hidden="true">
                <Sparkles size={15} />
              </span>
              ДИПЛОМНЫЙ ПРОЕКТ{' '}
              <span className="home__eyebrow-divider" aria-hidden="true">
                /
              </span>{' '}
              OCI IMAGE SECURITY
            </motion.div>

            <motion.h1
              id="home-title"
              className="home__title"
              initial={reducedMotion ? false : reveal}
              animate={{ opacity: 1, y: 0 }}
              transition={{ duration: 0.7, delay: 0.08 }}
            >
              <span className="home__title-line">ОБРАЗ</span>
              <span className="home__title-line home__title-second">
                <span className="home__title-outline">НЕ</span>{' '}
                <span className="home__title-acid">ЗНАЧИТ</span>
              </span>
              <span className="home__title-line">БЕЗОПАСНО.</span>
            </motion.h1>

            <motion.div
              className="home__hero-bottom"
              initial={reducedMotion ? false : reveal}
              animate={{ opacity: 1, y: 0 }}
              transition={{ duration: 0.7, delay: 0.2 }}
            >
              <p className="home__lead">
                Проверьте публичный образ Docker Hub: известные уязвимости, возможные секреты, состав пакетов
                и настройки. Получите находки и понятные следующие шаги.
              </p>
              <div className="home__actions">
                <Link className="home__button home__button--primary" to="/scans/new">
                  Проверить образ <ArrowUpRight size={19} aria-hidden="true" />
                </Link>
                <Link className="home__button home__button--outline" to="/demo/scans/partial-demo">
                  Пример отчёта <ArrowRight size={19} aria-hidden="true" />
                </Link>
              </div>
              <p className="home__hero-disclaimer">
                <span aria-hidden="true">✳</span> Для реальной проверки нужны <Link to="/login">вход</Link> и
                разрешение сервера. <Link to="/register">Создать аккаунт</Link>. Демо доступно без входа и
                содержит вымышленные данные.
              </p>
            </motion.div>
          </div>

          <motion.div
            className="home__visual"
            initial={reducedMotion ? false : { opacity: 0, y: 40, rotate: 2 }}
            animate={{ opacity: 1, y: 0, rotate: 0 }}
            transition={{ duration: 0.85, delay: 0.24 }}
          >
            <div className="home__visual-halo" aria-hidden="true" />
            <div className="home__orbit home__orbit--outer" aria-hidden="true" />
            <div className="home__orbit home__orbit--inner" aria-hidden="true" />
            <div className="home__float-tag home__float-tag--top" aria-hidden="true">
              <span>01 / INSPECT</span>
              <ArrowDownRight size={17} />
            </div>
            <div className="home__preview">
              <div className="home__preview-top">
                <div className="home__preview-dots" aria-hidden="true">
                  <i />
                  <i />
                  <i />
                </div>
                <span>IMAGE / EXPLORER</span>
                <span className="home__preview-cross" aria-hidden="true">
                  ✳
                </span>
              </div>
              <div className="home__preview-body">
                <div className="home__preview-label">
                  <span className="home__label-spark" aria-hidden="true">
                    ✳
                  </span>{' '}
                  СХЕМА ИССЛЕДОВАНИЯ
                </div>
                <div className="home__preview-heading">
                  Что внутри
                  <br />
                  <em>образа?</em>
                </div>
                <p className="home__preview-note">Иллюстрация интерфейса · не результат сканирования</p>
                <ol
                  className="home__preview-stack"
                  aria-label="Этапы исследования: образ, слои, пакеты, находки"
                >
                  <li className="home__stack-row">
                    <span className="home__stack-number">01</span>
                    <Box size={19} aria-hidden="true" />
                    <span>Образ</span>
                    <span className="home__stack-end" aria-hidden="true">
                      ↗
                    </span>
                  </li>
                  <li className="home__stack-row">
                    <span className="home__stack-number">02</span>
                    <Layers3 size={19} aria-hidden="true" />
                    <span>Слои</span>
                    <span className="home__stack-end" aria-hidden="true">
                      ↗
                    </span>
                  </li>
                  <li className="home__stack-row">
                    <span className="home__stack-number">03</span>
                    <Fingerprint size={19} aria-hidden="true" />
                    <span>Пакеты</span>
                    <span className="home__stack-end" aria-hidden="true">
                      ↗
                    </span>
                  </li>
                  <li className="home__stack-row home__stack-row--accent">
                    <span className="home__stack-number">04</span>
                    <ShieldAlert size={19} aria-hidden="true" />
                    <span>Находки</span>
                    <span className="home__stack-end" aria-hidden="true">
                      ↗
                    </span>
                  </li>
                </ol>
              </div>
              <div className="home__preview-footer">
                <span>OCI / VISION</span>
                <span>КОНЦЕПТ · НЕ LIVE-ДАННЫЕ</span>
              </div>
            </div>
            <div className="home__float-tag home__float-tag--bottom" aria-hidden="true">
              <span className="home__float-pulse" /> LOOK CLOSER / 001
            </div>
          </motion.div>
          <a className="home__scroll" href="#approach">
            Листай ниже <ArrowDownRight size={17} aria-hidden="true" />
          </a>
        </section>
      </div>

      <div ref={tickerRef} className="home__ticker" data-visible={tickerVisible} aria-hidden="true">
        <div className="home__ticker-track">
          {Array.from({ length: 4 }, (_, index) => (
            <span key={index}>
              KNOW YOUR IMAGE <span>✳</span> QUESTION THE LAYERS <span>✳</span> SEE BEYOND THE TAG{' '}
              <span>✳</span>{' '}
            </span>
          ))}
        </div>
      </div>

      <section className="home__onboarding home__container" id="approach" aria-labelledby="onboarding-title">
        <p className="home__section-kicker">ОТ ОБРАЗА К СЛЕДУЮЩЕМУ ШАГУ</p>
        <h2 id="onboarding-title">Как начать проверку</h2>
        <ol>
          <li>
            <strong>1. Выберите образ</strong>
            <p>
              Найдите репозиторий и тег в Docker Hub или укажите адрес, например <code>nginx:1.24</code>.
            </p>
          </li>
          <li>
            <strong>2. Подтвердите проверки</strong>
            <p>Выберите нужные категории и подтвердите цель. Один выбор версии ещё ничего не запускает.</p>
          </li>
          <li>
            <strong>3. Разберите отчёт</strong>
            <p>
              Посмотрите, что найдено, почему это важно и что исправить. Обратите внимание на непроверенные
              части.
            </p>
          </li>
        </ol>
        <p className="home__onboarding-scope">
          Поддерживаются публичные образы Docker Hub для Linux (amd64), в пределах ограничений размера и
          формата. Приватные образы и другие реестры не поддерживаются. Не вводите пароли и токены.
        </p>
        <details>
          <summary>Что важно знать до запуска</summary>
          <p>
            Сканирование исследует образ, а не работающий контейнер или сервер. Наличие версии в каталоге не
            гарантирует, что сервис сможет её обработать.
          </p>
          <p>
            ИИ-объяснение — отдельное необязательное действие. Оно передаёт подготовленные данные внешнему
            провайдеру и может быть платным; условия и согласие показываются до запроса. Для чтения обычного
            отчёта ИИ не нужен.
          </p>
        </details>
      </section>

      <section className="home__section home__container" aria-labelledby="approach-title">
        <div className="home__section-heading">
          <div>
            <p className="home__section-kicker">/ 01 — ПОДХОД</p>
            <h2 id="approach-title">
              НЕ ДОВЕРЯЙ
              <br />
              <span>ОБЁРТКЕ.</span>
            </h2>
          </div>
          <p>Тег — это только имя. Важнее понять, из чего собран образ и что требует внимания внутри.</p>
        </div>
        <div className="home__features">
          <article className="home__feature home__feature--lime">
            <div className="home__feature-top">
              <span>01 / УЯЗВИМОСТИ</span>
              <Layers3 size={25} aria-hidden="true" />
            </div>
            <div className="home__feature-art home__feature-art--layers" aria-hidden="true">
              <span />
              <span />
              <span />
            </div>
            <div>
              <h3>
                Что требует
                <br />
                обновления.
              </h3>
              <p>
                Известные проблемы пакетов и исправленные версии, когда они указаны в источниках. Покрытие
                зависит от доступной базы.
              </p>
            </div>
          </article>
          <article className="home__feature home__feature--violet">
            <div className="home__feature-top">
              <span>02 / СОСТАВ</span>
              <Fingerprint size={25} aria-hidden="true" />
            </div>
            <div className="home__feature-art home__feature-art--rings" aria-hidden="true">
              <span />
              <span />
              <span />
              <i>✳</i>
            </div>
            <div>
              <h3>
                Состав имеет
                <br />
                значение.
              </h3>
              <p>Пакеты и установленные версии помогают понять состав сборки и спланировать обновление.</p>
            </div>
          </article>
          <article className="home__feature home__feature--dark">
            <div className="home__feature-top">
              <span>03 / КОНТЕКСТ</span>
              <ShieldAlert size={25} aria-hidden="true" />
            </div>
            <div className="home__feature-art home__feature-art--signal" aria-hidden="true">
              <span>!</span>
              <i />
              <i />
              <i />
            </div>
            <div>
              <h3>
                Риск, а не
                <br />
                догадка.
              </h3>
              <p>
                У каждой находки есть контекст. Возможный секрет требует проверки, а неполный результат —
                внимания, не оценки «всё безопасно».
              </p>
            </div>
          </article>
        </div>
      </section>

      <section className="home__explore home__container" aria-labelledby="explore-title">
        <div className="home__explore-intro">
          <p className="home__section-kicker">/ 02 — ИССЛЕДУЙ ГЛУБЖЕ</p>
          <h2 id="explore-title">ПОД ПОВЕРХНОСТЬЮ.</h2>
          <p>
            Короткая памятка: как выбрать цель, разобраться с секретами и не пропустить ограничения отчёта.
            Иллюстрации ниже — не результаты сканирования.
          </p>
        </div>
        <Tabs.Root className="home__explore-tabs" defaultValue="image" activationMode="automatic">
          <Tabs.List className="home__explore-list" aria-label="Ракурсы исследования образа">
            {exploreTabs.map((tab) => (
              <Tabs.Trigger className="home__explore-trigger" key={tab.value} value={tab.value}>
                <span aria-hidden="true">{tab.number} / </span>
                {tab.label}
              </Tabs.Trigger>
            ))}
          </Tabs.List>
          {exploreTabs.map((tab) => (
            <Tabs.Content className="home__explore-panel" key={tab.value} value={tab.value}>
              <div className="home__explore-copy">
                <p className="home__explore-overline">ПАМЯТКА / {tab.number}</p>
                <h3>{tab.title}</h3>
                <p>{tab.description}</p>
                <span className="home__explore-note">Схематичная иллюстрация · не результат проверки</span>
              </div>
              <div className={`home__explore-art home__explore-art--${tab.value}`}>
                <div className="home__explore-art-top" aria-hidden="true">
                  <span>OCI / VISION</span>
                  <span>✳ {tab.number}</span>
                </div>
                <motion.div
                  className="home__explore-diagram"
                  aria-hidden="true"
                  initial={reducedMotion ? false : { opacity: 0, y: 18, rotate: -3 }}
                  animate={{ opacity: 1, y: 0, rotate: 0 }}
                  transition={{ duration: 0.45, ease: 'easeOut' }}
                >
                  {tab.illustration.map((item, index) => (
                    <span className="home__explore-tile" key={item}>
                      <small>0{index + 1}</small>
                      {item}
                    </span>
                  ))}
                </motion.div>
                <p className="home__explore-caption">{tab.caption}</p>
              </div>
            </Tabs.Content>
          ))}
        </Tabs.Root>
      </section>

      <section
        ref={outroRef}
        className="home__outro"
        data-visible={outroVisible}
        aria-labelledby="outro-title"
      >
        <div className="home__container home__outro-inner">
          <div className="home__outro-sun" aria-hidden="true">
            ✳
          </div>
          <p className="home__section-kicker">/ 03 — НАЧНИ ИССЛЕДОВАНИЕ</p>
          <h2 id="outro-title">
            СМОТРИ
            <br />
            <em>ГЛУБЖЕ.</em>
          </h2>
          <p className="home__outro-copy">
            Выберите публичный образ и нужные проверки. Для реального запуска войдите в аккаунт; доступность
            подтвердит сервер. Хотите сначала понять результат? Откройте демонстрационный отчёт без входа.
          </p>
          <div className="home__actions home__actions--outro">
            <Link className="home__button home__button--primary" to="/scans/new">
              Проверить образ <ArrowUpRight size={19} aria-hidden="true" />
            </Link>
            <Link className="home__button home__button--outline" to="/demo/scans/partial-demo">
              Пример отчёта <ArrowRight size={19} aria-hidden="true" />
            </Link>
          </div>
          <p className="home__back-top">
            <a href="#home-title">Наверх ↑</a>
          </p>
        </div>
      </section>
    </main>
  );
}
