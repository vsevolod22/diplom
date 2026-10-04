import { useRef, useState } from 'react';
import { ArrowLeft, LockKeyhole } from 'lucide-react';
import { Link, useNavigate } from 'react-router-dom';
import { useLiveScanSession } from '@/features/scans/liveScanContext';
import { useForm, useWatch } from 'react-hook-form';
import { z } from 'zod';
import { zodResolver } from '@hookform/resolvers/zod';
import { GuideTabs, GuideTabsContent, GuideTabsList, GuideTabsTrigger } from '@/features/scans/GuideTabs';
import { ScanShell } from '@/features/scans/ScanShell';
import { ScanScene } from '@/features/scans/ScanScene';
import { ScanAccessError, ScanHttpError } from '@/shared/api/scans/httpScanTransport';
import { scanChecks } from '@/shared/api/scans/scanTransport';

const alpineTargets = [
  { label: 'Alpine · latest', reference: 'registry-1.docker.io/library/alpine:latest' },
  { label: 'Alpine · 3.21', reference: 'registry-1.docker.io/library/alpine:3.21' },
  { label: 'Alpine · 3.20', reference: 'registry-1.docker.io/library/alpine:3.20' },
  { label: 'Alpine · 3.16 (архивный · CVE-пример)', reference: 'registry-1.docker.io/library/alpine@sha256:0db9d004361b106932f8c7632ae54d56e92c18281e2dd203127d77405020abf6' },
] as const;
const formSchema = z.object({
  imageReference: z.string().refine(value => alpineTargets.some(target => target.reference === value), 'Выберите образ из доступного каталога'),
  checks: z.array(z.enum(scanChecks)).min(1, 'Выберите хотя бы одну проверку'),
});
type FormValues = z.infer<typeof formSchema>;
export function ScanCreatePage({ demo = false }: { demo?: boolean }) {
  const {
    register,
    control,
    setValue,
    handleSubmit,
    formState: { errors },
  } = useForm<FormValues>({
    resolver: zodResolver(formSchema),
    defaultValues: { imageReference: '', checks: ['secret'] },
  });
  const imageReference = useWatch({ control, name: 'imageReference' });
  const checks = useWatch({ control, name: 'checks' }) ?? [];
  const [search, setSearch] = useState('');
  const [confirmed, setConfirmed] = useState(false);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState('');
  const attempt = useRef<{ target: string; checks: string; key: string } | null>(null);
  const live = useLiveScanSession();
  const navigate = useNavigate();
  async function create(values: FormValues) {
    if (demo || !live || !confirmed || busy) return;
    setBusy(true);
    setError('');
    try {
      const selected = scanChecks.filter(check => values.checks.includes(check));
      if (attempt.current?.target !== values.imageReference || attempt.current?.checks !== selected.join(',')) {
        attempt.current = { target: values.imageReference, checks: selected.join(','), key: crypto.randomUUID() };
      }
      const receipt = await live.transport.create({ imageReference: values.imageReference, scope: 'image', checks: selected, idempotencyKey: attempt.current.key });
      navigate(`/scans/${encodeURIComponent(receipt.scanId)}`);
    } catch (reason) {
      if (reason instanceof ScanAccessError) {
        setError(reason.status === 403 ? 'Аккаунту не выдан доступ к сканированию. Проверьте разрешение на странице аккаунта.' : 'Сессия недействительна. Войдите заново.');
      } else if (reason instanceof ScanHttpError && reason.status === 400) {
        setError('Сервер отклонил цель или параметры сканирования. Скан не создан.');
      } else if (reason instanceof ScanHttpError && reason.status === 429) {
        setError('Лимит запусков исчерпан. Скан не создан, повторите позже.');
      } else if (reason instanceof ScanHttpError && reason.status === 503) {
        setError(values.checks.includes('vuln') ? 'Проверка CVE недоступна: база уязвимостей не настроена или недоступна. Запуск не подтверждён; обратитесь к администратору и проверьте список перед повтором.' : 'Сканер или registry сейчас недоступны. Запуск не подтверждён; проверьте список перед повтором.');
      } else if (reason instanceof ScanHttpError && reason.code === 'IDEMPOTENCY_CONFLICT') {
        setError('Параметры повторного запуска изменились. Обновите страницу перед новой попыткой.');
      } else {
        setError('Не удалось подтвердить запуск. Проверьте список перед повтором: результат запроса неизвестен.');
      }
    } finally {
      setBusy(false);
    }
  }
  return (
    <ScanShell demo={demo}>
      <section className="min-w-0 space-y-8 pb-8" aria-labelledby="new-scan">
        <div className="scan-a1__chapter">
          <span>ГЛАВА 02 / НОВАЯ ПРОВЕРКА</span>
          <Link className="scan-a1__link" to={demo ? '/demo/scans' : '/scans'}>
            <ArrowLeft size={16} aria-hidden="true" /> К списку
          </Link>
        </div>
        <div className="scan-a1__create-hero">
          <div className="min-w-0">
            <span className="scan-a1__folio">СИГНАЛ / 02 — ГРАНИЦА ДОВЕРИЯ</span>
            <h2 id="new-scan" className="scan-a1__heading">
              Задайте <em>границы.</em>
            </h2>
            <p className="scan-a1__muted mt-6 max-w-xl text-lg">
              Найдите и выберите образ Alpine из доступных целей. Запуск требует действующей сессии и разрешения сервера.
            </p>
          </div>
          <ScanScene variant="create" />
        </div>

        <div className="scan-a1__form-grid scan-a1__form-grid--story">
          <form className="scan-a1__form" aria-label="Параметры скана" onSubmit={handleSubmit(create)}>
            <div>
              <input type="hidden" {...register('imageReference')} />
              <label htmlFor="image-search">Поиск по доступным образам</label>
              <input
                id="image-search"
                type="search"
                value={search}
                onChange={event => setSearch(event.target.value)}
                placeholder="Alpine, 3.21, latest"
                autoComplete="off"
              />
              <div className="scan-a1__targets" role="group" aria-label="Выбор образа" aria-describedby={errors.imageReference ? 'image-reference-error' : undefined}>
                {alpineTargets.filter(target => `${target.label} ${target.reference}`.toLowerCase().includes(search.trim().toLowerCase())).map(target => (
                  <button
                    key={target.reference}
                    type="button"
                    className="scan-a1__target"
                    aria-pressed={imageReference === target.reference}
                    onClick={() => {
                      setValue('imageReference', target.reference, { shouldValidate: true });
                      setConfirmed(false);
                      setError('');
                    }}
                  >
                    <strong>{target.label}</strong>
                    <span>{target.reference}</span>
                  </button>
                ))}
                {!alpineTargets.some(target => `${target.label} ${target.reference}`.toLowerCase().includes(search.trim().toLowerCase())) ? (
                  <p>Ничего не найдено. Сейчас поддерживается только Alpine из Docker Hub.</p>
                ) : null}
              </div>
              {imageReference === alpineTargets[3].reference ? <p className="scan-a1__muted">Архивный образ: при проверке закреплённого digest 04.10.2026 локальная DB нашла 4 CVE. Результат нового запуска зависит от актуальной DB и доступности scanner; этот образ не используйте для рабочих нагрузок.</p> : null}
              {errors.imageReference ? <p id="image-reference-error" role="alert">{errors.imageReference.message}</p> : null}
            </div>
            <fieldset>
              <legend>Проверки · одновременно, область registry IMAGE</legend>
              <label>
                <input type="checkbox" value="secret" {...register('checks', { onChange: () => { setConfirmed(false); setError(''); } })} />
                Secrets · проверка образа
              </label>
              <label>
                <input type="checkbox" value="sbom" {...register('checks', { onChange: () => { setConfirmed(false); setError(''); } })} />
                SBOM · перечень пакетов, не проверка уязвимостей
              </label>
              <label>
                <input type="checkbox" value="vuln" {...register('checks', { onChange: () => { setConfirmed(false); setError(''); } })} />
                CVE · доступно только при настроенной сервером базе уязвимостей
              </label>
              <label>
                <input type="checkbox" disabled />
                Host / running container · не поддерживаются (только registry IMAGE)
              </label>
              {errors.checks ? <p role="alert">{errors.checks.message}</p> : null}
            </fieldset>
            <label>
              <input
                type="checkbox"
                checked={confirmed}
                onChange={(event) => setConfirmed(event.target.checked)}
              />
              <span>
                Подтверждаю выбранную цель и область:{' '}
                <strong className="[overflow-wrap:anywhere]">{imageReference || 'цель не указана'} · {scanChecks.filter(item => checks.includes(item)).join(', ') || 'проверки не выбраны'}</strong>
              </span>
            </label>
            <button
              className="scan-a1__disabled"
              type="submit"
              disabled={demo || !live || !confirmed || !checks.length || busy}
              title={demo ? 'Демо не запускает реальные сканы' : undefined}
            >
              <LockKeyhole size={17} className="mr-2 inline" aria-hidden="true" />
              {demo || !live ? 'Запуск недоступен' : busy ? 'Запускаем…' : 'Запустить скан'}
            </button>
            {error ? <p role="alert">{error}</p> : null}
            <p className="text-sm">
              {confirmed
                ? demo ? 'Демо не отправляет запросы.' : 'Цель подтверждена; разрешение проверяет сервер.'
                : 'До запуска подтвердите цель и scope.'}{' '}
              Даже после квитанции POST digest/platform остаются неподтверждёнными до авторизованного GET
              status.
            </p>
            {demo ? (
              <Link className="scan-a1__link" to="/demo/scans/partial-demo">
                Посмотреть отдельный образец отчёта · другая фикстура
              </Link>
            ) : null}
          </form>
          <aside className="scan-a1__trust-note">
            <span className="scan-a1__folio">ГРАНИЦА / 01—03</span>
            <strong>Область доверия</strong>
            <p>
              Один запрос запускает выбранные Secrets, SBOM и CVE для registry IMAGE. SBOM — инвентарь, не оценка CVE. CVE требует настроенной сервером базы; host и running container не поддерживаются.
            </p>
            <p>POST 202 — квитанция, не подтверждение закреплённого digest/platform.</p>
            <GuideTabs defaultValue="target" className="scan-a1__guide">
              <GuideTabsList aria-label="Памятка о подготовке скана">
                <GuideTabsTrigger value="target">01 / Цель</GuideTabsTrigger>
                <GuideTabsTrigger value="limits">02 / Границы</GuideTabsTrigger>
              </GuideTabsList>
              <GuideTabsContent value="target">
                <span className="scan-a1__guide-kicker">ПЕРЕД ПРОВЕРКОЙ</span>
                <h3>Начните с точного адреса.</h3>
                <p>
                  Выберите Alpine из доступных тегов и подтвердите область. Другие репозитории сервер сейчас
                  не принимает. Tag сам по себе не доказывает digest.
                </p>
              </GuideTabsContent>
              <GuideTabsContent value="limits">
                <span className="scan-a1__guide-kicker">ПОСЛЕ КВИТАНЦИИ</span>
                <h3>Доверяйте только статусу.</h3>
                <p>
                  Закреплённые digest/platform подтверждает авторизованный GET status. Демо показывает только
                  вымышленные записи; live-статус возвращает сервер.
                </p>
              </GuideTabsContent>
            </GuideTabs>
          </aside>
        </div>
        <div className="scan-a1__trust-path" aria-label="Этапы настройки">
          <div>
            <span>01 / ЦЕЛЬ</span>
            <p>Выберите образ из каталога.</p>
          </div>
          <div>
            <span>02 / ОБЛАСТЬ</span>
            <p>Проверьте доступные категории.</p>
          </div>
          <div>
            <span>03 / РАЗРЕШЕНИЕ</span>
            <p>Подтвердите цель. Доступ проверяет сервер.</p>
          </div>
        </div>
      </section>
    </ScanShell>
  );
}
