import { useState } from 'react';
import { ArrowLeft, LockKeyhole } from 'lucide-react';
import { Link } from 'react-router-dom';
import { useForm, useWatch } from 'react-hook-form';
import { z } from 'zod';
import { zodResolver } from '@hookform/resolvers/zod';
import { ScanShell } from '@/features/scans/ScanShell';

const formSchema = z.object({
  imageReference: z.string().trim().min(1, 'Укажите цель').max(256, 'Слишком длинная ссылка'),
});
type FormValues = z.infer<typeof formSchema>;
export function ScanCreatePage({ demo = false }: { demo?: boolean }) {
  const {
    register,
    control,
    formState: { errors },
  } = useForm<FormValues>({
    resolver: zodResolver(formSchema),
    defaultValues: { imageReference: '' },
  });
  const imageReference = useWatch({ control, name: 'imageReference' });
  const [confirmed, setConfirmed] = useState(false);
  return (
    <ScanShell demo={demo}>
      <section className="min-w-0 space-y-8 pb-8" aria-labelledby="new-scan">
        <div className="scan-a1__chapter">
          <span>ГЛАВА 02 / НОВАЯ ПРОВЕРКА</span>
          <Link className="scan-a1__link" to={demo ? '/demo/scans' : '/scans'}>
            <ArrowLeft size={16} aria-hidden="true" /> К списку
          </Link>
        </div>
        <div className="scan-a1__form-grid">
          <div className="min-w-0">
            <h2 id="new-scan" className="scan-a1__heading">
              Задайте <em>границы.</em>
            </h2>
            <p className="scan-a1__muted mt-6 max-w-xl text-lg">
              Укажите образ и подтвердите разрешённую область. Запуск из браузера пока не настроен —
              заполнение формы не отправляет запрос.
            </p>
            <div className="mt-10 border-l-4 border-[#d1ff5e] pl-5 text-sm leading-relaxed text-[#ded9e9]">
              <strong className="block text-lg text-white">Область доверия</strong>
              Secrets · image — внутренний сценарий разрабатывается и ожидает приёмки. CVE, SBOM и container /
              host не входят в доступный scope. POST 202 — квитанция, не подтверждение закреплённого
              digest/platform.
            </div>
          </div>
          <div className="scan-a1__form" role="group" aria-label="Параметры скана">
            <div>
              <label htmlFor="image-reference">Образ в registry (только разрешённый Alpine)</label>
              <input
                {...register('imageReference')}
                type="text"
                id="image-reference"
                className="mt-3"
                placeholder="registry-1.docker.io/library/alpine:3.21"
                aria-invalid={!!errors.imageReference}
                aria-describedby={errors.imageReference ? 'image-reference-error' : undefined}
              />
              {errors.imageReference ? (
                <p id="image-reference-error" role="alert">
                  {errors.imageReference.message}
                </p>
              ) : null}
            </div>
            <fieldset>
              <legend>Проектируемые проверки и область</legend>
              <p>
                <LockKeyhole size={18} className="mr-2 inline" aria-hidden="true" />
                Secrets · image (внутренний сценарий разрабатывается; запуск из браузера недоступен)
              </p>
              <label>
                <input type="checkbox" disabled />
                CVE и SBOM · пока недоступны
              </label>
              <label>
                <input type="checkbox" disabled />
                Container / host · требуется отдельное разрешение и backend
              </label>
            </fieldset>
            <label>
              <input
                type="checkbox"
                checked={confirmed}
                onChange={(event) => setConfirmed(event.target.checked)}
              />
              <span>
                Подтверждаю выбранную цель и область:{' '}
                <strong className="[overflow-wrap:anywhere]">{imageReference || 'цель не указана'}</strong>
              </span>
            </label>
            <button
              className="scan-a1__disabled"
              type="button"
              disabled
              title="Нет защищённого browser ingress и авторизованной сессии"
            >
              <LockKeyhole size={17} className="mr-2 inline" aria-hidden="true" />
              Запуск недоступен
            </button>
            <p className="text-sm">
              {confirmed
                ? 'Цель подтверждена, но сервер недоступен из браузера.'
                : 'До запуска подтвердите цель и scope.'}{' '}
              Даже после квитанции POST digest/platform остаются неподтверждёнными до авторизованного GET
              status.
            </p>
            {demo ? (
              <Link className="scan-a1__link" to="/demo/scans/partial-demo">
                Посмотреть отдельный образец отчёта · другая фикстура
              </Link>
            ) : null}
          </div>
        </div>
      </section>
    </ScanShell>
  );
}
