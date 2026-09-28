import { useState } from 'react';
import { useForm, useWatch } from 'react-hook-form';
import { z } from 'zod';
import { zodResolver } from '@hookform/resolvers/zod';
import { ScanShell, controlClass } from '@/features/scans/ScanShell';
import { Alert, Badge, Button, Card } from '@/shared/ui/scan-primitives';

const formSchema = z.object({
  imageReference: z.string().trim().min(1, 'Укажите цель').max(256, 'Слишком длинная ссылка'),
});
type FormValues = z.infer<typeof formSchema>;
export function ScanCreatePage({ demo = false }: { demo?: boolean }) {
  const {
    register,
    control,
    formState: { errors },
  } = useForm<FormValues>({ resolver: zodResolver(formSchema), defaultValues: { imageReference: '' } });
  const imageReference = useWatch({ control, name: 'imageReference' });
  const [confirmed, setConfirmed] = useState(false);
  return (
    <ScanShell demo={demo}>
      <section className="min-w-0 space-y-5" aria-labelledby="new-scan">
        <div className="space-y-1">
          <p className="text-xs font-bold uppercase tracking-widest text-indigo-800">
            Подготовка / цель и scope
          </p>
          <h2 id="new-scan" className="text-2xl font-semibold tracking-tight sm:text-3xl">
            Новый скан
          </h2>
          <p className="text-sm text-slate-600">
            Сначала проверьте цель и доступную область. Запуск пока отключён.
          </p>
        </div>
        <div className="grid min-w-0 items-start gap-5 lg:grid-cols-[minmax(0,1.5fr)_minmax(0,1fr)]">
          <Card className="min-w-0 space-y-6 p-5 sm:p-7">
            <div className="flex flex-wrap items-center justify-between gap-2">
              <h3 className="text-lg font-semibold">Параметры проверки</h3>
              <Badge tone="warning">Запуск недоступен</Badge>
            </div>
            <label className="block space-y-2 font-medium">
              Образ в registry (только разрешённый Alpine)
              <input
                {...register('imageReference')}
                className={`${controlClass} w-full min-w-0 font-normal`}
                placeholder="registry-1.docker.io/library/alpine:3.21"
                aria-invalid={!!errors.imageReference}
                aria-describedby={errors.imageReference ? 'image-reference-error' : undefined}
              />
            </label>
            {errors.imageReference ? (
              <p id="image-reference-error" role="alert" className="text-sm text-red-800">
                {errors.imageReference.message}
              </p>
            ) : null}
            <fieldset className="space-y-3 border-t border-slate-200 pt-5">
              <legend className="font-semibold">Доступные проверки и область</legend>
              <label className="flex min-w-0 items-start gap-3 text-sm leading-relaxed">
                <input className="mt-1 size-5 shrink-0 accent-indigo-700" type="checkbox" checked readOnly />{' '}
                Secrets · image (внутренний API)
              </label>
              <label className="flex min-w-0 items-start gap-3 text-sm leading-relaxed text-slate-600">
                <input className="mt-1 size-5 shrink-0" type="checkbox" disabled /> CVE и SBOM · пока
                недоступны
              </label>
              <label className="flex min-w-0 items-start gap-3 text-sm leading-relaxed text-slate-600">
                <input className="mt-1 size-5 shrink-0" type="checkbox" disabled /> Container / host ·
                требуется отдельное разрешение и backend
              </label>
            </fieldset>
            <div className="space-y-4 border-t border-slate-200 pt-5">
              <label className="flex min-w-0 items-start gap-3 break-words text-sm leading-relaxed">
                <input
                  className="mt-1 size-5 shrink-0 accent-indigo-700"
                  type="checkbox"
                  checked={confirmed}
                  onChange={(event) => setConfirmed(event.target.checked)}
                />
                <span>
                  Подтверждаю выбранную цель и область:{' '}
                  <strong className="font-semibold [overflow-wrap:anywhere]">
                    {imageReference || 'цель не указана'}
                  </strong>
                </span>
              </label>
              <Button
                className="w-full sm:w-auto"
                type="button"
                disabled
                title="Нет защищённого browser ingress и авторизованной сессии"
              >
                Запуск недоступен
              </Button>
              <p className="text-sm leading-relaxed text-slate-600">
                {confirmed
                  ? 'Цель подтверждена, но сервер недоступен из браузера.'
                  : 'До запуска подтвердите цель и scope.'}{' '}
                Даже после квитанции POST digest/platform остаются неподтверждёнными до авторизованного GET
                status.
              </p>
            </div>
          </Card>
          <Card className="min-w-0 space-y-5 p-5 sm:p-7">
            <div className="space-y-2">
              <p className="text-xs font-bold uppercase tracking-widest text-indigo-800">Границы доверия</p>
              <h3 className="text-lg font-semibold">Что будет подтверждено?</h3>
            </div>
            <ul className="space-y-4 text-sm leading-relaxed text-slate-700">
              <li className="border-l-2 border-indigo-300 pl-3">
                <strong className="block text-slate-900">Цель и область</strong>Только разрешённый образ
                Alpine и проверка secrets внутри image.
              </li>
              <li className="border-l-2 border-amber-400 pl-3">
                <strong className="block text-slate-900">Не проверяется</strong>CVE, SBOM и container / host
                не входят в доступный scope.
              </li>
              <li className="border-l-2 border-slate-300 pl-3">
                <strong className="block text-slate-900">Результат</strong>POST 202 — квитанция, не
                подтверждение закреплённого digest/platform.
              </li>
            </ul>
            <Alert className="text-sm leading-relaxed">
              Без защищённой авторизованной сессии запуск из браузера невозможен.{' '}
              {demo
                ? 'Демо показывает только вымышленные результаты.'
                : 'Доступ к реальному API не настроен.'}
            </Alert>
          </Card>
        </div>
      </section>
    </ScanShell>
  );
}
