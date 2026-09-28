import { useState } from 'react';
import { ArrowDownRight, ArrowRight, LockKeyhole, ScanLine, ShieldCheck } from 'lucide-react';
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
      <section className="min-w-0 space-y-8 pb-8" aria-labelledby="new-scan">
        <div className="scan-experience-hero relative min-w-0 overflow-hidden rounded-[1.75rem] bg-[#17142a] px-5 py-7 text-white sm:px-9 sm:py-10 lg:px-12">
          <div
            aria-hidden="true"
            className="pointer-events-none absolute -right-12 -top-20 size-56 rounded-full border-[34px] border-[#c9ff54]/20 sm:size-72"
          />
          <div
            aria-hidden="true"
            className="pointer-events-none absolute bottom-0 right-0 h-24 w-1/2 bg-[linear-gradient(120deg,transparent,rgba(145,98,255,0.22))]"
          />
          <div className="relative flex min-w-0 flex-wrap items-start justify-between gap-6">
            <div className="min-w-0 flex-1">
              <p className="flex items-center gap-2 text-[11px] font-black uppercase tracking-[0.2em] text-[#c9ff54]">
                <ScanLine size={16} aria-hidden="true" /> Подготовка / цель и scope
              </p>
              <h2
                id="new-scan"
                className="mt-5 max-w-[12ch] text-[clamp(2.7rem,7vw,5.5rem)] font-black leading-[0.92] tracking-[-0.065em]"
              >
                Новый <span className="text-[#c9ff54]">скан</span>
              </h2>
              <p className="mt-6 max-w-xl text-sm leading-relaxed text-[#e1dff1] sm:text-base">
                Сначала проверьте цель и доступную область. Запуск пока отключён.
              </p>
            </div>
            <span
              aria-hidden="true"
              className="text-6xl font-black leading-none tracking-[-0.09em] text-[#c9ff54]/60 sm:text-8xl"
            >
              02
            </span>
          </div>
        </div>
        <div className="grid min-w-0 items-start gap-5 lg:grid-cols-[minmax(0,1.5fr)_minmax(0,1fr)]">
          <Card className="scan-demo-reveal min-w-0 overflow-hidden">
            <div className="flex min-w-0 flex-wrap items-center justify-between gap-3 bg-[#eee8ff] px-5 py-5 sm:px-7">
              <div className="flex items-center gap-4">
                <span
                  aria-hidden="true"
                  className="text-4xl font-black leading-none tracking-[-0.09em] text-[#5535a0]"
                >
                  01
                </span>
                <div>
                  <p className="text-[11px] font-black uppercase tracking-[0.18em] text-[#5535a0]">
                    Настройка / image
                  </p>
                  <h3 className="text-xl font-extrabold tracking-tight text-[#21153d] sm:text-2xl">
                    Параметры проверки
                  </h3>
                </div>
              </div>
              <Badge tone="warning">Запуск недоступен</Badge>
            </div>
            <div className="min-w-0 space-y-7 p-5 sm:p-7">
              <div className="min-w-0 space-y-3">
                <label htmlFor="image-reference" className="block text-sm font-bold text-[#21153d]">
                  Образ в registry (только разрешённый Alpine)
                </label>
                <input
                  {...register('imageReference')}
                  id="image-reference"
                  className={`${controlClass} w-full min-w-0 border-[#a99bc8] font-normal transition-[border-color,box-shadow] hover:border-[#5535a0] focus-visible:border-[#5535a0] focus-visible:ring-2 focus-visible:ring-[#c9ff54]`}
                  placeholder="registry-1.docker.io/library/alpine:3.21"
                  aria-invalid={!!errors.imageReference}
                  aria-describedby={errors.imageReference ? 'image-reference-error' : undefined}
                />
                {errors.imageReference ? (
                  <p id="image-reference-error" role="alert" className="text-sm text-red-800">
                    {errors.imageReference.message}
                  </p>
                ) : null}
              </div>
              <fieldset className="min-w-0 border-t border-[#e3dff0] pt-6">
                <legend className="text-base font-extrabold tracking-tight text-[#21153d]">
                  Проектируемые проверки и область
                </legend>
                <div className="mt-4 space-y-2">
                  <div className="flex min-w-0 items-start gap-3 rounded-xl border border-[#e3dff0] bg-[#f8f7fb] p-3 text-sm leading-relaxed text-slate-700 sm:p-4">
                    <LockKeyhole size={19} className="mt-0.5 shrink-0 text-[#5535a0]" aria-hidden="true" />
                    <span className="min-w-0">
                      Secrets · image (внутренний сценарий разрабатывается и ожидает приёмки; запуск из
                      браузера недоступен)
                    </span>
                  </div>
                  <label className="flex min-w-0 items-start gap-3 rounded-xl border border-[#e3dff0] bg-[#f8f7fb] p-3 text-sm leading-relaxed text-slate-600 sm:p-4">
                    <input className="mt-0.5 size-5 shrink-0" type="checkbox" disabled />
                    <span className="min-w-0">CVE и SBOM · пока недоступны</span>
                  </label>
                  <label className="flex min-w-0 items-start gap-3 rounded-xl border border-[#e3dff0] bg-[#f8f7fb] p-3 text-sm leading-relaxed text-slate-600 sm:p-4">
                    <input className="mt-0.5 size-5 shrink-0" type="checkbox" disabled />
                    <span className="min-w-0">
                      Container / host · требуется отдельное разрешение и backend
                    </span>
                  </label>
                </div>
              </fieldset>
              <div className="min-w-0 space-y-5 border-t border-[#e3dff0] pt-6">
                <label className="flex min-w-0 items-start gap-3 rounded-xl border border-[#cbbde9] bg-[#f6f2ff] p-4 text-sm leading-relaxed transition-colors hover:border-[#5535a0] focus-within:ring-2 focus-within:ring-[#5535a0]">
                  <input
                    className="mt-0.5 size-5 shrink-0 accent-[#5535a0] focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-[#5535a0]"
                    type="checkbox"
                    checked={confirmed}
                    onChange={(event) => setConfirmed(event.target.checked)}
                  />
                  <span className="min-w-0 text-[#21153d]">
                    Подтверждаю выбранную цель и область:{' '}
                    <strong className="font-extrabold [overflow-wrap:anywhere]">
                      {imageReference || 'цель не указана'}
                    </strong>
                  </span>
                </label>
                <Button
                  className="w-full gap-3 sm:w-auto"
                  type="button"
                  disabled
                  title="Нет защищённого browser ingress и авторизованной сессии"
                >
                  <LockKeyhole size={18} aria-hidden="true" /> Запуск недоступен
                </Button>
                <p className="text-sm leading-relaxed text-slate-700">
                  {confirmed
                    ? 'Цель подтверждена, но сервер недоступен из браузера.'
                    : 'До запуска подтвердите цель и scope.'}{' '}
                  Даже после квитанции POST digest/platform остаются неподтверждёнными до авторизованного GET
                  status.
                </p>
              </div>
            </div>
          </Card>
          <Card className="scan-demo-reveal min-w-0 overflow-hidden">
            <div className="relative overflow-hidden bg-[#24193f] px-5 py-7 text-white sm:px-7">
              <span
                aria-hidden="true"
                className="pointer-events-none absolute -right-4 -bottom-9 text-9xl font-black leading-none text-[#c9ff54]/15"
              >
                02
              </span>
              <p className="relative text-[11px] font-black uppercase tracking-[0.2em] text-[#c9ff54]">
                Границы доверия
              </p>
              <h3 className="relative mt-3 max-w-[12ch] text-3xl font-black leading-[1.05] tracking-[-0.05em] sm:text-4xl">
                Что планируется проверить?
              </h3>
              <ArrowDownRight size={25} className="relative mt-6 text-[#c9ff54]" aria-hidden="true" />
            </div>
            <div className="min-w-0 space-y-6 p-5 sm:p-7">
              <ul className="space-y-0 text-sm leading-relaxed text-slate-700">
                <li className="flex min-w-0 gap-3 border-b border-[#e3dff0] py-4 first:pt-0">
                  <ArrowRight size={18} className="mt-0.5 shrink-0 text-[#5535a0]" aria-hidden="true" />
                  <span className="min-w-0">
                    <strong className="block text-base font-extrabold text-[#21153d]">Цель и область</strong>
                    Планируемая область: разрешённый образ Alpine и secrets внутри image. Внутренний сценарий
                    ожидает приёмки.
                  </span>
                </li>
                <li className="flex min-w-0 gap-3 border-b border-[#e3dff0] py-4">
                  <ArrowRight size={18} className="mt-0.5 shrink-0 text-[#5535a0]" aria-hidden="true" />
                  <span className="min-w-0">
                    <strong className="block text-base font-extrabold text-[#21153d]">Не проверяется</strong>
                    CVE, SBOM и container / host не входят в доступный scope.
                  </span>
                </li>
                <li className="flex min-w-0 gap-3 py-4 pb-0">
                  <ShieldCheck size={18} className="mt-0.5 shrink-0 text-[#5535a0]" aria-hidden="true" />
                  <span className="min-w-0">
                    <strong className="block text-base font-extrabold text-[#21153d]">Результат</strong> POST
                    202 — квитанция, не подтверждение закреплённого digest/platform.
                  </span>
                </li>
              </ul>
              <Alert className="text-sm leading-relaxed">
                Без защищённой авторизованной сессии запуск из браузера невозможен.{' '}
                {demo
                  ? 'Демо показывает только вымышленные результаты.'
                  : 'Доступ к реальному API не настроен.'}
              </Alert>
            </div>
          </Card>
        </div>
      </section>
    </ScanShell>
  );
}
