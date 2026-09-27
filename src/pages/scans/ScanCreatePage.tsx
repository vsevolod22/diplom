import { useState } from 'react';
import { useForm, useWatch } from 'react-hook-form';
import { z } from 'zod';
import { zodResolver } from '@hookform/resolvers/zod';
import { ScanShell, controlClass } from '@/features/scans/ScanShell';

const formSchema = z.object({ imageReference: z.string().trim().min(1, 'Укажите цель').max(256, 'Слишком длинная ссылка') });
type FormValues = z.infer<typeof formSchema>;
export function ScanCreatePage({ demo = false }: { demo?: boolean }) {
  const { register, control, formState: { errors } } = useForm<FormValues>({ resolver: zodResolver(formSchema), defaultValues: { imageReference: '' } });
    const imageReference = useWatch({ control, name: 'imageReference' });
  const [confirmed, setConfirmed] = useState(false);
  return <ScanShell demo={demo}>
    <section className="max-w-xl space-y-5 rounded-xl border border-slate-200 p-5" aria-labelledby="new-scan">
      <h2 id="new-scan" className="text-xl font-semibold">Новый скан</h2>
      <label className="block space-y-2">Образ в registry (только разрешённый Alpine)
        <input {...register('imageReference')} className={`${controlClass} w-full`} placeholder="registry-1.docker.io/library/alpine:3.21" aria-invalid={!!errors.imageReference} />
      </label>
      {errors.imageReference ? <p role="alert">{errors.imageReference.message}</p> : null}
      <fieldset className="space-y-2"><legend className="font-medium">Доступные проверки и область</legend>
        <label className="block"><input type="checkbox" checked readOnly /> Secrets · image (внутренний API)</label>
        <label className="block text-slate-600"><input type="checkbox" disabled /> CVE и SBOM · пока недоступны</label>
        <label className="block text-slate-600"><input type="checkbox" disabled /> Container / host · требуется отдельное разрешение и backend</label>
      </fieldset>
      <label className="flex gap-2"><input type="checkbox" checked={confirmed} onChange={(event) => setConfirmed(event.target.checked)} /> Подтверждаю выбранную цель и область: {imageReference || 'цель не указана'}</label>
      <button className={controlClass} type="button" disabled title="Нет защищённого browser ingress и авторизованной сессии">Запуск недоступен</button>
      <p className="text-sm text-slate-600">{confirmed ? 'Цель подтверждена, но сервер недоступен из браузера.' : 'До запуска подтвердите цель и scope.'} Даже после квитанции POST digest/platform остаются неподтверждёнными до авторизованного GET status.</p>
    </section>
  </ScanShell>;
}
