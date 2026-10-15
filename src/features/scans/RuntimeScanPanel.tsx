import { useCallback, useEffect, useMemo, useState, useRef } from 'react';
import {
  RuntimeTransport,
  type RuntimeCapabilities,
  type RuntimeConsent,
  type RuntimeReport,
  type RuntimeTarget,
  type RuntimeMode,
} from '../../shared/api/scans/runtimeTransport';
import { scanSession } from '../../shared/api/auth/scanSession';
const newKey = () =>
  Array.from(crypto.getRandomValues(new Uint8Array(16)), (v) => v.toString(16).padStart(2, '0')).join('');
const errors: Record<string, string> = {
  RUNTIME_UNAVAILABLE: 'Runtime-хранилище или raw ingress ещё не подключены оператором.',
  NOT_AUTHORIZED: 'Нет отдельного runtime допуска, актуального согласия или enrolled provenance.',
  RUNTIME_ACCESS_CHANGED: 'Сессия изменилась. Откройте панель заново.',
  INVALID_RUNTIME_INPUT: 'Пакет не соответствует ограниченному runtime контракту.',
  RUNTIME_REQUEST_FAILED: 'Запрос отклонён. Исторические данные не изменены.',
};
export function RuntimeScanPanel({ subject, generation }: { subject: string; generation: number }) {
  const transport = useMemo(
    () =>
      new RuntimeTransport(
        subject,
        () => scanSession().subject === subject && scanSession().generation === generation,
      ),
    [subject, generation],
  );
  const [caps, setCaps] = useState<RuntimeCapabilities | null>(null);
  const [targets, setTargets] = useState<RuntimeTarget[]>([]);
  const [targetId, setTarget] = useState('');
  const [mode, setMode] = useState<RuntimeMode>('imported-historical');
  const [consent, setConsent] = useState<RuntimeConsent | null>(null);
  const [input, setInput] = useState('');
  const [history, setHistory] = useState<RuntimeReport[]>([]);
  const [cursor, setCursor] = useState<string | null>(null);
  const [detail, setDetail] = useState<RuntimeReport | null>(null);
  const [imageId, setImageId] = useState('');
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState('');
  const [intentKey, setIntentKey] = useState<string | null>(null);
  const mounted = useRef(false);
  const action = useRef(0);
  const view = useRef(0);
  const selectedCapture = useRef<string | null>(null);
  const sessionCurrent = useCallback(
      () => scanSession().subject === subject && scanSession().generation === generation,
      [subject, generation],
    );
    const invalidatePending = useCallback(() => {
      action.current++;
      view.current++;
    }, []);
  const selected = targets.find((t) => t.targetId === targetId);
  const fail = (e: unknown) =>
    setError(
      errors[e instanceof Error ? e.message : ''] ?? 'Runtime-запрос не выполнен; live доступ не расширен.',
    );
  useEffect(() => {
    const abort = new AbortController();
    let active = true;
    mounted.current = true;
    action.current++;
    view.current++;
    selectedCapture.current = null;
    setConsent(null);
    setIntentKey(null);
    setDetail(null);
    setInput('');
    setImageId('');
    setTarget('');
    setMode('imported-historical');
    setBusy(false);
    setError('');
    setCaps(null);
    setTargets([]);
    setHistory([]);
    setCursor(null);
    Promise.all([
      transport.capabilities(abort.signal),
      transport.targets(abort.signal),
      transport.history(undefined, abort.signal),
    ])
      .then(([c, t, h]) => {
        if (active && sessionCurrent()) {
          setCaps(c);
          setTargets(t);
          setHistory(h.captures);
          setCursor(h.nextCursor);
        }
      })
      .catch((e) => {
        if (active && sessionCurrent()) fail(e);
      });
    return () => {
      active = false;
      mounted.current = false;
      invalidatePending();
      abort.abort();
    };
  }, [transport, sessionCurrent, invalidatePending]);
  const run = async (fn: (current: () => boolean) => Promise<void>) => {
    if (!mounted.current || !sessionCurrent()) return;
    const token = ++action.current,
      selection = view.current;
    const current = () =>
      mounted.current && sessionCurrent() && action.current === token && view.current === selection;
    setBusy(true);
    setError('');
    try {
      await fn(current);
    } catch (e) {
      if (current()) fail(e);
    } finally {
      if (current()) setBusy(false);
    }
  };
  const reset = () => {
    action.current++;
    view.current++;
    selectedCapture.current = null;
    setBusy(false);
    setImageId('');
    setConsent(null);
    setIntentKey(null);
    setInput('');
    setDetail(null);
    setError('');
  };
  const refresh = async (current: () => boolean) => {
    const id = selectedCapture.current,
      selection = view.current;
    const [h, d] = await Promise.all([
      transport.history(),
      id ? transport.detail(id) : Promise.resolve(null),
    ]);
    if (!current() || view.current !== selection || selectedCapture.current !== id) return;
    setHistory(h.captures);
    setCursor(h.nextCursor);
    if (d) setDetail(d);
  };
  const selectCapture = (id: string) => {
    selectedCapture.current = id;
    view.current++;
    setDetail(null);
    setImageId('');
    return run(async (current) => {
      const d = await transport.detail(id);
      if (current()) setDetail(d);
    });
  };
  return (
    <section
      aria-labelledby="runtime-panel-title"
      className="my-6 min-w-0 space-y-4 rounded-xl border p-4 [overflow-wrap:anywhere]"
    >
      <h2 id="runtime-panel-title">Контейнер: отдельное runtime evidence</h2>
      <p>
        Исторический импорт не является live-сканированием. Host требует независимого opt-in; нативный macOS
        не равен Linux VM Docker Desktop.
      </p>
      <p>
        Не проверяются writable layer, содержимое volumes, traffic, effective isolation, exploitability и весь
        host.
      </p>
      {error ? <p role="alert">{error}</p> : null}
      <p role="status">
        Live capture:{' '}
        {caps?.liveCapture
          ? 'условно доступен для enrolled Linux-local цели'
          : 'недоступен: требуется квалификация TASK5 и отдельная application topology/protocol'}
        . Наличие Docker не даёт прав.
      </p>
      <label className="block">
        Режим{' '}
        <select
          value={mode}
          disabled={busy}
          onChange={(e) => {
            reset();
            setMode(e.target.value as RuntimeMode);
          }}
        >
          <option value="imported-historical">Подписанный исторический импорт</option>
          <option value="broker-capture" disabled={!caps?.liveCapture}>
            Linux-local capture · qualified only
          </option>
        </select>
      </label>
      <label className="block">
        Зарегистрированная цель{' '}
        <select
          value={targetId}
          disabled={busy}
          onChange={(e) => {
            reset();
            setTarget(e.target.value);
          }}
        >
          <option value="">Выберите enrolled target</option>
          {targets.map((t) => (
            <option key={t.targetId} value={t.targetId}>
              {t.context} / {t.containerId}
            </option>
          ))}
        </select>
      </label>
      {!targets.length ? (
        <p>
          Нет enrolled целей для вашей учётной записи. Оператор отдельно регистрирует полный container
          ID/context и публичный signer; Engine enumeration не выполняется.
        </p>
      ) : null}
      {selected ? (
        <p>
          Full ID: <code>{selected.containerId}</code> · context {selected.context} v{selected.contextVersion}
          ; enrollment v{selected.version}
        </p>
      ) : null}
      <button
        type="button"
        disabled={
          busy ||
          !selected ||
          (mode === 'imported-historical' && !selected.importAllowed) ||
          (mode === 'broker-capture' && (!caps?.liveCapture || !selected?.liveAllowed))
        }
        onClick={() =>
          run(async (current) => {
            const c = await transport.consent(targetId, mode, selected);
            if (!current()) return;
            setConsent(c);
            setIntentKey(null);
          })
        }
      >
        Подтверждаю только выбранный runtime scope / цель
      </button>
      {consent ? (
        <div>
          <p>
            Consent {consent.consentId} до {new Date(consent.expiresAt).toISOString()}; nonce для
            операторского пакета:
          </p>
          <code>{consent.nonce}</code>
          <p>
            Authority epoch {consent.epoch}; subject <code>{subject}</code>. Пакет подписывает отдельно
            enrolled оператор, приватный ключ не загружается сюда.
          </p>
          <button
            type="button"
            disabled={busy}
            onClick={() =>
              run(async (current) => {
                await transport.revoke(consent.consentId);
                if (!current()) return;
                setConsent(null);
                setIntentKey(null);
                setInput('');
                await refresh(current);
              })
            }
          >
            Отозвать это runtime согласие
          </button>
        </div>
      ) : null}
      {mode === 'imported-historical' ? (
        <label className="block">
          Очищенный signed JSON package (не raw inspect)
          <textarea
            className="block w-full min-w-0 rounded border p-2"
            rows={6}
            value={input}
            disabled={busy}
            onChange={(e) => {
              setInput(e.target.value);
              setIntentKey(null);
            }}
            maxLength={65536}
          />
        </label>
      ) : null}
      <button
        type="button"
        disabled={
          busy ||
          !consent ||
          consent.expiresAt <= Date.now() ||
          (mode === 'imported-historical' && !input) ||
          (mode === 'broker-capture' && !caps?.liveCapture)
        }
        onClick={() =>
          run(async (current) => {
            if (!consent) return;
            const key = intentKey ?? newKey();
            setIntentKey(key);
            if (new TextEncoder().encode(input).length > 65536) throw new Error('INVALID_RUNTIME_INPUT');
            const receipt =
              mode === 'imported-historical'
                ? await transport.submitImport(key, input)
                : await transport.submitCapture(key, consent);
            if (!current()) return;
            selectedCapture.current = receipt.captureId;
            const d = await transport.detail(receipt.captureId);
            if (!current()) return;
            setDetail(d);
            await refresh(current);
          })
        }
      >
        {busy
          ? 'Обработка…'
          : mode === 'imported-historical'
            ? 'Принять исторический пакет'
            : 'Запросить qualified capture'}
      </button>
      <h3>Отдельная runtime история</h3>
      <button type="button" disabled={busy} onClick={() => run(refresh)}>
        Обновить историю / durable status
      </button>
      <ul>
        {history.map((r) => (
          <li key={r.captureId}>
            <button type="button" disabled={busy} onClick={() => selectCapture(r.captureId)}>
              {r.createdAt} · {r.mode} · {r.state} · {r.target.context}
            </button>
          </li>
        ))}
      </ul>
      {cursor ? (
        <button
          type="button"
          disabled={busy}
          onClick={() =>
            run(async (current) => {
              const h = await transport.history(cursor);
              if (!current()) return;
              setHistory((previous) => [
                ...previous,
                ...h.captures.filter((r) => !previous.some((p) => p.captureId === r.captureId)),
              ]);
              setCursor(h.nextCursor);
            })
          }
        >
          Следующая runtime страница
        </button>
      ) : null}
      {detail ? (
        <article aria-label="Runtime evidence detail" className="min-w-0 space-y-2">
          <h3>
            {detail.mode === 'imported-historical'
              ? 'Импортированные исторические данные'
              : 'Broker observation в момент capture'}
          </h3>
          <p>
            {detail.state} / {detail.reason} · {detail.checksVersion} / {detail.resourcePolicyVersion}
          </p>
          <p>
            {detail.target.containerId} · {detail.target.context} v{detail.target.contextVersion}; archived
            enrollment v{detail.target.version}
          </p>
          <p>
            Archived consent: <code>{detail.consentId}</code> · не текущее согласие формы.
          </p>
          {detail.evidence ? (
            <>
              <p>
                Capture interval: {detail.evidence.startedAt} — {detail.evidence.endedAt}. Received:{' '}
                {detail.receivedAt}
              </p>
              <p>
                Canonical capture hash: <code>{detail.evidence.hash}</code>; snapshot v1 hash:{' '}
                <code>{detail.evidence.snapshot.hash}</code>
              </p>
              <p>
                Running-at-observation: {String(detail.evidence.running)}
                {detail.mode === 'imported-historical'
                  ? ' · заявление enrolled источника, не live proof'
                  : ''}
                ; не текущая liveness.
              </p>
              <p>
                Provenance: {detail.provenance?.signerId ?? 'qualified broker'}; sourceVersion{' '}
                {detail.provenance?.sourceVersion ?? 'runtime-capture-v1 broker'}; configured facts не
                доказывают effective UID/isolation.
              </p>
              <pre className="max-w-full whitespace-pre-wrap break-words text-xs">
                {JSON.stringify(detail.evidence.snapshot.facts, null, 2)}
              </pre>
              <p>
                Image config identity: {detail.evidence.imageConfigDigest ?? 'unknown'} · не manifest digest.
              </p>
            </>
          ) : (
            <p>Нет committed evidence; это не «0 проблем».</p>
          )}
          {detail.state === 'running' ? (
            <button
              type="button"
              disabled={busy}
              onClick={() =>
                run(async (current) => {
                  const id = detail.captureId;
                  if (selectedCapture.current !== id || !current()) return;
                  await transport.cancel(id);
                  if (!current()) return;
                  await refresh(current);
                })
              }
            >
              Отменить текущую попытку
            </button>
          ) : null}
          {detail.evidence?.imageConfigDigest ? (
            <div>
              <label>
                Отдельно owner-admitted image scan ID{' '}
                <input
                  value={imageId}
                  onChange={(e) => setImageId(e.target.value)}
                  className="block w-full rounded border p-2"
                />
              </label>
              <button
                type="button"
                disabled={busy || !imageId}
                onClick={() =>
                  run(async (current) => {
                    const id = detail.captureId;
                    if (selectedCapture.current !== id || !current()) return;
                    await transport.imageLink(id, imageId);
                    if (!current()) return;
                    const d = await transport.detail(id);
                    if (current()) setDetail(d);
                  })
                }
              >
                Проверить manifest → config → platform association
              </button>
            </div>
          ) : null}
          {!detail.links.length ? (
            <p>Image linkage/CVE/SBOM: unsupported / отсутствует подтверждённая chain; counts unknown.</p>
          ) : (
            detail.links.map((l) => (
              <div key={l.imageScanId}>
                <p>
                  Image-only {l.manifestDigest} / {l.platform}; {l.verificationVersion}
                </p>
                <p>
                  SBOM {l.sbom.outcome}, CVE {l.vuln.outcome}.{' '}
                  {l.sbom.outcome === 'checked' && l.vuln.outcome === 'checked'
                    ? 'Image-only checks available.'
                    : 'Partial / unavailable image-only coverage; не «0 проблем».'}{' '}
                  Actual image evidence: {l.imageScanId}; DB provenance hash{' '}
                  {l.vuln.dbEvidenceHash ?? 'unavailable'}. Это не writable filesystem контейнера.
                </p>
                <p>
                  SBOM reason {l.sbom.reason}; scanner {l.sbom.scannerVersion ?? 'unavailable'}; checkedAt{' '}
                  {l.sbom.checkedAt ?? 'unavailable'}.
                </p>
                <p>
                  CVE reason {l.vuln.reason}; scanner {l.vuln.scannerVersion ?? 'unavailable'}; checkedAt{' '}
                  {l.vuln.checkedAt ?? 'unavailable'}.
                </p>
              </div>
            ))
          )}
          <p>Исключения: {detail.exclusions.join(', ')}. Host: not_authorized.</p>
        </article>
      ) : null}
    </section>
  );
}
