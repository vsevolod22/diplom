import assert from 'node:assert/strict';
import { test } from 'node:test';
import { JSDOM } from 'jsdom';
import React, { act } from 'react';
import { createRoot } from 'react-dom/client';
import { generateKeyPairSync } from 'node:crypto';
import { RuntimeScanPanel } from '../../../src/features/scans/RuntimeScanPanel.js';
import { scanSession, transitionScanSession } from '../../../src/shared/api/auth/scanSession.js';
import { project } from '../../broker/src/projection.js';
import { createHistoricalPackage } from '../src/operator-package.js';
import { EXCLUSIONS, type Report, type Target } from '../src/contract.js';
const target: Target = {
  targetId: 'a'.repeat(32),
  containerId: 'b'.repeat(64),
  context: 'isolated-linux',
  contextVersion: 1,
  version: 1,
  importAllowed: true,
  liveAllowed: false,
};
const date = '2026-10-08T12:00:00.000Z',
  id = 'e'.repeat(32),
  consentId = 'c'.repeat(32);
const running: Report = {
  captureId: id,
  subject: 'alice',
  target,
  mode: 'imported-historical',
  state: 'running',
  reason: 'READY',
  createdAt: date,
  receivedAt: null,
  consentId,
  checksVersion: 'runtime-config-v1',
  resourcePolicyVersion: 'runtime-host-policy-v1',
  evidence: null,
  provenance: null,
  links: [],
  exclusions: EXCLUSIONS,
};
const caps = {
  schemaVersion: 'runtime-capabilities-v1',
  historicalImport: true,
  liveCapture: false,
  liveReason: 'QUALIFICATION_MISSING',
  host: 'not_authorized',
  rawIntake: 'parent-bootstrap-required',
};
const client = { cancelQueries: async () => {}, removeQueries: () => {} };
const session = (subject: string) => {
  transitionScanSession(subject, client as never, true);
  return scanSession().generation;
};
const json = (value: unknown) => new Response(JSON.stringify(value));
const delay = () => new Promise((resolve) => setTimeout(resolve, 5));
const deferred = () => {
  let resolve!: (value: Response) => void;
  const promise = new Promise<Response>((r) => {
    resolve = r;
  });
  return { promise, resolve };
};
function completed(): Report {
  const snapshot = project(
    {
      Id: target.containerId,
      Config: { User: '1000' },
      HostConfig: {
        Privileged: false,
        ReadonlyRootfs: true,
        SecurityOpt: [],
        Memory: 0,
        NanoCpus: 0,
        PidsLimit: 5,
        CpuQuota: 0,
        CpuPeriod: 0,
        NetworkMode: 'none',
        PidMode: '',
        IpcMode: 'private',
        UsernsMode: '',
        CapAdd: [],
        CapDrop: [],
        PortBindings: {},
      },
      Mounts: [],
    },
    {
      epoch: 1,
      subject: 'alice',
      id: target.containerId,
      context: { id: target.context, version: 1, transport: 'unix', endpoint: '/unused', apiVersion: '1.47' },
      grantVersion: 1,
    },
    Date.parse(date),
  );
  const packet = createHistoricalPackage(
    {
      snapshot,
      startedAt: date,
      running: true,
      imageConfigDigest: `sha256:${'2'.repeat(64)}`,
      imageSemantics: 'docker-config-sha256-v1',
      subject: 'alice',
      targetId: target.targetId,
      targetVersion: 1,
      consentId,
      nonce: 'd'.repeat(64),
      authorityEpoch: 7,
      signerId: 'f'.repeat(32),
    },
    generateKeyPairSync('ed25519').privateKey,
  );
  return {
    ...running,
    state: 'completed',
    receivedAt: date,
    evidence: packet.payload.capture,
    provenance: { signerId: 'f'.repeat(32), sourceVersion: 'operator-runtime-v1' },
    links: [
      {
        imageScanId: '00000000-0000-0000-0000-000000000001',
        manifestDigest: `sha256:${'1'.repeat(64)}`,
        configDigest: `sha256:${'2'.repeat(64)}`,
        platform: 'linux/amd64',
        verificationVersion: 'image-config-chain-v1',
        captureHash: packet.payload.capture.hash,
        linkedAt: date,
        sbom: {
          outcome: 'checked',
          reason: 'READY',
          scannerVersion: '0.69.3',
          checkedAt: date,
          dbEvidenceHash: null,
        },
        vuln: {
          outcome: 'failed',
          reason: 'IMAGE_RESULT_UNAVAILABLE',
          scannerVersion: null,
          checkedAt: null,
          dbEvidenceHash: null,
        },
      },
    ],
  };
}

test('R9/R11 actual mounted panel refreshes selected terminal detail, fences session/late/unmount and renders archived independent provenance', async () => {
  const dom = new JSDOM('<!doctype html><div id="root"></div>', { url: 'http://localhost/' });
  const prior = new Map<string, PropertyDescriptor | undefined>();
  for (const [key, value] of Object.entries({
    window: dom.window,
    document: dom.window.document,
    navigator: dom.window.navigator,
    HTMLElement: dom.window.HTMLElement,
    IS_REACT_ACT_ENVIRONMENT: true,
  })) {
    prior.set(key, Object.getOwnPropertyDescriptor(globalThis, key));
    Object.defineProperty(globalThis, key, { value, writable: true, configurable: true });
  }
  const originalFetch = globalThis.fetch;
  const container = dom.window.document.getElementById('root')!;
  const root = createRoot(container);
  let report = structuredClone(running),
    detailCalls = 0,
    cancelCalls = 0,
    pending: ReturnType<typeof deferred> | undefined;
  const button = (text: string) => {
    const found = Array.from(container.querySelectorAll('button')).find((b) => b.textContent?.includes(text));
    assert.ok(found, `missing button ${text}`);
    return found;
  };
  const click = async (text: string) => {
    await act(async () => {
      button(text).click();
      await delay();
    });
  };
  const select = async (index: number, value: string) => {
    await act(async () => {
      const element = container.querySelectorAll('select')[index];
      element.value = value;
      element.dispatchEvent(new dom.window.Event('change', { bubbles: true }));
      await delay();
    });
  };
  const render = async (subject: string) => {
    const generation = session(subject);
    await act(async () => {
      root.render(<RuntimeScanPanel subject={subject} generation={generation} />);
      await delay();
    });
  };
  globalThis.fetch = async (url, init) => {
    const path = String(url);
    if (path.endsWith('/capabilities')) return json(caps);
    if (path.endsWith('/targets')) return json({ targets: [target] });
    if (path.endsWith('/consents'))
      return json({
        consentId: '9'.repeat(32),
        nonce: '8'.repeat(64),
        expiresAt: Date.now() + 60000,
        epoch: 8,
        target,
        mode: 'imported-historical',
      });
    if (path.endsWith('/cancel')) {
      cancelCalls++;
      report = { ...running, state: 'cancelled', reason: 'CANCELLED' };
      return json({ changed: true, cancelled: true, state: 'cancelled' });
    }
    if (path.endsWith(`/captures/${id}`)) {
      detailCalls++;
      if (pending) return pending.promise;
      return json(report);
    }
    if (path.endsWith('/captures'))
      return json({ captures: scanSession().subject === 'alice' ? [report] : [], nextCursor: null });
    throw new Error(`unexpected ${path} ${init?.method}`);
  };
  try {
    await render('alice');
    await click(date);
    assert.match(container.querySelector('article')!.textContent!, /running \/ READY/);
    assert.ok(button('Отменить'));
    report = { ...running, state: 'failed', reason: 'INDETERMINATE' };
    await click('Обновить историю');
    assert.match(container.querySelector('article')!.textContent!, /failed \/ INDETERMINATE/);
    assert.equal(
      Array.from(container.querySelectorAll('button')).some((b) => b.textContent?.includes('Отменить')),
      false,
    );
    assert.equal(cancelCalls, 0);
    assert.equal(detailCalls, 2);
    report = completed();
    await click('Обновить историю');
    const archived = container.querySelector('article')!.textContent!;
    assert.match(archived, new RegExp(`Archived consent: ${consentId}`));
    assert.match(archived, /archived enrollment v1/);
    assert.match(archived, /sourceVersion operator-runtime-v1/);
    assert.match(archived, /SBOM reason READY; scanner 0.69.3; checkedAt 2026-10-08T12:00:00.000Z/);
    assert.match(archived, /CVE reason IMAGE_RESULT_UNAVAILABLE; scanner unavailable; checkedAt unavailable/);
    assert.match(archived, /Partial \/ unavailable image-only coverage/);
    await select(1, target.targetId);
    assert.equal(container.querySelector('article'), null);
    await click('Подтверждаю');
    assert.match(container.textContent!, new RegExp(`Consent ${'9'.repeat(32)}`));
    await click(date);
    assert.match(container.querySelector('article')!.textContent!, new RegExp(consentId));
    assert.equal(container.querySelector('article')!.textContent!.includes('9'.repeat(32)), false);
    await select(1, '');
    assert.equal(container.querySelector('article'), null);
    assert.equal(container.textContent!.includes('Consent ' + '9'.repeat(32)), false);
    await click(date);
    pending = deferred();
    await act(async () => {
      button('Обновить историю').click();
      await delay();
    });
    await render('bob');
    await act(async () => {
      pending!.resolve(json(report));
      await delay();
    });
    assert.equal(container.querySelector('article'), null);
    assert.equal(container.textContent!.includes('Consent ' + '9'.repeat(32)), false);
    assert.equal(cancelCalls, 0);
    pending = undefined;
    report = structuredClone(running);
    await render('alice');
    await click(date);
    await click('Отменить');
    assert.match(container.querySelector('article')!.textContent!, /cancelled \/ CANCELLED/);
    assert.equal(cancelCalls, 1);
    pending = deferred();
    await act(async () => {
      button('Обновить историю').click();
      await delay();
    });
    await act(async () => {
      root.unmount();
      pending!.resolve(json(report));
      await delay();
    });
    assert.equal(container.textContent, '');
  } finally {
    // unmount is idempotent in this local root; no shared UI/report modules are mutated.
    await act(async () => root.unmount());
    globalThis.fetch = originalFetch;
    dom.window.close();
    for (const [key, descriptor] of prior) {
      if (descriptor) Object.defineProperty(globalThis, key, descriptor);
      else Reflect.deleteProperty(globalThis, key);
    }
  }
});
