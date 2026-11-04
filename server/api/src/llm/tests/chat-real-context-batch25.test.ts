import 'reflect-metadata';
import assert from 'node:assert/strict';
import test from 'node:test';
import { createHash, randomUUID } from 'node:crypto';
import { mkdtempSync, readFileSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { LedgerStore } from '../../ledger/ledger-store.js';
import { OciResolver } from '../../oci/oci-resolver.js';
import { PublicImageScansService } from '../../scans/public-image-scans.service.js';
import { publicVulnerabilityFixture } from '../../scans/public-vulnerability.fixture.js';
import { parseVulnFindings } from '../../worker/vuln-findings.js';
import { CURRENT_DB_POLICY, evaluateDbPolicy } from '../../worker/cve-db-policy.mjs';
import type { ArchiveScanReport } from '../../worker/archive-scan-worker.js';
import { ReportReader } from '../report-context.js';
import { HISTORY, bytes, reportBinding, validateChatReply, type Turn } from '../history-contract.js';
import { HistoryStore } from '../history-store.js';
import { selectPreparedHistory } from '../history-context.js';
import { prepareOpenAiChat, validateOpenAiPreparedReply } from '../openai-prepared-request.js';
import { makeOpenAiPolicy } from './openai-core.fixture.js';
import { diagnostic } from '../provider-diagnostic.js';
import { mandatoryFinding } from '../summary-context.js';
import { chatReplySchema, chatHistorySchema } from '../../../../../src/shared/api/scans/llmChatContract.js';
import { historyProjection } from '../history-contract.js';
import { encodeDelivery, DELIVERY } from '../history-delivery.js';
import { OPENAI_COST_BASIS } from '../openai-accounting.js';

const replayDirectory = process.env.NODE_DLA_REPLAY_DIR;
const question = 'С каких находок этого отчёта начать проверку и какое ограничение покрытия важно учитывать? Ответь по-русски с источниками.';
const text = 'Сканер сообщил о находке; требуется проверка.';
const identity = { subject: 'a'.repeat(32), scope: ['scan:read'] };

// Opt-in private input stays in memory. Assertions expose booleans/counts only,
// never scanner facts, citation identities, prepared bodies or provider responses.
test('batch25 actual440 selected chat citations satisfy production acceptance and durable history', { skip: !replayDirectory }, t => {
  const raw = readFileSync(join(replayDirectory!, 'scanner.private.json'));
  assert.equal(createHash('sha256').update(raw).digest('hex'), '69277afee2131f161651203864d1a776e336e9029d20e6b011f600d8fc003c22');
  const reduced = JSON.parse(readFileSync(join(replayDirectory!, 'reduced-public-fixture.json'), 'utf8'));
  const findings = parseVulnFindings(JSON.parse(raw.toString('utf8')), reduced.image, 'linux/amd64', reduced.binding);
  assert.equal(findings.length, 440);
  const report: ArchiveScanReport = { ...publicVulnerabilityFixture(), receipt: reduced.binding.receipt,
    scannerVersion: reduced.scannerVersion, vuln: { outcome: 'checked', findings, db: reduced.dbIdentity,
      dbPolicy: evaluateDbPolicy(reduced.dbIdentity, CURRENT_DB_POLICY, Date.now())!,
      os: { outcome: 'checked' }, node: { outcome: 'unsupported', reason: 'NODE_INVENTORY_UNKNOWN' } } };
  delete report.sbom;
  const directory = mkdtempSync(join(tmpdir(), 'chat-real-context-batch25-'));
  const previous = process.env.SCAN_LEDGER_PATH;
  process.env.SCAN_LEDGER_PATH = join(directory, 'ledger.sqlite');
  const store = new LedgerStore();
  let history: HistoryStore | undefined;
  try {
    const ledger = store.ledger!;
    const scanId = ledger.enqueue({ ...report.receipt, subject: identity.subject, idempotencyKey: 'batch25-chat',
      scope: 'image', checks: '["vuln"]', cvePolicy: CURRENT_DB_POLICY }).scanId;
    const job = ledger.claim()!;
    assert.equal(ledger.finishArchive(scanId, job.attempts, report, undefined, job.leaseToken), true);
    const scans = new PublicImageScansService(store, new OciResolver());
    const full = new ReportReader(scans, true).read(identity, scanId);
    assert.equal(full.findingCount, 440);
    assert.deepEqual(full.identifierCounts, { cve: 431, debianTemp: 6, debianDla: 3 });
    const path = join(directory, 'llm-history.sqlite');
    history = new HistoryStore(path, true);
    const policy = makeOpenAiPolicy({ requestBytes: 262144 });
    const initial = history.snapshot(identity.subject, scanId);
    const selected = selectPreparedHistory(full, initial, question, policy.findings, policy.inputTokens,
      context => prepareOpenAiChat(context, policy));
    assert.equal(selected.context.report.findings.length, 35, 'legitimate full findings must not disappear to manufacture acceptance');
    assert.equal(selected.context.omission.findings, 405);
    assert.equal(full.findings.filter(mandatoryFinding).every(finding =>
      selected.context.report.findings.some(row => row.findingId === finding.findingId)), true);
    assert.equal(JSON.stringify(selected.context.report.coverage) === JSON.stringify(full.coverage), true);
    assert.equal(JSON.stringify(selected.context.report.identifierCounts) === JSON.stringify(full.identifierCounts), true);
    const binding = reportBinding(selected.context.report);
    const wire = JSON.parse(selected.prepared.body);
    const modelContext = JSON.parse(wire.messages[1].content);
    assert.equal(modelContext.report.findingCount, 440);
    assert.equal(JSON.stringify(modelContext.report.findings) === JSON.stringify(selected.context.report.findings), true,
      'model receives exact full selected facts without truncation');
    const format = wire.response_format;
    assert.equal(format.type, 'json_schema');
    assert.equal(format.json_schema.strict, true);
    const schema = format.json_schema.schema;
    assert.equal(schema.additionalProperties, false);
    assert.deepEqual([...schema.required].sort(), ['scanId', 'digest', 'platform', 'reportVersion', 'text', 'citations'].sort());
    assert.equal(schema.properties.citations.minItems, 1);
    assert.equal(schema.properties.citations.maxItems, 3);
    assert.equal(new RegExp(schema.properties.text.pattern, 'u').test(text), true);
    const sizes = selected.context.report.findings.map(finding => bytes({ ...binding, finding }));
    const histogram = { le1024: 0, from1025to2048: 0, from2049to4096: 0, gt4096: 0 };
    for (const size of sizes) {
      if (size <= 1024) histogram.le1024++;
      else if (size <= 2048) histogram.from1025to2048++;
      else if (size <= 4096) histogram.from2049to4096++;
      else histogram.gt4096++;
    }
    const payload = (index: number) => ({ ...binding, text, citations: [selected.context.report.findings[index].findingId] });
    let accepted = 0, rejected = 0, oversizedRejected = 0, browserRejected = 0;
    const failureCounts: Record<string, number> = {};
    for (let index = 0; index < sizes.length; index++) {
      try {
        const result = validateOpenAiPreparedReply(selected.prepared, policy, payload(index));
        assert.equal(result.operation, 'chat');
        accepted++;
        if (!chatReplySchema.safeParse(result.value).success) browserRejected++;
      }
      catch (error) {
        rejected++;
        if (sizes[index] > HISTORY.citationBytes) oversizedRejected++;
        const finite = diagnostic(error);
        const key = finite ? `${finite.phase}/${finite.reason}` : 'unclassified';
        failureCounts[key] = (failureCounts[key] ?? 0) + 1;
      }
    }
    t.diagnostic(JSON.stringify({ full: 440, selected: sizes.length, omitted: selected.context.omission.findings,
      citationBytes: HISTORY.citationBytes, min: Math.min(...sizes), max: Math.max(...sizes), histogram,
      accepted, rejected, oversizedRejected, browserRejected, failureCounts }));
    // RED means a model-visible citation cannot support even a valid minimal
    // Russian answer. Keep this as an acceptance test, not an expected rejection.
    const valid = payload(sizes.findIndex(size => size <= HISTORY.citationBytes));
    const result = validateOpenAiPreparedReply(selected.prepared, policy, valid);
    assert.equal(result.operation, 'chat');
    const reply = validateChatReply(valid, selected.context.report, true);
    for (const invalid of [ { ...valid, scanId: randomUUID() }, { ...valid, digest: 'sha256:' + '0'.repeat(64) },
      { ...valid, platform: 'linux/arm64' }, { ...valid, reportVersion: '0'.repeat(64) },
      { ...valid, citations: [] }, { ...valid, citations: [valid.citations[0], valid.citations[0]] },
      { ...valid, citations: ['unknown-finding'] }, { ...valid, extra: true }, { ...valid, text: 'English only response' } ]) {
      let rejected = false;
      try { validateOpenAiPreparedReply(selected.prepared, policy, invalid); } catch { rejected = true; }
      assert.equal(rejected, true, 'invalid protocol/language must be rejected');
    }
    // Preserve a failed turn in the same temporary scope before completion.
    const begin = (): { head: ReturnType<HistoryStore['snapshot']>; id: string } => {
      const head = history!.snapshot(identity.subject, scanId), id = randomUUID();
      const turn: Turn = { id, mutationId: randomUUID(), state: 'pending', question, report: binding, createdAt: Date.now(),
        inputHash: 'a'.repeat(64), consentPolicyVersion: policy.version, requestHash: selected.prepared.hash };
      return { id, head: history!.begin(identity.subject, scanId, head.epoch, head.revision, turn,
        { id, sessionId: 'b'.repeat(32), generation: 1, accessIncarnation: 'c'.repeat(32), policyVersion: policy.version,
          deadline: Date.now() + 60000, requestHash: selected.prepared.hash }) };
    };
    const failed = begin();
    assert.equal(history.fail(identity.subject, scanId, failed.head.epoch, failed.id, 'failed'), true);
    const pending = begin();
    history.finish(identity.subject, scanId, pending.head.epoch, pending.head.revision, pending.id, reply);
    history.close(); history = new HistoryStore(path);
    const retained = history.readSnapshot(identity.subject, scanId);
    assert.deepEqual(retained.turns.map(turn => turn.state), ['failed', 'completed']);
    assert.equal(retained.turns[0].id === failed.id, true);
    assert.equal(JSON.stringify(retained.turns[1].reply) === JSON.stringify(reply), true, 'reply persisted without alteration');
    assert.equal(retained.pending, null);
    assert.equal(JSON.stringify(new ReportReader(scans, true).read(identity, scanId)) === JSON.stringify(full), true);
    t.diagnostic('protocol_negative_controls=9; strict_schema=true; failed_turn_preserved=true; completed_reply_reopened=true; report_unchanged=true');
    assert.equal(rejected, 0, 'all selected real citations must accept minimal Russian prose');
    assert.equal(browserRejected, 0, 'all selected real citations must also pass the actual browser contract');
    for (let index = 0; index < sizes.length; index++) {
      const one = validateChatReply(payload(index), selected.context.report, true);
      const pending = begin();
      history.finish(identity.subject, scanId, pending.head.epoch, pending.head.revision, pending.id, one);
      const head = history.snapshot(identity.subject, scanId);
      history.decision(identity.subject, scanId, head.epoch, head.revision, { id: randomUUID(), mutationId: randomUUID(),
        kind: 'user-decision', text: 'Проверить находку вручную.', report: binding, sources: one.sources });
    }
    const top = sizes.map((size, index) => ({ size, index })).sort((a, b) => b.size - a.size).slice(0, 3);
    const triple = validateOpenAiPreparedReply(selected.prepared, policy,
      { ...binding, text, citations: top.map(row => selected.context.report.findings[row.index].findingId) });
    assert.equal(triple.operation, 'chat');
    if (triple.operation !== 'chat') assert.fail('chat result required');
    const pendingTriple = begin();
    history.finish(identity.subject, scanId, pendingTriple.head.epoch, pendingTriple.head.revision, pendingTriple.id, triple.value);
    const lines = encodeDelivery({ ...binding, epoch: pendingTriple.head.epoch, revision: pendingTriple.head.revision + 1,
      mutationId: randomUUID(), turnId: pendingTriple.id, outcome: 'completed', reply: triple.value,
      usage: { input: 20, output: 10, costMicros: 40, source: OPENAI_COST_BASIS } }).lines;
    assert.equal(lines.every(line => Buffer.byteLength(line) <= DELIVERY.lineBytes), true);
    assert.equal(Buffer.byteLength(lines.join('')) <= DELIVERY.totalBytes, true);
    const beforeReopen = history.snapshot(identity.subject, scanId);
    history.close(); history = new HistoryStore(path);
    const afterReopen = history.snapshot(identity.subject, scanId);
    assert.equal(JSON.stringify(afterReopen) === JSON.stringify(beforeReopen), true, 'all full citations/decisions retained exactly');
    assert.equal(chatHistorySchema.safeParse(historyProjection(afterReopen, binding)).success, true);
    assert.equal(afterReopen.decisions.length, 35);
    assert.equal(afterReopen.turns.filter(turn => turn.state === 'completed').length, 37);
    t.diagnostic('all35_exact_citations_and_decisions_reopened=true; maximum_openai3_sources_delivered=true; browser_history=true');
  } finally {
    history?.close(); store.onModuleDestroy();
    if (previous === undefined) delete process.env.SCAN_LEDGER_PATH; else process.env.SCAN_LEDGER_PATH = previous;
    rmSync(directory, { recursive: true, force: true });
  }
});
