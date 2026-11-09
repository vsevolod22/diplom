import assert from 'node:assert/strict';
import test from 'node:test';
import { moduleApiHistoryWire } from '../moduleapi-history-wire.js';
import { createModuleApiPolicy, MODULEAPI_MODEL, MODULEAPI_PROMPTS } from '../moduleapi-policy.js';
import { prepareModuleApiChat } from '../moduleapi-prepared-request.js';
import { reportBinding } from '../history-contract.js';
import { openAiHistory, openAiReport, openAiSettings } from './openai-core.fixture.js';

const source = { ...reportBinding(openAiReport), finding: openAiReport.findings[0] };
const id = (n: number) => `00000000-0000-4000-8000-${String(n).padStart(12, '0')}`;
function context() {
  return { ...structuredClone(openAiHistory), history: { ...structuredClone(openAiHistory.history),
    userTurns: Array.from({ length: 8 }, (_, n) => ({ id: id(n + 1), text: 'Что проверить?',
      report: reportBinding(openAiReport), sources: [structuredClone(source)], sourceState: 'same-report' })),
    decisions: [{ id: id(20), mutationId: id(21), kind: 'user-decision', text: 'Проверить находку.',
      report: reportBinding(openAiReport), sources: [structuredClone(source)], sourceState: 'same-report' }],
  } };
}
test('prepared ModuleAPI wire interns sources losslessly without changing questions, decisions or authoritative context', () => {
  const input = context(), original = structuredClone(input);
  const policy = createModuleApiPolicy({ ...openAiSettings, model: MODULEAPI_MODEL, retention: 'unknown', monetaryLimit: 'capped' }, MODULEAPI_PROMPTS);
  assert.ok(policy);
  const prepared = prepareModuleApiChat(input, policy);
  const wire = JSON.parse(JSON.parse(prepared.body).messages[1].content);
  assert.equal(wire.history.sourceCatalog.length, 1);
  const catalog = new Map(wire.history.sourceCatalog.map((s: { id: string; source: unknown }) => [s.id, s.source]));
  for (const name of ['userTurns', 'decisions'] as const) {
    const restored = wire.history[name].map((entry: { sourceIds: string[] }) => {
      const { sourceIds, ...rest } = entry;
      return { ...rest, sources: sourceIds.map(id => { assert.ok(catalog.has(id)); return catalog.get(id); }) };
    });
    assert.deepEqual(restored, input.history[name]);
  }
  assert.deepEqual(input, original);
  assert.ok(Buffer.byteLength(JSON.stringify(wire)) < Buffer.byteLength(JSON.stringify(input)));
  assert.equal(wire.history.userTurns.length, 8);
  assert.equal(wire.history.decisions.length, 1);
  assert.equal(prepared.reserve.input, Buffer.byteLength(prepared.body) + 1024);
});
test('source catalog never aliases changed or historical sources by finding ID; invalid history still fails before interning', () => {
  const input = context();
  const historical = { ...structuredClone(source), reportVersion: 'f'.repeat(64) };
  input.history.userTurns[1].sources = [historical];
  input.history.userTurns[1].report = { ...input.history.userTurns[1].report, reportVersion: historical.reportVersion };
  input.history.userTurns[1].sourceState = 'historical-unresolved';
  const wire = moduleApiHistoryWire(input) as { history: { sourceCatalog: { source: unknown }[]; userTurns: { sourceIds: string[] }[] } };
  assert.equal(wire.history.sourceCatalog.length, 2);
  assert.notEqual(wire.history.userTurns[0].sourceIds[0], wire.history.userTurns[1].sourceIds[0]);
  const policy = createModuleApiPolicy({ ...openAiSettings, model: MODULEAPI_MODEL, retention: 'unknown', monetaryLimit: 'capped' }, MODULEAPI_PROMPTS);
  assert.ok(policy);
  input.history.userTurns[0].sources[0].finding.findingId = 'forged';
  assert.throws(() => prepareModuleApiChat(input, policy));
  assert.deepEqual(moduleApiHistoryWire(openAiHistory), openAiHistory);
});
