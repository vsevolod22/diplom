import type { HistoryContext } from './history-context.js';

// Called only after full history/source validation. Intern exact source records,
// never findings by ID: historical bindings or changed details must stay distinct.
// The retained store and authoritative context are not mutated or truncated.
export function moduleApiHistoryWire(context: HistoryContext): unknown {
  const catalog: { id: string; source: unknown }[] = [];
  const ids = new Map<string, string>();
  const entry = (value: unknown) => {
    const record = value as Record<string, unknown> & { sources: unknown[] };
    const { sources, ...rest } = record;
    const sourceIds = sources.map(source => {
      const key = JSON.stringify(source);
      let id = ids.get(key);
      if (id === undefined) {
        id = `history-source-${catalog.length}`;
        ids.set(key, id);
        catalog.push({ id, source });
      }
      return id;
    });
    return { ...rest, sourceIds };
  };
  const history = { ...context.history,
    userTurns: context.history.userTurns.map(entry),
    decisions: context.history.decisions.map(entry),
    sourceCatalog: catalog,
  };
  const compact = { ...context, history };
  // Empty and already-small histories retain the original compatibility shape.
  return Buffer.byteLength(JSON.stringify(compact)) < Buffer.byteLength(JSON.stringify(context)) ? compact : context;
}
