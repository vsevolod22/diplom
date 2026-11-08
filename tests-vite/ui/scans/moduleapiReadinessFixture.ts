// Exercise the actual backend projection with an inert synthetic resolver. No runtime,
// credential/environment reader, provider, store or network is constructed or called.
const { moduleApiReadiness } = await import(
  /* @vite-ignore */ '../../../server/api/src/llm/' + 'public-readiness.ts'
);

type Options = {
  configured?: boolean;
  credential?: boolean;
  accounting?: boolean;
  quota?: boolean;
  history?: boolean;
};
export function moduleApiReadinessWire({
  configured = true,
  credential = true,
  accounting = true,
  quota = true,
  history = true,
}: Options = {}) {
  return moduleApiReadiness(
    {
      inspect: () => ({
        configuration: configured ? { policy: { model: 'gpt-5.4-mini' } } : null,
        runtime: accounting ? {} : null,
      }),
      credentialReady: () => credential,
    },
    quota,
    history,
  );
}
