import { createRoot } from 'react-dom/client';

import { SafeMarkdown } from '../src/features/scans/safeMarkdown';

// Test-only adversarial input: the actual chat schema rejects HTML/unsafe URLs before rendering.
const samples = [
  { id: 'html', text: '<script>window.__task16Executed = true</script><img src=x onerror="window.__task16Executed = true">' },
  { id: 'urls', text: '[JS](javascript:alert(1)) [DATA](data:text/html,unsafe) [FILE](file:///synthetic) [SAFE](https://example.invalid/synthetic)' },
  { id: 'unfinished', text: '- ```js\n  window.__task16Executed = true\n  незакрытый список' },
  { id: 'tilde', text: '1. ~~~text\n   синтетический незакрытый fence' },
  { id: 'closed', text: '```js\nwindow.__task16Executed = true\n```' },
];

createRoot(document.getElementById('root')!).render(
  <main style={{ maxWidth: '100%', overflowWrap: 'anywhere' }}>
    <h1>SYNTHETIC · actual SafeMarkdown renderer, not backend output</h1>
    {samples.map((sample) => (
      <section key={sample.id} data-testid={sample.id} aria-label={`Synthetic ${sample.id}`}>
        <h2>{sample.id}</h2>
        <SafeMarkdown text={sample.text} />
      </section>
    ))}
  </main>,
);
