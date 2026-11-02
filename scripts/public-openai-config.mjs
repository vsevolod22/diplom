// Bounded nonsecret descriptor normalization for the isolated Python preparer.
// No environment/key/filesystem reads, subprocess, provider or Docker operation.
import { pathToFileURL } from 'node:url';
import { validateOpenAiDeployment } from './public-openai-descriptor.mjs';

export async function normalizeOpenAiConfiguration(input, output) {
  const chunks = []; let bytes = 0;
  for await (const chunk of input) {
    const b = Buffer.from(chunk); bytes += b.length;
    if (bytes > 16384) throw Error('OPENAI_CONFIG_REJECTED');
    chunks.push(b);
  }
  const selection = validateOpenAiDeployment(JSON.parse(Buffer.concat(chunks).toString('utf8')));
  output.write(JSON.stringify(selection));
}
if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  try {
    if (process.argv.length !== 2) throw Error('OPENAI_CONFIG_REJECTED');
    await normalizeOpenAiConfiguration(process.stdin, process.stdout);
  } catch { process.stderr.write('OPENAI_CONFIG_REJECTED\n'); process.exitCode = 1; }
}
