// @vitest-environment node
import { execFile } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import { promisify } from 'node:util';
import { expect, it } from 'vitest';

// BlockNote/ProseMirror selection and input rules require a real layout engine.
// Do not replace the editor with a textarea or claim jsdom events prove WYSIWYG.
it('qualifies the real BlockNote composer and widget in isolated Chromium at 375/1280px', async () => {
  const root = fileURLToPath(new URL('../../../', import.meta.url));
  const result = await promisify(execFile)(process.execPath, ['tests-e2e/blocknote-chat-layout.mjs'], {
    cwd: root,
    timeout: 150_000,
    maxBuffer: 2 * 1024 * 1024,
  }).catch((error: Error & { stdout?: string; stderr?: string }) => {
    throw new Error(`${error.message}\n${error.stdout ?? ''}\n${error.stderr ?? ''}`);
  });
  expect(result.stdout).toContain('real Chromium / ephemeral loopback / synthetic fixture only');
  expect(result.stdout).toContain('"failures": []');
}, 160_000);
