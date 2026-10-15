import { binding } from './contract.mjs';

// At-most-once observation admission, NOT intake replay or durable operator authority.
// Production uses the module-shared instance; explicit instances are controlled-test scopes.
export class CaptureAuthority {
  #used = new Set();
  used(value) {
    binding(value);
    return this.#used.has(`nonce:${value.nonce}`) || this.#used.has(`consent:${value.consentId}`);
  }
  consume(value) {
    if (this.used(value) || this.#used.size >= 256) return false;
    // Synchronous: both identifiers are reserved before any runner/await/first observation.
    this.#used.add(`nonce:${value.nonce}`);
    this.#used.add(`consent:${value.consentId}`);
    return true;
  }
}

// Shared across collectors/supervisor invocations in this loaded module, never silently pruned.
// New processes or separately loaded module copies reset it. External operator must prevent replay.
export const processCaptureAuthority = new CaptureAuthority();
