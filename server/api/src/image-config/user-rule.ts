import type { Classification, Coverage } from './contract.js';

export interface UserRuleResult { coverage: Coverage; classification?: Classification }

export function evaluateUser(user: string | undefined): UserRuleResult {
  if (user === undefined || user === '') return { coverage: { outcome: 'checked' }, classification: 'DEFAULT_ROOT' };
  if (!/^[0-9]{1,10}(?::[0-9]{1,10})?$/.test(user)) {
    return { coverage: { outcome: 'unsupported', reason: 'USER_NOT_RESOLVABLE' } };
  }
  const [uid, gid] = user.split(':').map(Number);
  if (uid > 4_294_967_295 || (gid !== undefined && gid > 4_294_967_295)) {
    return { coverage: { outcome: 'unsupported', reason: 'USER_NOT_RESOLVABLE' } };
  }
  return uid === 0 ? { coverage: { outcome: 'checked' }, classification: 'NUMERIC_ROOT' } :
    { coverage: { outcome: 'checked' } };
}
