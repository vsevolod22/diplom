import { lstatSync, realpathSync } from 'node:fs';
import { dirname, isAbsolute, normalize } from 'node:path';
const verified = new WeakSet<object>();
export interface PrivateBoundary {
  readonly root: string;
  readonly endpoint: string;
}
function check(root: string, endpoint: string): boolean {
  try {
    const uid = process.getuid?.();
    if (
      uid === undefined ||
      !isAbsolute(root) ||
      normalize(root) !== root ||
      realpathSync(root) !== root ||
      dirname(endpoint) !== root ||
      realpathSync(endpoint) !== endpoint
    )
      return false;
    const directory = lstatSync(root);
    const socket = lstatSync(endpoint);
    return (
      directory.isDirectory() &&
      directory.uid === uid &&
      (directory.mode & 0o777) === 0o700 &&
      socket.isSocket() &&
      socket.uid === uid &&
      (socket.mode & 0o777) === 0o600
    );
  } catch {
    return false;
  }
}
// A measured local filesystem boundary, not a production/whole-topology attestation.
// Only an operator-owned disposable harness calls this; production entrypoint is off.
export function verifyPrivateBoundary(root: string, endpoint: string): PrivateBoundary {
  if (!check(root, endpoint)) throw new Error('private_boundary_unverified');
  const permit = Object.freeze({ root, endpoint });
  verified.add(permit);
  return permit;
}
export function boundaryCurrent(permit: PrivateBoundary | undefined, endpoint: string): boolean {
  return !!permit && verified.has(permit) && permit.endpoint === endpoint && check(permit.root, endpoint);
}
