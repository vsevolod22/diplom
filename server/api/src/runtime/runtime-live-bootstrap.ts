import {
  acceptOperatorQualification,
  SerializedCaptureCoordinator,
  type Qualification,
} from '../../../runtime/src/live-port.js';
import { UnixApplicationCaller } from '../../../runtime/src/application-ipc.js';

// Operator-only API composition: no Engine dependency, environment switch, discovery or store init.
// This does not establish qualification; the independent reviewer must supply current acceptance.
export function createQualifiedRuntimePort(input: {
  qualification: Qualification;
  independentReview: (record: Readonly<Qualification>) => boolean;
  applicationSocket: string;
  applicationCredential: string;
  dispatchKey: string;
}): SerializedCaptureCoordinator {
  const permit = acceptOperatorQualification(input.qualification, input.independentReview);
  if (input.applicationCredential === input.dispatchKey) throw new Error('NOT_AUTHORIZED');
  const caller = new UnixApplicationCaller(
    input.applicationSocket,
    input.applicationCredential,
    input.dispatchKey,
  );
  return new SerializedCaptureCoordinator(permit, caller);
}
