import { acceptOperatorQualification, type Qualification } from '../../runtime/src/live-port.js';
import { listenApplicationCaller } from '../../runtime/src/application-ipc.js';
import { verifyPrivateBoundary } from './boundary.js';
import { EnrolledRuntimeCaller } from './enrolled-runtime.js';
import type { Target } from '../../runtime/src/contract.js';
import { CallerJournal } from '../../api/src/runtime/runtime-caller-journal.js';
// Explicit operator-only bootstrap. Ordinary main.ts/run.mjs stays unchanged and disabled.
// The review callback must validate CURRENT independent fixture AND application source/topology
// acceptance against actual identities; file modes, a digest echo or fixture candidate cannot do so.
export async function launchEnrolledRuntime(input: {
  qualification: Qualification;
  independentReview: (r: Readonly<Qualification>) => boolean;
  root: string;
  tapEndpoint: string;
  applicationSocket: string;
  applicationCredential: string;
  dispatchKey: string;
  callerJournalPath: string;
  forbiddenDatabasePaths: string[];
  imageConfigSemantics: boolean;
  allowedSubject: (subject: string, target: Readonly<Target>, brokerSubject: string) => boolean;
}) {
  const record = Object.freeze({ ...input.qualification });
  acceptOperatorQualification(record, input.independentReview);
  const current = () => {
    try {
      return Date.now() < record.expiresAt && input.independentReview(record);
    } catch {
      return false;
    }
  };
  const boundary = verifyPrivateBoundary(input.root, input.tapEndpoint);
  if (!boundary) throw new Error('QUALIFICATION_MISSING');
  const journal = new CallerJournal(input.callerJournalPath, input.dispatchKey, input.forbiddenDatabasePaths);
  const caller = new EnrolledRuntimeCaller(
    {
      context: input.qualification.context,
      contextVersion: input.qualification.contextVersion,
      tapEndpoint: input.tapEndpoint,
      imageConfigSemantics: input.imageConfigSemantics,
    },
    boundary,
    record.epoch,
    current,
    journal,
  );
  try {
    const listener = await listenApplicationCaller(
      input.applicationSocket,
      input.applicationCredential,
      caller,
      input.allowedSubject,
    );
    return {
      server: listener.server,
      close: async () => {
        try {
          await listener.close();
        } finally {
          journal.close();
        }
      },
    };
  } catch (error) {
    journal.close();
    throw error;
  }
}
