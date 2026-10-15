import { randomBytes } from 'node:crypto';
import { Broker } from './broker.js';
import { PolicyStore, credentialDigest } from './policy.js';
import { AuditBuffer } from './audit.js';
import { UnixEngine, type EngineTransport } from './engine.js';
import type { PrivateBoundary } from './boundary.js';
import type { DispatchAck, EnrolledCaller, LiveIntent, Invalidation } from '../../runtime/src/live-port.js';
import type { Capture } from '../../runtime/src/contract.js';
import { CallerJournal } from '../../api/src/runtime/runtime-caller-journal.js';
// Lives ONLY in the independently confined Linux private-caller/broker deployment.
// Exported for explicit operator composition, not imported by public RuntimeApiModule.
export class EnrolledRuntimeCaller implements EnrolledCaller {
  private readonly policy = new PolicyStore();
  private readonly credential = randomBytes(32).toString('hex');
  private readonly broker: Broker;
  private ack: ((decision: DispatchAck) => void) | undefined;
  private epoch: number;
  private active = false;
  constructor(
    private readonly enrollment: {
      context: string;
      contextVersion: number;
      tapEndpoint: string;
      imageConfigSemantics: boolean;
    },
    boundary: PrivateBoundary,
    epoch: number,
    private readonly qualificationCurrent: () => boolean,
    private readonly journal: CallerJournal,
    transport: EngineTransport = new UnixEngine(),
  ) {
    this.epoch = epoch;
    const engine: EngineTransport = {
      inspect: (pin, signal, bound, dispatched) => {
        if (!this.qualificationCurrent() || signal.aborted)
          return Promise.reject(new Error('QUALIFICATION_MISSING'));
        return transport.inspect(pin, signal, bound, () => {
          if (!this.qualificationCurrent() || signal.aborted) throw new Error('QUALIFICATION_MISSING');
          dispatched();
          this.ack?.('dispatched');
          this.ack = undefined;
        });
      },
    };
    this.broker = new Broker({
      policy: this.policy,
      audit: new AuditBuffer(512),
      engine,
      boundary,
      enabled: true,
    });
  }
  private activeIntent: LiveIntent | undefined;
  async invalidate(fence: Invalidation): Promise<void> {
    this.journal.invalidate(fence);
    const i = this.activeIntent;
    if (i && i.subject === fence.subject && i.consentId === fence.consentId && i.epoch === fence.epoch)
      this.policy.unavailable();
  }
  async inspect(
    intent: LiveIntent,
    signal: AbortSignal,
    ack: (decision: DispatchAck) => void,
    permit?: string,
  ): Promise<Capture> {
    if (
      this.active ||
      !this.qualificationCurrent() ||
      this.journal.revoked(intent) ||
      intent.target.context !== this.enrollment.context ||
      intent.target.contextVersion !== this.enrollment.contextVersion ||
      intent.expiresAt <= Date.now()
    ) {
      ack('aborted');
      throw new Error('NOT_AUTHORIZED');
    }
    try {
      this.journal.consume(intent, permit);
    } catch (error) {
      ack('aborted');
      throw error;
    }
    this.epoch++;
    const now = Date.now();
    const caller = 'runtime-caller';
    const consent = 'runtime-consent';
    const grant = 'runtime-grant';
    this.policy.replace({
      version: this.epoch,
      callers: [{ id: caller, subject: intent.brokerSubject, digest: credentialDigest(this.credential) }],
      contexts: [
        {
          id: this.enrollment.context,
          version: this.enrollment.contextVersion,
          transport: 'unix',
          endpoint: this.enrollment.tapEndpoint,
          apiVersion: '1.47',
        },
      ],
      consents: [
        {
          id: consent,
          caller,
          subject: intent.brokerSubject,
          version: this.epoch,
          approved: true,
          revoked: false,
        },
      ],
      grants: [
        {
          id: grant,
          caller,
          subject: intent.brokerSubject,
          consent,
          consentVersion: this.epoch,
          context: this.enrollment.context,
          contextVersion: this.enrollment.contextVersion,
          policyVersion: this.epoch,
          version: intent.attempt,
          containerId: intent.target.containerId,
          audience: 'inspect-broker',
          scope: 'container:inspect',
          notBefore: now,
          expiresAt: Math.min(intent.expiresAt, now + 300000),
          revoked: false,
        },
      ],
    });
    this.active = true;
    this.activeIntent = intent;
    let dispatched = false;
    this.ack = (decision) => {
      if (decision === 'dispatched') {
        this.journal.dispatched(intent);
        dispatched = true;
      }
      ack(decision);
    };
    try {
      const reply = await this.broker.handle(
        { id: intent.target.containerId, context: intent.target.context, grant, credential: this.credential },
        signal,
        () => {},
        {
          binding: { nonce: intent.nonce, consentId: intent.consentId, authorityEpoch: intent.epoch },
          imageConfigSemantics: this.enrollment.imageConfigSemantics,
        },
      );
      if (this.ack) {
        this.ack('aborted');
        this.ack = undefined;
      }
      if (!this.qualificationCurrent() || signal.aborted) throw new Error('INDETERMINATE');
      if (reply.status !== 'checked' || !reply.capture)
        throw new Error(
          reply.runtimeReason ?? (reply.status === 'not_authorized' ? 'NOT_AUTHORIZED' : 'INDETERMINATE'),
        );
      if (!reply.capture.running) throw new Error('TARGET_NOT_RUNNING');
      this.journal.settle(intent, false);
      return reply.capture;
    } catch (error) {
      const definite =
        error instanceof Error &&
        ['TARGET_NOT_RUNNING', 'INVALID_RUNTIME_INPUT', 'NOT_AUTHORIZED'].includes(error.message);
      this.journal.settle(intent, dispatched && !definite);
      throw error;
    } finally {
      this.active = false;
      this.activeIntent = undefined;
      if (this.ack) {
        this.ack('aborted');
        this.ack = undefined;
      }
    }
  }
}
