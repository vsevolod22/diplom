import { ConflictException } from '@nestjs/common';
import { PUBLIC_IMAGE_PROFILE } from '../oci/public-image-policy.js';
import type { ReportContext } from './report-context.js';

// Call only after owner lookup and full report validation. This is capability of
// the public summary endpoint, not public receipt authority: validated legacy
// reports retain their all-evidence projection and plain response contract.
export function supportsPublicSummary(report: Pick<ReportContext, 'profile'>): boolean {
  return report.profile === undefined || report.profile === PUBLIC_IMAGE_PROFILE;
}
export function requirePublicSummaryReport(report: Pick<ReportContext, 'profile'>): void {
  if (!supportsPublicSummary(report)) throw new ConflictException({ errorCode: 'LLM_SUMMARY_UNSUPPORTED_REPORT' });
}
