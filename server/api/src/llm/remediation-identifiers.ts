import { PUBLIC_ECOSYSTEMS, publicPackageName, publicPackageVersion, publicVulnerabilityKind, type PackageEcosystem } from '../worker/public-image-evidence.js';
import type { SafeFinding } from './report-context.js';
import { russianHumanTextFailure } from './russian-text.js';
import { insufficientRussian, residualTokenClass, type LanguageRejection } from './language-rejection.js';
import type { GroundingPredicate } from './provider-diagnostic.js';
import { rightBoundary, tokenWitness, type GroundingWitness } from './grounding-witness.js';

export type RemediationFields = { packageName: string; installedVersion: string; fixedVersion: string | null };
// Reuse scanner identity grammars, then fail closed on credential/instruction-shaped
// tokens. These are identifiers, never a channel for advisory prose or commands.
const dataToken = (value: string) => !/CANARY|(?:^|[-_.])(?:sk-|AKIA)|(?:ignore|disregard)[-_.]*(?:all[-_.]*)?(?:previous[-_.]*)?instructions|(?:system|developer)[-_.]*prompt|(?:api[-_]?key|password|secret|token)[:=]|[A-Za-z0-9_+/=-]{40,}/i.test(value);
export function safeRemediationFields(value: Record<string, unknown>): value is Record<string, unknown> & RemediationFields {
  return PUBLIC_ECOSYSTEMS.includes(value.ecosystem as PackageEcosystem) && publicPackageName(value.packageName, value.ecosystem as PackageEcosystem) && dataToken(value.packageName) &&
    publicPackageVersion(value.installedVersion) && dataToken(value.installedVersion) &&
    (value.fixedVersion === null || publicPackageVersion(value.fixedVersion) && dataToken(value.fixedVersion));
}

function citedRemediation(findings: readonly SafeFinding[]) {
  return findings.filter((finding): finding is SafeFinding & RemediationFields => finding.check === 'vuln' &&
    finding.identifierKind !== undefined &&
        finding.identifierKind === publicVulnerabilityKind(finding.cveId, finding.ecosystem as PackageEcosystem) && safeRemediationFields(finding));
}

// Shared finite prose endings, not arbitrary punctuation: a dot or exactly three
// dots must terminate at whitespace, end of text or a closing quote. In particular,
// neither domains nor an ellipsis followed by an identifier are prose boundaries.
const proseIdentityEnd = /(?:$|[\s;()!?«»“”"'’›—…]|[,:](?=$|\s)|(?:\.{3}|\.)(?=$|\s|[»”"'’›]))/u.source;

// Call only with current cited SafeFindings. Do not mine arbitrary JSON/free text
// for names: even CamelCase is prose unless declared in these exact fields.
export function withoutCitedPackageIdentifiers(text: string, findings: readonly SafeFinding[]): string {
  const cited = citedRemediation(findings);
  const names = new Set(cited.map(f => f.packageName));
  const versions = new Set(cited.flatMap(f => f.fixedVersion === null ? [f.installedVersion] : [f.installedVersion, f.fixedVersion]));
  const tokens = new Set([...names, ...versions]);
  // A colon is a delimiter only after an explicit Russian identity label, never
  // a general exemption for hosts, ports or paths. Keep identifier case exact.
  let prose = text.replace(
    new RegExp(/(?<![\p{L}\p{N}_./@:+~!,-])((пакет(?:а|у|ом|е)?|верси[а-яё]*)\s*:\s*[«"']?)([@A-Za-z0-9][A-Za-z0-9._+~:!,/@-]*)/u.source + `(?=${proseIdentityEnd})`, 'giu'),
    (mention: string, prefix: string, label: string, token: string) => {
      const allowed = /^пакет/iu.test(label) ? names : versions;
      const identity = allowed.has(token) ? token : token.replace(/[.,:!]+$/u, '');
      return allowed.has(identity) ? prefix + ' ' + token.slice(identity.length) : mention;
    },
  );
  // Longest first and whole-token boundaries prevent partial matches in invented
  // versions, scoped packages, domains, paths and credential-like strings.
  // Hyphens stay identity syntax here; the report-term Russian compound rule is separate.
  for (const token of [...tokens].sort((a, b) => b.length - a.length)) {
    const escaped = token.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
    prose = prose.replace(new RegExp(`(?<![\\p{L}\\p{N}_./@:+~!,\\-])${escaped}(?=${proseIdentityEnd})`, 'gu'), ' ');
  }
  return prose;
}

// Report vocabulary is not a factual claim. These finite conventional acronyms
// may occur in Russian prose without being literal source fields. Brand/package
// names still require exact cited evidence; translation/legacy rules stay unchanged.
const reportTerms = new Set(['API', 'CPU', 'CVE', 'CVSS', 'DLA', 'HTTP', 'HTTPS', 'JSON', 'RCE', 'SBOM', 'sbom', 'SQL', 'SSL', 'TEMP', 'TLS', 'UTF', 'XML', 'XSS']);
export function publicReportHumanText(text: string, findings: readonly SafeFinding[]): boolean {
  return publicReportLanguageFailure(text, findings) === undefined;
}
export function publicReportLanguageFailure(text: string, findings: readonly SafeFinding[]): LanguageRejection | undefined {
  const cited = citedRemediation(findings);
  const allowed = new Set([...reportTerms, ...cited.map(f => f.ecosystem)]);
  // Match grounded score-label punctuation, including CVSS:(9.8) and CVSS—9.8,
  // never a joined identifier such as CVSS9.8. Grounding still checks the raw score.
  const prose = withoutCitedPackageIdentifiers(text, findings).replace(
    /(?<![\p{L}\p{N}_./@:+~!,-])CVSS(?![\p{L}\p{N}_])(?=\s*[:—-]?\s*(?:\(\s*\d+(?:[.,]\d+)?\s*\)|\d+(?:[.,]\d+)?)(?:$|[\s;()!?«»“”"']|[,.:](?=$|\s)))/gu, ' ',
  ).replace(
    // Nonbreaking hyphen mirrors the existing ASCII compound boundary only before Russian letters.
    new RegExp(/(?<![\p{L}\p{N}_./@:+~!,-])[A-Za-z][A-Za-z0-9_+]*/u.source + `(?=${proseIdentityEnd}|[-‑](?=[А-Яа-яЁё]))`, 'gu'),
    token => allowed.has(token) ? ' ' : token,
  );
  // Identifiers alone are not a Russian explanation, even if every token is known.
  if ((prose.match(/[А-Яа-яЁё]/gu)?.length ?? 0) < 3) return insufficientRussian();
  return russianHumanTextFailure(prose, JSON.stringify(findings), (residual, firstLetter) => residualTokenClass(residual, firstLetter, {
    identities: new Set(cited.flatMap(f => f.fixedVersion === null ? [f.packageName, f.installedVersion] : [f.packageName, f.installedVersion, f.fixedVersion])),
    ecosystems: new Set(cited.map(f => f.ecosystem as string)), reportTerms,
  }));
}

// A script check cannot distinguish an invented numeric version from Russian
// prose. Check dotted version-like tokens and explicit identity/version labels
// separately. Bare integers remain counts unless explicitly presented as an
// identity/version or score; this is a bounded lexical guard, not a semantic fact checker.
export function groundedRemediationText(text: string, findings: readonly SafeFinding[]): boolean {
  return remediationGroundingFailure(text, findings) === undefined;
}
// Compatibility API; both callers use the same evaluator and rejection order.
export function remediationGroundingFailure(text: string, findings: readonly SafeFinding[]): GroundingPredicate | undefined {
  return remediationGroundingRejection(text, findings)?.predicate;
}
export type RemediationGroundingRejection = Readonly<{ predicate: GroundingPredicate; witness: GroundingWitness }>;
const rejection = (predicate: GroundingPredicate, witness: GroundingWitness): RemediationGroundingRejection => Object.freeze({ predicate, witness });
export function remediationGroundingRejection(text: string, findings: readonly SafeFinding[]): RemediationGroundingRejection | undefined {
  const cited = citedRemediation(findings);
  const names = new Set(cited.map(f => f.packageName));
  const versions = new Set(cited.flatMap(f => f.fixedVersion === null ? [f.installedVersion] : [f.installedVersion, f.fixedVersion]));
  const scores = new Set<number>();
  const cvssVersions = new Set<string>();
  for (const finding of findings) {
    if (finding.check !== 'vuln' || !Array.isArray(finding.assessments)) continue;
    for (const assessment of finding.assessments) {
      if (!assessment || typeof assessment !== 'object') continue;
      const cvss = assessment.cvss;
      if (!cvss || typeof cvss !== 'object') continue;
      if (cvss.scoreState === 'available' && typeof cvss.reportedScore === 'number' &&
        Number.isFinite(cvss.reportedScore) && cvss.reportedScore >= 0 && cvss.reportedScore <= 10)
        scores.add(cvss.reportedScore);
      if (cvss.versionState === 'available' && typeof cvss.version === 'string' && ['2.0', '3.0', '3.1'].includes(cvss.version))
        cvssVersions.add(cvss.version);
    }
  }
  // Only an explicit CVSS version label selects version evidence. Bare CVSS 3.1
  // remains a score claim; neither a package version nor a score grants a version.
  let invalidVersion: RemediationGroundingRejection | undefined;
  const cvssVersionSpans: Array<{ start: number; end: number }> = [];
  const checkedVersions = text.replace(
    /(?<![\p{L}\p{N}_./@:+~!,-])(?:CVSS\s+верси(?:я|и|ю|ей)|верси(?:я|и|ю|ей)\s+CVSS(?=\s|:))\s*:?\s*[«“"']?([^\s;()!?«»“”"']*)/giu,
    (mention: string, token: string, offset: number) => {
      if (!cvssVersions.has(token.replace(/[.,:]+$/u, '')))
        invalidVersion ??= rejection('cvss_version', tokenWitness(token, 'no_cited_value_match', rightBoundary(text.slice(offset + mention.length))));
      cvssVersionSpans.push({ start: offset, end: offset + mention.length });
      return ' '.repeat(mention.length);
    },
  );
  if (invalidVersion) return invalidVersion;
  const mentions = /(?<![\p{L}\p{N}_])(?<label>пакет(?:а|у|ом|е)?|верси[а-яё]*|обнов[а-яё]*(?:\s+(?:пакет(?:а|у|ом|е)?\s+)?[«"']?[@A-Za-z0-9][A-Za-z0-9._+~:!,/@-]{0,127}[»"']?)?\s+до)(?:\s+|\s*[:—-]\s*)[«"']?(?<token>[@A-Za-z0-9][A-Za-z0-9._+~:!,/@-]*)(?![\p{L}\p{N}_])/giu;
  for (const mention of text.matchAll(mentions)) {
    const { label, token } = mention.groups!;
    // Skip only version labels inside the validated CVSS phrase, not enclosing
    // package/update claims such as "пакет CVSS версии 3.1".
    if (/^верси/iu.test(label) && cvssVersionSpans.some(span => mention.index >= span.start && mention.index + mention[0].length <= span.end)) continue;
    const allowed = /^пакет/iu.test(label) ? names : versions;
    // Sentence punctuation is not part of an identity. Never normalize a version
    // component, coerce an unknown field or write this validation view back.
    if (!allowed.has(token) && !allowed.has(token.replace(/[.,:!]+$/u, '')))
      return rejection(/^пакет/iu.test(label) ? 'package_label' : /^верси/iu.test(label) ? 'version_label' : 'update_target',
        tokenWitness(token, 'no_cited_value_match', rightBoundary(text.slice(mention.index + mention[0].length))));
  }
  const groundedScore = (token: string) => {
    // Plain unsigned decimals only: no exponent, sign, range or version syntax.
    // Numeric equality permits 10.0 and 7,0 without normalizing any identifiers.
    if (!/^(?:0|[1-9]\d*)(?:[.,]\d+)?$/u.test(token)) return false;
    const value = Number(token.replace(',', '.'));
    return Number.isFinite(value) && value >= 0 && value <= 10 && scores.has(value);
  };
  const scoreEnd = /^(?:$|[\s;()!?«»“”"']|[,.:](?=$|\s))/u;
  // Parentheses must be parsed as a whole, including integer scores. Unclosed or
  // nested forms cannot fall through to the ordinary unlabelled-count allowance.
  let invalidScore: RemediationGroundingRejection | undefined;
  // Only the existing unsigned-decimal grammar permits numeric source comparison.
  const rejectedScoreWitness = (token: string, after: string) => tokenWitness(token,
    /^(?:0|[1-9]\d*)(?:[.,]\d+)?$/u.test(token) ? 'no_cited_value_match' : 'indeterminate', rightBoundary(after));
  const checkedParentheses = checkedVersions.replace(
    /(?<![\p{L}\p{N}_./@:+~!,-])(?:оценк[а-яё]*|балл[а-яё]*|CVSS)\s*[:—-]?\s*\(([^)]*)\)/giu,
    (mention: string, token: string, offset: number) => {
      if (!groundedScore(token.trim())) invalidScore ??= rejection('score_value',
        rejectedScoreWitness(token.trim(), checkedVersions.slice(offset + mention.length)));
      else if (!scoreEnd.test(checkedVersions.slice(offset + mention.length))) invalidScore ??= rejection('score_boundary',
        tokenWitness(token.trim(), 'cited_value_match', rightBoundary(checkedVersions.slice(offset + mention.length))));
      return ' '.repeat(mention.length);
    },
  );
  if (/(?<![\p{L}\p{N}_./@:+~!,-])(?:оценк[а-яё]*|балл[а-яё]*|CVSS)\s*[:—-]?\s*\(/iu.test(checkedParentheses))
    // This predicate captures only an opening prefix, not a score token.
    return rejection('score_parentheses', tokenWitness('', 'indeterminate', 'indeterminate'));
  // Inspect scores before masking package versions: a matching package version
  // is not score evidence. All replacements are local validation views only.
  const checkedScores = checkedParentheses.replace(/[+-]?(?:\d+(?:[.,]\d+)*|[.,]\d+)/gu, (token: string, offset: number) => {
    const before = checkedParentheses.slice(0, offset), after = checkedParentheses.slice(offset + token.length);
    const labelledBefore = /(?<![\p{L}\p{N}_./@:+~!,-])(?:оценк[а-яё]*|балл[а-яё]*|CVSS)\s*[:—-]?\s*$/iu.test(before);
    const labelledAfter = /^\s+балл[а-яё]*(?![\p{L}\p{N}_])/iu.test(after);
    if (!labelledBefore && !labelledAfter) return token;
    if (!groundedScore(token)) invalidScore ??= rejection('score_value', rejectedScoreWitness(token, after));
    else if (!scoreEnd.test(after) || !labelledBefore && /[\p{L}\p{N}_./@:+~!,-]$/u.test(before)) invalidScore ??= rejection('score_boundary',
      tokenWitness(token, 'cited_value_match', !scoreEnd.test(after) ? rightBoundary(after) : 'indeterminate'));
    return ' '.repeat(token.length);
  });
  const prose = withoutCitedPackageIdentifiers(checkedScores, findings);
  if (invalidScore) return invalidScore;
  const tilde = prose.indexOf('~');
  if (tilde !== -1) return rejection('unmasked_tilde', tokenWitness('~', 'indeterminate', rightBoundary(prose.slice(tilde + 1))));
  const dotted = /\d+(?:\.\d+)+/u.exec(prose);
  if (dotted) {
    const after = prose.slice(dotted.index + dotted[0].length);
    // A residual substring of a longer identity cannot establish source equality.
    const fragment = /[\p{L}\p{N}_./@:+~!,-]$/u.test(prose.slice(0, dotted.index)) || rightBoundary(after) === 'identity_continuation';
    return rejection('unmasked_dotted_number', tokenWitness(dotted[0], fragment ? 'indeterminate' :
      versions.has(dotted[0]) || names.has(dotted[0]) ? 'cited_value_match' : 'no_cited_value_match', rightBoundary(after)));
  }
  return undefined;
}
