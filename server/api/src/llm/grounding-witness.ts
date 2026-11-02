// Diagnostic-only lexical observations, never validation or additional citation authority.
// Source relation is restricted to the rejecting check's existing evidence type:
// its identity comparison, or its unsigned-decimal numeric score comparison.
// A match does not prove the surrounding claim is valid; fragments stay indeterminate.
export const GROUNDING_SOURCE_RELATIONS = Object.freeze(['cited_value_match', 'no_cited_value_match', 'indeterminate'] as const);
export const GROUNDING_LEXICAL_CLASSES = Object.freeze(['unsigned_decimal', 'signed_decimal', 'dotted_numeric', 'ascii_identity', 'tilde', 'indeterminate'] as const);
export const GROUNDING_BOUNDARY_CLASSES = Object.freeze(['end', 'whitespace', 'sentence_punctuation', 'typography', 'identity_continuation', 'other', 'indeterminate'] as const);
export type GroundingSourceRelation = typeof GROUNDING_SOURCE_RELATIONS[number];
export type GroundingBoundaryClass = typeof GROUNDING_BOUNDARY_CLASSES[number];
export type GroundingWitness = Readonly<{
  sourceRelation: GroundingSourceRelation;
  lexicalClass: typeof GROUNDING_LEXICAL_CLASSES[number];
  boundaryClass: GroundingBoundaryClass;
}>;

// Reconstruct only own scalar data fields; partial, accessor and extra-key metadata
// is not a witness. Never retain the caller object or invoke its property getters.
export function finiteGroundingWitness(value: unknown): GroundingWitness | undefined {
  if (!value || typeof value !== 'object') return undefined;
  try {
    const keys = Reflect.ownKeys(value);
    if (keys.length !== 3 || !['sourceRelation', 'lexicalClass', 'boundaryClass'].every(key => keys.includes(key))) return undefined;
    const sourceRelation = Object.getOwnPropertyDescriptor(value, 'sourceRelation')?.value;
    const lexicalClass = Object.getOwnPropertyDescriptor(value, 'lexicalClass')?.value;
    const boundaryClass = Object.getOwnPropertyDescriptor(value, 'boundaryClass')?.value;
    if (!GROUNDING_SOURCE_RELATIONS.includes(sourceRelation) || !GROUNDING_LEXICAL_CLASSES.includes(lexicalClass) ||
      !GROUNDING_BOUNDARY_CLASSES.includes(boundaryClass)) return undefined;
    return Object.freeze({ sourceRelation, lexicalClass, boundaryClass });
  } catch { return undefined; }
}

// Right edge in the rejecting check's local validation view, not a raw response
// offset. Parenthesized scores inspect the edge after the closing parenthesis.
// A check on a left edge, or without a unique token, uses indeterminate.
export function rightBoundary(after: string): GroundingBoundaryClass {
  if (!after) return 'end';
  if (/^\s/u.test(after)) return 'whitespace';
  if (/^[—…]/u.test(after)) return 'typography';
  if (/^(?:[;()!?«»“”"']|[,.:](?=$|\s))/u.test(after)) return 'sentence_punctuation';
  if (/^[\p{L}\p{N}_./@:+~!,-]/u.test(after)) return 'identity_continuation';
  return 'other';
}
export function tokenWitness(token: string, sourceRelation: GroundingSourceRelation,
  boundaryClass: GroundingBoundaryClass): GroundingWitness {
  let lexicalClass: GroundingWitness['lexicalClass'] = 'indeterminate';
  // Existing reply limits bound callers; independently cap this optional classifier.
  if (token.length <= 256) {
    if (/^(?:0|[1-9]\d*)(?:[.,]\d+)?$/u.test(token)) lexicalClass = 'unsigned_decimal';
    else if (/^[+-]\d+(?:[.,]\d+)?$/u.test(token)) lexicalClass = 'signed_decimal';
    else if (/^\d+(?:\.\d+)+$/u.test(token)) lexicalClass = 'dotted_numeric';
    else if (token === '~') lexicalClass = 'tilde';
    else if (/^[@A-Za-z0-9][A-Za-z0-9._+~:!,/@-]*$/u.test(token)) lexicalClass = 'ascii_identity';
  }
  return Object.freeze({ sourceRelation, lexicalClass, boundaryClass });
}
