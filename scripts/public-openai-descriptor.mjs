// Import-safe v6 contract facade. Implementation stays in the audited historical
// source-build module so frozen recovery imports need no allowlist expansion.
export { OPENAI_DEPLOYMENT, openAiSafe, openAiVolumeName, openAiRouterSelection,
  validateOpenAiDeployment, validateOpenAiBuildDeployment, validateOpenAiVolume,
  openAiEnvironment, assertNoOpenAiDockerSecret } from './public-llm-source-build.mjs';
