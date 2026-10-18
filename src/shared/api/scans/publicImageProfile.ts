import { z } from 'zod';
import { advisorySource } from './vulnAdvisory';
export const reportSeveritySource = z.union([advisorySource, z.enum(['debian', 'pypi', 'pip', 'go-vulndb', 'rustsec', 'cargo', 'maven', 'nuget', 'composer', 'php-security-advisories'])]);

export const PUBLIC_IMAGE_PROFILE = 'public-hub-amd64-v1';
export const PUBLIC_IMAGE_RESOURCE_POLICY = 'public-hub-resources-v1';
export const REPORT_ECOSYSTEMS = ['apk', 'deb', 'rpm', 'npm', 'pypi', 'gem', 'gomod', 'cargo', 'maven', 'composer', 'nuget'] as const;
export const reportEcosystem = z.enum(REPORT_ECOSYSTEMS);
export type ReportEcosystem = z.infer<typeof reportEcosystem>;
const part = '[a-z0-9]+(?:[._-][a-z0-9]+)*';
const repository = `${part}/${part}`;
// Explicit canonical Docker Hub official (library/name) or namespace/name only.
// Parsing a reference is syntax validation, never a statement of server admission.
export const publicImageReference = z.string().max(512).regex(new RegExp(`^registry-1\\.docker\\.io/${repository}(?::[A-Za-z0-9_][A-Za-z0-9_.-]{0,127}|@sha256:[a-f0-9]{64})$`))
  .refine(value => value.slice('registry-1.docker.io/'.length).split(/[:@]/)[0].length <= 255 && value.slice('registry-1.docker.io/'.length).split(/[:@]/)[0].split('/').every(segment => segment.length <= 128));
export const pinnedPublicImage = publicImageReference.refine(value => /@sha256:[a-f0-9]{64}$/.test(value));
export const reportOs = z.strictObject({ name: z.enum(['alpine', 'debian', 'ubuntu', 'redhat', 'centos', 'rocky', 'alma', 'oracle', 'amazon']), version: z.string().min(1).max(80).regex(/^[0-9]+(?:\.[0-9]+){0,3}$/) });
export const publicProfile = z.literal(PUBLIC_IMAGE_PROFILE);
export const legacyReportImage = z.union([z.string().regex(/^registry-1\.docker\.io\/library\/alpine@sha256:[a-f0-9]{64}$/),
  z.literal('registry-1.docker.io/library/nginx@sha256:0dcc88822d45581e65ae329f8be769762bf628d3b2bb7d2a077d4aa5c98b30e3'),
  z.literal('registry-1.docker.io/library/nginx@sha256:b17b00f7ef0038aeb11362157f49006a130628ee711cefcced871405d046f114')]);
export const validReportImage = (image: string, profile?: typeof PUBLIC_IMAGE_PROFILE) => profile === PUBLIC_IMAGE_PROFILE || legacyReportImage.safeParse(image).success;
