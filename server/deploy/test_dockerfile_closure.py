"""Source-only image closure checks; no imports of application code or Docker calls."""
import json
from pathlib import Path
import re
import shlex
import unittest


ROOT = Path(__file__).resolve().parents[2]
API = Path('server/api/src')
ENTRYPOINTS = {
    'api': ('src/main.ts', 'src/oci/nginx-local.main.ts',
            'src/worker/verify-vuln-db-release.ts'),
    'worker': ('src/worker/worker.main.ts', 'src/worker/nginx-local-worker.main.ts',
               'src/worker/verify-vuln-db-release.ts'),
}
COPY_SOURCES = {
    'pnpm-lock.yaml', 'pnpm-workspace.yaml', 'package.json',
    'server/api/package.json', 'server/api/src', 'server/api/tsconfig.json',
    'server/runtime/src', 'server/deploy/trust/db-signing-key.pub.pem',
}
# Lexical check for literal relative module specifiers. The actual image tsc run
# remains authoritative for TypeScript resolution and package/type correctness.
IMPORT = re.compile(r'''(?:from\s*|import\s*\(\s*|import\s*|require\(\s*)['"]([^'"]+)['"]''')


def copies(text):
    result = []
    for line in text.splitlines():
        if line.startswith('COPY ') and not line.startswith('COPY --from='):
            tokens = shlex.split(line)[1:]
            result.extend(tokens[:-1])
    return result


def production_graph(entries):
    seen = set()

    def visit(path):
        path = path.resolve()
        if path in seen:
            return
        if not path.is_relative_to(ROOT):
            raise AssertionError('Module escaped repository')
        seen.add(path)
        for specifier in IMPORT.findall(path.read_text()):
            if not specifier.startswith('.'):
                continue
            target = (path.parent / specifier).resolve()
            candidates = [target]
            if target.suffix == '.js':
                candidates.insert(0, target.with_suffix('.ts'))
            elif target.suffix == '.mjs':
                candidates.insert(0, target.with_suffix('.mts'))
            found = next((candidate for candidate in candidates if candidate.is_file()), None)
            if found is None:
                raise AssertionError(f'Unresolved module: {path.relative_to(ROOT)} -> {specifier}')
            if found.suffix in ('.ts', '.mts', '.js', '.mjs'):
                visit(found)

    for entry in entries:
        visit(ROOT / 'server/api' / entry)
    return {path.relative_to(ROOT) for path in seen}


def missing_sources(graph, sources):
    roots = [Path(source) for source in sources]
    return sorted(path for path in graph
                  if not any(path == source or source in path.parents for source in roots))


class DockerfileClosureTests(unittest.TestCase):
    def test_only_explicit_public_source_roots_are_copied(self):
        for role in ENTRYPOINTS:
            with self.subTest(role=role):
                text = (ROOT / f'server/deploy/{role}.Dockerfile').read_text()
                self.assertEqual(set(copies(text)), COPY_SOURCES)
                self.assertEqual(len(copies(text)), len(COPY_SOURCES))

    def test_production_typecheck_roots_match_default_local_and_verifier(self):
        for role, entries in ENTRYPOINTS.items():
            with self.subTest(role=role):
                text = (ROOT / f'server/deploy/{role}.Dockerfile').read_text()
                match = re.search(r"'(\{\"extends\":.*?\})' > server/api/tsconfig.deploy.json", text)
                self.assertIsNotNone(match, 'Image must declare its production typecheck roots')
                config = json.loads(match.group(1))
                self.assertEqual(config, {'extends': './tsconfig.json',
                                          'files': list(entries), 'include': []})
                self.assertIn('exec tsc --project tsconfig.deploy.json', text)
                self.assertIn('NODE_OPTIONS=--max-old-space-size=1024', text)
                self.assertIn('--child-concurrency=1 --network-concurrency=4', text)

    def test_transitive_production_imports_are_present_in_each_image(self):
        for role, entries in ENTRYPOINTS.items():
            with self.subTest(role=role):
                text = (ROOT / f'server/deploy/{role}.Dockerfile').read_text()
                graph = production_graph(entries)
                self.assertFalse(missing_sources(graph, copies(text)))
                self.assertFalse(any('.test.' in str(path) for path in graph))
                self.assertFalse(any(path.is_relative_to('server/broker') or
                                     path.is_relative_to('src') for path in graph))

    def test_missing_runtime_copy_is_detected(self):
        graph = production_graph(ENTRYPOINTS['api'])
        self.assertIn(Path('server/runtime/src/contract.ts'), graph)
        self.assertIn(Path('server/runtime/src/contract.ts'),
                      missing_sources(graph, COPY_SOURCES - {'server/runtime/src'}))

    def test_build_checks_do_not_start_application_and_keep_runtime_identity(self):
        for role in ENTRYPOINTS:
            with self.subTest(role=role):
                text = (ROOT / f'server/deploy/{role}.Dockerfile').read_text()
                self.assertIn("(':memory:').close()", text)
                self.assertIn('USER 65532:65532', text)
                for line in text.splitlines():
                    if line.startswith(('RUN ', '    && ')):
                        self.assertNotIn('node --import', line)
                        self.assertNotIn('tsx src/', line)
                if role == 'worker':
                    self.assertIn('COPY --from=scanner /usr/local/bin/trivy /usr/local/bin/trivy', text)
                    self.assertIn('&& trivy --version', text)


if __name__ == '__main__':
    unittest.main()
