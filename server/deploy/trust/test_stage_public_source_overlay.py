import importlib.util
import json
import os
import shutil
import tempfile
import unittest
from pathlib import Path
from unittest import mock

MODULE = Path(__file__).with_name('stage_public_source_overlay.py')
spec = importlib.util.spec_from_file_location('stage_public_source_overlay', MODULE)
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)


class OverlayTests(unittest.TestCase):
    def setUp(self):
        # Synthetic files only; /private/tmp avoids macOS's /tmp symlink.
        self.temp = tempfile.TemporaryDirectory(prefix='dip-overlay-mocks-', dir='/private/tmp')
        self.repo = Path(self.temp.name) / 'repo'
        self.outputs = []
        for path in module.ENTRYPOINTS:
            self.source(path, 'export const initializer = () => undefined;\n')
        self.source('server/runtime/src/contract.ts', 'export const version = 1;\n')

    def tearDown(self):
        for output in self.outputs:
            if output.is_symlink():
                output.unlink()
            elif output.exists():
                shutil.rmtree(output)
        self.temp.cleanup()

    def source(self, path, text):
        target = self.repo / path
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(text)
        return target

    def output(self, kind):
        suffix = Path(self.temp.name).name + '-' + str(len(self.outputs))
        value = Path('/private/tmp') / ('dip-public-source-overlay-' + kind + '-' + suffix)
        self.outputs.append(value)
        return value

    def plan(self):
        output = self.output('plan')
        return module.inventory(str(self.repo), str(output))

    def stage(self, plan=None):
        plan = plan or self.plan()
        return module.stage(str(self.repo), plan['inventory'], plan['inventory_sha256'],
                            str(self.output('context')))

    def test_inventory_is_deterministic_and_has_exact_two_roots(self):
        first, _ = module.collect(str(self.repo))
        second, _ = module.collect(str(self.repo))
        self.assertEqual(first, second)
        self.assertEqual(first['roots'], list(module.ROOTS))
        self.assertEqual(len(first['files']), 5)
        self.assertFalse(any(first['qualification'].values()))

    def test_mjs_is_included_and_json_assets_are_not_opened(self):
        self.source('server/api/src/worker/policy.mjs', 'export const policy = 1;\n')
        self.source('server/api/src/worker/config.json', 'synthetic-not-source')
        value, _ = module.collect(str(self.repo))
        names = {f['path'] for f in value['files']}
        self.assertIn('server/api/src/worker/policy.mjs', names)
        self.assertNotIn('server/api/src/worker/config.json', names)

    def test_exclusions_happen_before_content_reads(self):
        excluded = ['server/api/src/.env', 'server/api/src/.env.ts',
                    'server/api/src/private-key.ts', 'server/api/src/key.pem',
                    'server/api/src/state.sqlite', 'server/api/src/x.test.ts',
                    'server/api/src/x.spec.mjs', 'server/api/src/x.seed.ts',
                    'server/api/src/nginx-proof.main.ts',
                    'server/api/src/tests/a.ts', 'server/api/src/fixtures/a.ts',
                    'server/api/src/testfixtures/a.ts', 'server/api/src/test-harness/a.ts',
                    'server/api/src/init-tools/a.ts', 'server/api/src/assets/a.ts',
                    'server/runtime/src/proofoutputs/a.ts']
        for name in excluded + list(module.EXCLUDED_FILES):
            self.source(name, 'synthetic excluded data')
        opened = []
        original = module.read_regular

        def read(directory, name, *args, **kwargs):
            opened.append(name)
            return original(directory, name, *args, **kwargs)

        with mock.patch.object(module, 'read_regular', side_effect=read):
            value, _ = module.collect(str(self.repo))
        self.assertEqual(len(value['files']), 5)
        self.assertEqual(len(opened), 5)
        self.assertNotIn('a.ts', opened)
        self.assertNotIn('.env.ts', opened)
        self.assertNotIn('private-key.ts', opened)
        self.assertNotIn('archive-smoke.ts', opened)
        self.assertNotIn('scans.config.browser.ts', opened)
        self.assertNotIn('verify-vuln-db-release.ts', opened)

    def test_foreign_notices_and_root_env_are_outside_enumeration(self):
        self.source('docs/notices/shadcn-21st.md', 'synthetic notice')
        self.source('public/notices/shadcn-21st-LICENSE.txt', 'synthetic notice')
        self.source('.env.local', 'synthetic env')
        seen = []
        original = module.beneath_directory

        def descend(root, parts):
            seen.append(parts)
            return original(root, parts)

        with mock.patch.object(module, 'beneath_directory', side_effect=descend):
            module.collect(str(self.repo))
        self.assertEqual(seen, [root.split('/') for root in module.ROOTS])

    def test_production_initialization_modules_and_functions_are_preserved(self):
        path = 'server/api/src/runtime/runtime-history-initialize.ts'
        self.source(path, 'export function initializeHistory() { return 1; }\n')
        value, _ = module.collect(str(self.repo))
        self.assertIn(path, {f['path'] for f in value['files']})

    def test_source_symlink_is_refused_before_content_read(self):
        target = self.repo / 'server/api/src/link.ts'
        target.symlink_to(self.repo / 'server/runtime/src/contract.ts')
        with self.assertRaises(module.Refusal):
            module.collect(str(self.repo))

    def test_source_directory_symlink_is_refused(self):
        target = self.repo / 'server/api/src/linked'
        target.symlink_to(self.repo / 'server/runtime/src', target_is_directory=True)
        with self.assertRaises((OSError, module.Refusal)):
            module.collect(str(self.repo))

    def test_repo_symlink_parent_is_refused(self):
        link = Path(self.temp.name) / 'linked-repo'
        link.symlink_to(self.repo, target_is_directory=True)
        with self.assertRaises(OSError):
            module.collect(str(link))

    def test_hardlinked_source_is_refused(self):
        os.link(self.repo / 'server/runtime/src/contract.ts', self.repo / 'server/api/src/link.ts')
        with self.assertRaises(module.Refusal):
            module.collect(str(self.repo))

    def test_fifo_source_is_refused_without_opening(self):
        os.mkfifo(self.repo / 'server/api/src/fifo.ts')
        with self.assertRaises(module.Refusal):
            module.collect(str(self.repo))

    def test_source_size_bound(self):
        with mock.patch.object(module, 'MAX_FILE', 1):
            with self.assertRaises(module.Refusal):
                module.collect(str(self.repo))

    def test_source_count_and_total_bounds(self):
        for field, limit in [('MAX_FILES', 1), ('MAX_BYTES', 1), ('MAX_PATHS', 1)]:
            with self.subTest(field=field), mock.patch.object(module, field, limit):
                with self.assertRaises(module.Refusal):
                    module.collect(str(self.repo))

    def test_missing_entrypoint_refuses(self):
        (self.repo / module.ENTRYPOINTS[0]).unlink()
        with self.assertRaises(module.Refusal):
            module.collect(str(self.repo))

    def test_missing_runtime_source_refuses(self):
        (self.repo / 'server/runtime/src/contract.ts').unlink()
        with self.assertRaises(module.Refusal):
            module.collect(str(self.repo))

    def test_inventory_output_is_exclusive_and_private(self):
        plan = self.plan()
        parent = Path(plan['inventory']).parent
        self.assertEqual(parent.stat().st_mode & 0o777, 0o700)
        self.assertEqual(Path(plan['inventory']).stat().st_mode & 0o777, 0o444)
        with self.assertRaises(FileExistsError):
            module.inventory(str(self.repo), str(parent))

    def test_output_parent_symlink_and_traversal_refuse(self):
        for output in ['/tmp/dip-public-source-overlay-plan-x',
                       '/private/tmp/../tmp/dip-public-source-overlay-plan-x',
                       '/private/tmp/other-name']:
            with self.subTest(output=output), self.assertRaises(module.Refusal):
                module.output_name(output, 'plan')
        link = Path(self.temp.name) / 'parent-link'
        link.symlink_to(self.repo, target_is_directory=True)
        with self.assertRaises(OSError):
            module.open_directory(str(link))

    def test_tampered_inventory_pin_refuses(self):
        plan = self.plan()
        with self.assertRaises(module.Refusal):
            module.stage(str(self.repo), plan['inventory'], '0' * 64,
                         str(self.output('context')))

    def test_arbitrary_inventory_file_is_not_opened(self):
        with mock.patch.object(module, 'read_regular') as read:
            with self.assertRaises(module.Refusal):
                module.load_inventory(str(self.repo / '.env.local'), '0' * 64)
        read.assert_not_called()

    def test_inventory_file_symlink_refuses(self):
        plan = self.plan()
        path = Path(plan['inventory'])
        path.unlink()
        path.symlink_to(self.repo / 'server/runtime/src/contract.ts')
        with self.assertRaises(module.Refusal):
            module.load_inventory(str(path), plan['inventory_sha256'])

    def test_changed_or_added_source_refuses_before_output_creation(self):
        for change in ('change', 'add'):
            with self.subTest(change=change):
                plan = self.plan()
                path = module.ENTRYPOINTS[0] if change == 'change' else 'server/api/src/new.ts'
                self.source(path, 'export const changed = 2;\n')
                output = self.output('context')
                with self.assertRaises(module.Refusal):
                    module.stage(str(self.repo), plan['inventory'], plan['inventory_sha256'], str(output))
                self.assertFalse(output.exists())

    def test_stage_has_exact_source_and_generated_file_set(self):
        plan = self.plan()
        result = self.stage(plan)
        output = Path(result['context'])
        files = {p.relative_to(output).as_posix() for p in output.rglob('*') if p.is_file()}
        self.assertEqual(files, set(module.ENTRYPOINTS) | {'server/runtime/src/contract.ts',
            'Dockerfile.api', 'Dockerfile.worker', '.dockerignore', 'overlay-manifest.json'})
        receipt = json.loads((output / 'overlay-manifest.json').read_bytes())
        self.assertEqual(receipt['context_sha256'], result['context_sha256'])
        self.assertEqual(receipt['source_sha256'], plan['source_sha256'])
        self.assertFalse(receipt['leftover_parent_files_removed'])
        self.assertFalse(receipt['build_executed'])
        self.assertFalse(any(receipt['qualification'].values()))

    def test_dockerfiles_only_use_pinned_from_workdir_and_source_copy(self):
        for image in (module.API_IMAGE, module.WORKER_IMAGE):
            lines = module.dockerfile(image).decode().splitlines()
            self.assertEqual(lines[0], 'FROM ' + image)
            self.assertEqual(lines[1], 'WORKDIR /app/server/api')
            self.assertEqual(lines[2:], ['COPY server/api/src /app/server/api/src',
                                        'COPY server/runtime/src /app/server/runtime/src'])
            self.assertNotIn('RUN', {line.split()[0] for line in lines})
            for directive in ('ENV', 'ARG', 'USER', 'CMD', 'ENTRYPOINT'):
                self.assertNotIn(directive, {line.split()[0] for line in lines})

    def test_ignorefile_is_exact_filename_allowlist_with_parent_directories(self):
        raw = module.ignorefile(['server/api/src/main.ts', 'Dockerfile.api']).decode()
        self.assertEqual(raw.splitlines()[0], '**')
        self.assertIn('!server/api/src/main.ts\n', raw)
        self.assertIn('!server/api/src/\n', raw)
        self.assertNotIn('!server/api/src/**', raw)
        self.assertNotIn('!server/runtime/src/**', raw)
        self.assertNotIn('overlay-manifest.json', raw)

    def test_existing_context_is_never_overwritten(self):
        plan = self.plan()
        output = self.output('context')
        output.mkdir(mode=0o700)
        sentinel = output / 'sentinel'
        sentinel.write_text('untouched')
        with self.assertRaises(FileExistsError):
            module.stage(str(self.repo), plan['inventory'], plan['inventory_sha256'], str(output))
        self.assertEqual(sentinel.read_text(), 'untouched')

    def test_write_failure_retains_own_partial_context(self):
        plan = self.plan()
        output = self.output('context')
        original = module.write_new
        count = 0

        def write(directory, path, raw):
            nonlocal count
            count += 1
            if count == 2:
                raise OSError('synthetic write failure')
            return original(directory, path, raw)

        with mock.patch.object(module, 'write_new', side_effect=write):
            with self.assertRaises(OSError):
                module.stage(str(self.repo), plan['inventory'], plan['inventory_sha256'], str(output))
        self.assertTrue(output.exists())
        self.assertTrue(any(output.iterdir()))

    def test_stage_is_readable_by_nonroot_despite_private_umask(self):
        plan = self.plan()
        previous = os.umask(0o077)
        try:
            result = self.stage(plan)
        finally:
            os.umask(previous)
        output = Path(result['context'])
        self.assertEqual((output / 'server/api/src').stat().st_mode & 0o777, 0o755)
        self.assertEqual((output / module.ENTRYPOINTS[0]).stat().st_mode & 0o777, 0o444)
        self.assertEqual(output.stat().st_mode & 0o777, 0o700)

    def test_source_changes_during_staging_refuse_and_retain_output(self):
        plan = self.plan()
        output = self.output('context')
        original = module.write_new
        changed = False

        def write(directory, path, raw):
            nonlocal changed
            original(directory, path, raw)
            if not changed:
                changed = True
                self.source(module.ENTRYPOINTS[0], 'export const changed = true;\n')

        with mock.patch.object(module, 'write_new', side_effect=write):
            with self.assertRaises(module.Refusal):
                module.stage(str(self.repo), plan['inventory'], plan['inventory_sha256'], str(output))
        self.assertTrue(output.exists())

    def test_file_change_while_reading_is_detected(self):
        original = module.os.read
        target = self.repo / module.ENTRYPOINTS[0]
        changed = False

        def read(fd, size):
            nonlocal changed
            raw = original(fd, size)
            if raw and not changed:
                changed = True
                target.write_text('changed while reading\n')
            return raw

        with mock.patch.object(module.os, 'read', side_effect=read):
            with self.assertRaises(module.Refusal):
                module.collect(str(self.repo))

    def test_excluded_hidden_symlink_is_never_followed(self):
        (self.repo / 'server/api/src/.env.ts').symlink_to(self.repo / 'server/runtime/src/contract.ts')
        value, _ = module.collect(str(self.repo))
        self.assertEqual(len(value['files']), 5)

    def test_depth_bound_refuses(self):
        self.source('server/api/src/' + 'nested/' * 65 + 'leaf.ts', 'export const leaf = 1;\n')
        with self.assertRaises(module.Refusal):
            module.collect(str(self.repo))


if __name__ == '__main__':
    unittest.main()
