"""Read-only exact cached application input checks; no Docker or native launch."""
import copy
import importlib.util
import os
from pathlib import Path
import tempfile
import unittest

spec=importlib.util.spec_from_file_location('protocol_runner',Path(__file__).with_name('run.py'))
runner=importlib.util.module_from_spec(spec)
spec.loader.exec_module(runner)


@unittest.skipUnless(os.environ.get('TASK11_INPUT_APPLICATION_DIR'),'exact cached application input required')
class ApplicationInputs(unittest.TestCase):
    def setUp(self):
        self.options=runner.arguments(['--application-dir',os.environ['TASK11_INPUT_APPLICATION_DIR'],
            '--source-sha',os.environ['TASK11_INPUT_SOURCE_SHA'],
            '--application-sha256',os.environ['TASK11_INPUT_APPLICATION_SHA256'],
            '--go',os.environ['TASK11_INPUT_GO']])

    def test_actual_clean_binary_exact_source_and_directory_checksum(self):
        application,checksum,metadata=runner.application_inputs(self.options)
        self.assertEqual(application.name,'cloud-8021x-linux-arm64')
        self.assertEqual(checksum,self.options.application_sha256)
        self.assertIn('vcs.modified=false',metadata)

    def test_actual_binary_rejects_wrong_claimed_source(self):
        options=copy.copy(self.options);options.source_sha='0'*40
        with self.assertRaisesRegex(ValueError,'build metadata'):
            runner.application_inputs(options)

    def test_actual_binary_rejects_wrong_claimed_hash(self):
        options=copy.copy(self.options);options.application_sha256='0'*64
        with self.assertRaisesRegex(ValueError,'SHA256 mismatch'):
            runner.application_inputs(options)

    def test_directory_cannot_rebind_actual_binary_checksum(self):
        with tempfile.TemporaryDirectory(prefix='task11-protocol-inputs-') as directory:
            options=copy.copy(self.options);options.application_dir=Path(directory)
            (options.application_dir/'cloud-8021x-linux-arm64').symlink_to(self.options.application_dir/'cloud-8021x-linux-arm64')
            (options.application_dir/'SHA256SUMS').write_text('0'*64+'  cloud-8021x-linux-arm64\n')
            with self.assertRaisesRegex(ValueError,'directory checksum binding'):
                runner.application_inputs(options)

    def test_unpinned_source_and_hash_are_rejected(self):
        for field,value in [('source_sha','HEAD'),('application_sha256','latest')]:
            options=copy.copy(self.options);setattr(options,field,value)
            with self.assertRaisesRegex(ValueError,'exact source SHA'):
                runner.application_inputs(options)


if __name__=='__main__':
    unittest.main()
