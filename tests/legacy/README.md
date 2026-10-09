# Historical compatibility fixtures

These files are byte-preserved retired Python/server startup and Terraform inputs. Only development parity tests import or render them. They are never installed, imported or executed by the supported Go deployment. Their tests establish historical migration/rollback semantics; they do not validate the shipping loader or green ownership.

The active Windows SYSTEM certificate inventory tool remains in `scripts/windows_certificates.ps1`; its copy here only preserves historical template rendering. `baseline_checkpoint.py` remains the existing development fixture.

Current deployment tests: `tests/test_green_deployment.py` and `terraform/green/tests/green.tftest.hcl`.
