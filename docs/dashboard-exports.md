# Dashboard exports

The dashboard locals in `datadog.tf`, `datadog-auth.tf`, `datadog-usage.tf`, and
`datadog-smallstep.tf` are authoritative. Terraform manages the dashboards with
`datadog_dashboard_json`; JSON imports support deployments without Terraform.

Run from the repository root:

```sh
cd tools/dashboard
go run . sync --root ../..
go run . sync --root ../.. --check
```

Go and Terraform are required. `--dry-run` reports drift without changing files;
`--debug` enables structured diagnostic logging. The tool evaluates dashboard
locals in a temporary module with canonical example server names and default
dashboard settings. It does not read `terraform.tfvars`, load a backend, use
deployment state, contact Datadog, or apply infrastructure. Deployment-specific
host suffixes, site counters, and collector options remain configured in the
root Terraform module.

Generated files:

- `datadog-dashboard.json`: complete FreeRADIUS dashboard for UI import.
- `datadog-smallstep-dashboard.json`: complete Smallstep dashboard for UI import.
- `docs/generated/datadog-dashboard-v2.tf`: native HCL companion using the pinned
  Datadog provider's official mapping.
- `docs/generated/datadog-dashboard-v2-losses.json`: fields omitted by that native
  mapping. Unexpected losses fail generation instead of silently discarding
  additional dashboard behavior.

Commit regenerated files with their source changes. CI checks them without any
production credentials. Do not hand-edit the generated files or maintain a
separate copy of the UI export.

## Native provider limitation

Provider 4.25.0 supports `datadog_dashboard_v2`, but its log/event `group_by`
schema and mapping omit `should_exclude_missing`. Our JSON explicitly sets this
to `false` to include missing owner/AP/VLAN buckets. The provider's flattening
path drops it without reporting a dropped field, so the tool also compares the
roundtrip output and records the loss.

[Datadog PR #4225](https://github.com/DataDog/terraform-provider-datadog/pull/4225)
adds the schema and roundtrip support, including tests for explicit `false`
values. It is open and draft as of October 8, 2026, and is not in the pinned
release. [Issue #3033](https://github.com/DataDog/terraform-provider-datadog/issues/3033)
reports the same unsupported flag for monitors.

The native companion is a reference export, **not behavior-equivalent deployable
configuration**. It stays outside the root module so Terraform cannot create a
second dashboard. Keep the JSON resources until a released provider preserves
the required fields and the roundtrip tests confirm parity.

## Future state migration

After native field support is released, upgrade and verify the provider mapping,
then replace the JSON resource with configurable native HCL in a reviewed PR.
Preserve optional dashboard creation, deployment-specific host filters, flexible
site tiles, collector settings, and every query/layout during that migration.

Follow [Datadog's migration guide](https://github.com/DataDog/terraform-provider-datadog/blob/v4.25.0/docs/guides/dashboard_v2_migration.md)
and back up the correct workspace's state before changing ownership. If the
dashboard is already managed as `datadog_dashboard_json.radius[0]`, remove only
that state binding, then import the same dashboard ID into
`datadog_dashboard_v2.radius[0]`. Removing a state binding does not delete the
remote dashboard. Do not apply between those steps, and do not keep both
resources managing the same ID. Review a subsequent plan for updates only,
without dashboard creation or destruction. Smallstep's state binding remains
unchanged unless it is migrated separately.

This PR does not perform that migration or any production import/apply.
