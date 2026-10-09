# The old Datadog log-readback collector is retired. Native PostgreSQL accounting
# and Go outbox delivery are authoritative. Historical credentials are untouched;
# no VM IAM grant to a Datadog application/readback key remains.
removed {
  from = google_secret_manager_secret_iam_member.radius_usage_credentials
  lifecycle { destroy = true }
}
removed {
  from = datadog_monitor.radius_usage_stale
  lifecycle { destroy = true }
}
