# Retain actual rollback material; removal from this fresh-install configuration
# must never delete secret containers or versions. This is NOT a green rollout plan.
removed {
  from = google_secret_manager_secret.radius_server_ca_key
  lifecycle { destroy = false }
}
removed {
  from = google_secret_manager_secret.radius_server_ca_cert
  lifecycle { destroy = false }
}
removed {
  from = google_secret_manager_secret.radius_server_key
  lifecycle { destroy = false }
}
removed {
  from = google_secret_manager_secret.radius_server_cert
  lifecycle { destroy = false }
}
removed {
  from = google_secret_manager_secret.radius_dh_params
  lifecycle { destroy = false }
}
removed {
  from = google_secret_manager_secret.okta_ca_cert
  lifecycle { destroy = false }
}
removed {
  from = google_secret_manager_secret_version.okta_ca_cert
  lifecycle { destroy = false }
}
removed {
  from = google_secret_manager_secret.okta_root_ca_cert
  lifecycle { destroy = false }
}
removed {
  from = google_secret_manager_secret_version.okta_root_ca_cert
  lifecycle { destroy = false }
}
removed {
  from = google_secret_manager_secret.jamf_url
  lifecycle { destroy = false }
}
removed {
  from = google_secret_manager_secret_version.jamf_url
  lifecycle { destroy = false }
}
removed {
  from = google_secret_manager_secret.jamf_client_id
  lifecycle { destroy = false }
}
removed {
  from = google_secret_manager_secret_version.jamf_client_id
  lifecycle { destroy = false }
}
removed {
  from = google_secret_manager_secret.jamf_client_secret
  lifecycle { destroy = false }
}
removed {
  from = google_secret_manager_secret_version.jamf_client_secret
  lifecycle { destroy = false }
}
