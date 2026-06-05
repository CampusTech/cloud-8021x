output "project_id" {
  description = "The created GCP project ID"
  value       = google_project.this.project_id
}

output "radius_primary_ip" {
  description = "Primary RADIUS server public IP"
  value       = google_compute_address.radius.address
}

output "radius_secondary_ip" {
  description = "Secondary (failover) RADIUS server public IP"
  value       = google_compute_address.radius_secondary.address
}

output "ssh_command_primary" {
  description = "SSH into the primary VM via IAP tunnel"
  value       = "gcloud compute ssh radius-primary --zone=${var.zone} --project=${google_project.this.project_id} --tunnel-through-iap"
}

output "ssh_command_secondary" {
  description = "SSH into the secondary VM via IAP tunnel"
  value       = "gcloud compute ssh radius-secondary --zone=${var.secondary_zone} --project=${google_project.this.project_id} --tunnel-through-iap"
}

output "datadog_dashboard_url" {
  description = "Datadog dashboard URL (empty if dashboard is disabled)"
  value       = nonsensitive(local.datadog_enabled ? "https://app.${var.datadog_site}${datadog_dashboard_json.radius[0].url}" : "")
}

output "unifi_radius_config" {
  description = "Values for UniFi RADIUS server profile — configure both primary and secondary servers"
  value = {
    primary_server_ip   = google_compute_address.radius.address
    secondary_server_ip = google_compute_address.radius_secondary.address
    auth_port           = 1812
    accounting_port     = 1813
    shared_secrets      = { for k, v in google_secret_manager_secret.radius_secret : k => v.secret_id }
  }
}

# -----------------------------------------------------------------------------
# Smallstep step-ca (only meaningful when enable_smallstep_ca = true)
# -----------------------------------------------------------------------------

output "smallstep_acme_directory_url" {
  description = "ACME directory URL for MDM ACME payloads (macOS/iOS). Empty if disabled."
  value       = var.enable_smallstep_ca ? "https://${var.smallstep_ca_dns_name}/acme/${var.smallstep_acme_provisioner_name}/directory" : ""
}

output "smallstep_scep_url" {
  description = "SCEP URL for Fleet's custom_scep_proxy (Windows). Empty if disabled."
  value       = var.enable_smallstep_ca ? "https://${var.smallstep_ca_dns_name}/scep/${var.smallstep_scep_provisioner_name}" : ""
}

output "smallstep_scep_rsa_url" {
  description = "RSA SCEP enrollment URL (Windows + non-ADE Macs point here). Empty if disabled."
  value       = var.enable_smallstep_ca ? "https://${var.smallstep_ca_rsa_dns_name}/scep/${var.smallstep_scep_rsa_provisioner_name}" : ""
}

output "smallstep_rsa_lb_ip" {
  description = "Public IP of the RSA step-ca load balancer; point smallstep_ca_rsa_dns_name at this A record. Empty if disabled."
  value       = var.enable_smallstep_ca ? google_compute_global_address.smallstep_rsa_lb[0].address : ""
}

output "smallstep_ca_cert_secret_id" {
  description = "Secret Manager secret holding the Smallstep CA root cert PEM (for RADIUS trust + MDM root payloads). Empty if disabled."
  value       = var.enable_smallstep_ca ? google_secret_manager_secret.smallstep_ca_cert[0].secret_id : ""
}

output "smallstep_lb_ip" {
  description = "Public IP of the step-ca load balancer; point smallstep_ca_dns_name at this A record. Empty if disabled."
  value       = var.enable_smallstep_ca ? google_compute_global_address.smallstep_lb[0].address : ""
}
