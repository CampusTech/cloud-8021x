locals {
  unifi_source_discovery_enabled = anytrue([for client in values(var.radius_clients) : client.unifi_host_id != null])
  static_radius_sources          = distinct(flatten([for client in values(var.radius_clients) : client.cidrs]))
}

# Each node reconciles its own rule; concurrent HA refreshes cannot overwrite
# each other's state. Start disabled until the first authenticated discovery.
resource "google_compute_firewall" "radius_discovered" {
  for_each      = local.unifi_source_discovery_enabled ? toset(["radius-primary", "radius-secondary"]) : toset([])
  project       = google_project.this.project_id
  name          = "allow-${each.key}-discovered"
  network       = google_compute_network.radius.id
  target_tags   = [each.key]
  source_ranges = ["192.0.2.1/32"]
  disabled      = true
  allow {
    protocol = "udp"
    ports    = ["1812", "1813"]
  }
  lifecycle {
    # The discovery service owns only these fields; Terraform owns everything else.
    ignore_changes = [source_ranges, disabled]
  }
}

resource "google_project_iam_custom_role" "radius_source_discovery" {
  count       = local.unifi_source_discovery_enabled ? 1 : 0
  project     = google_project.this.project_id
  role_id     = "radiusSourceDiscovery"
  title       = "RADIUS source discovery firewall updates"
  permissions = ["compute.firewalls.get", "compute.firewalls.update"]
}

resource "google_project_iam_member" "radius_source_discovery" {
  count   = local.unifi_source_discovery_enabled ? 1 : 0
  project = google_project.this.project_id
  role    = google_project_iam_custom_role.radius_source_discovery[0].name
  member  = "serviceAccount:${google_service_account.radius.email}"
  condition {
    title = "OnlyRadiusDiscoveryRules"
    expression = join(" || ", [
      for rule in google_compute_firewall.radius_discovered : "(resource.type == 'compute.googleapis.com/Firewall' && resource.name == 'projects/${google_project.this.project_id}/global/firewalls/${rule.name}')"
    ])
  }
}

# The Compute firewall PATCH API also lists networks.updatePolicy. Network
# resources do not support resource.name IAM Conditions, so grant this single
# prerequisite separately. Actual firewall get/update stays restricted above;
# this role does not grant firewall create/delete or network update permissions.
resource "google_project_iam_custom_role" "radius_source_network_policy" {
  count       = local.unifi_source_discovery_enabled ? 1 : 0
  project     = google_project.this.project_id
  role_id     = "radiusSourceNetworkPolicy"
  title       = "RADIUS firewall API network-policy prerequisite"
  permissions = ["compute.networks.updatePolicy"]
}

resource "google_project_iam_member" "radius_source_network_policy" {
  count   = local.unifi_source_discovery_enabled ? 1 : 0
  project = google_project.this.project_id
  role    = google_project_iam_custom_role.radius_source_network_policy[0].name
  member  = "serviceAccount:${google_service_account.radius.email}"
}
