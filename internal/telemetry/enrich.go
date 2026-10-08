package telemetry

import (
	"strconv"
	"time"

	"github.com/CampusTech/cloud-8021x/internal/accounting/binding"
	"github.com/CampusTech/cloud-8021x/internal/config"
	"github.com/CampusTech/cloud-8021x/internal/domain"
	"github.com/CampusTech/cloud-8021x/internal/network"
)

type LocalDisplay struct {
	locations map[string]config.Location
	snapshots *domain.SnapshotStore
	network   *network.Store
	maxAge    time.Duration
}

func NewDisplay(c config.Config, snapshots *domain.SnapshotStore, metadata *network.Store) *LocalDisplay {
	d := &LocalDisplay{locations: map[string]config.Location{}, snapshots: snapshots, network: metadata, maxAge: c.Policy.InventoryMaxAge}
	for _, l := range c.Network.Locations {
		d.locations[l.ID] = l
	}
	return d
}
func (d *LocalDisplay) Enrich(r *BusinessRecord, location, called string, id *binding.Attribution) {
	now := time.Now()
	if id != nil && d.snapshots != nil {
		v := d.snapshots.View()
		if domain.Fresh(v.Updated(), now, d.maxAge) {
			if m := v.MetadataFor(id.DeviceID); m != nil {
				r.Fields["device_owner"], r.Fields["device_name"], r.Fields["device_model"] = present(m.Owner), present(m.Name), present(m.Model)
				r.Fields["serial"] = present(m.Serial)
			}
		}
	}
	if l, ok := d.locations[location]; ok && d.network != nil {
		vlan := 0
		if id != nil && id.VLAN != nil {
			vlan = *id.VLAN
		}
		m := d.network.Resolve(l.ProviderID, l.SiteID, called, vlan, now, d.maxAge)
		r.Fields["site_name"], r.Fields["ap_name"], r.Fields["vlan_name"] = present(m.Site), present(m.Authenticator), present(m.VLAN)
		if vlan != 0 {
			r.Fields["vlan_id"] = strconv.Itoa(vlan)
		}
	}
}
