package fleet

import (
	"context"
	"errors"
	"fmt"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/CampusTech/cloud-8021x/internal/domain"
)

type profile struct {
	UUID      string `json:"profile_uuid"`
	Status    string `json:"status"`
	Operation string `json:"operation_type"`
}
type host struct {
	ID             int    `json:"id"`
	UUID           string `json:"uuid"`
	Platform       string `json:"platform"`
	OSVersion      string `json:"os_version"`
	Serial         any    `json:"hardware_serial"`
	Display        any    `json:"display_name"`
	Computer       any    `json:"computer_name"`
	Hostname       any    `json:"hostname"`
	Model          any    `json:"hardware_model"`
	FleetID        *int   `json:"fleet_id"`
	TeamID         int    `json:"team_id"`
	EnrolledAt     string `json:"last_enrolled_at"`
	MDMEnrolledAt  string `json:"last_mdm_enrolled_at"`
	ScriptsEnabled bool   `json:"scripts_enabled"`
	Mapping        []struct {
		Email any `json:"email"`
	} `json:"device_mapping"`
	Users []struct {
		Username any `json:"idp_username"`
	} `json:"end_users"`
	MDM struct {
		Status   string    `json:"enrollment_status"`
		Profiles []profile `json:"profiles"`
	} `json:"mdm"`
	Labels []struct {
		Name string `json:"name"`
	} `json:"labels"`
}

func (h host) enrolled() bool { return strings.HasPrefix(h.MDM.Status, "On") }
func (h host) group() int {
	if h.FleetID != nil {
		return *h.FleetID
	}
	return h.TeamID
}
func (h host) device() domain.Device {
	text := func(v any) string { s, _ := v.(string); return s }
	first := func(vs ...any) string {
		for _, v := range vs {
			if s := text(v); s != "" {
				return s
			}
		}
		return ""
	}
	owner := ""
	for _, r := range h.Mapping {
		if s := text(r.Email); s != "" {
			owner = s
			break
		}
	}
	if owner == "" {
		for _, r := range h.Users {
			if s := text(r.Username); s != "" {
				owner = s
				break
			}
		}
	}
	identities := []string{}
	for _, alias := range []string{text(h.Serial), h.UUID} {
		if alias != "" {
			identities = append(identities, domain.NormalizeIdentity(alias))
		}
	}
	return domain.Device{ID: domain.DeviceID(fmt.Sprintf("fleet:%d", h.ID)), Identities: identities, HardwareSerial: text(h.Serial), Groups: []domain.GroupID{domain.GroupID(fmt.Sprintf("fleet:%d", h.group()))}, Enrolled: h.enrolled(), Metadata: &domain.DeviceMetadata{Serial: text(h.Serial), Name: first(h.Display, h.Computer, h.Hostname), Model: text(h.Model), Owner: owner}}
}

// Observer carries only the read-only account. It cannot submit MDM commands or scripts.
type Observer struct {
	Client           *Client
	PageSize         int
	HostIDs, TeamIDs []string
	AllowLabel       string
	Now              func() time.Time
}

var _ domain.DeviceInventoryProvider = (*Observer)(nil)

func selected(ids []string, id string) bool {
	if ids == nil {
		return true
	}
	for _, candidate := range ids {
		if strings.TrimPrefix(candidate, "fleet:") == id {
			return true
		}
	}
	return false
}
func (o *Observer) hosts(ctx context.Context) ([]host, error) {
	size := o.PageSize
	if size == 0 {
		size = 100
	}
	if size < 1 || size > 1000 {
		return nil, errors.New("invalid Fleet page size")
	}
	all := []host{}
	seen := map[int]bool{}
	for page := 0; page < 10000; page++ {
		var response struct {
			Hosts []host `json:"hosts"`
		}
		query := url.Values{"page": {strconv.Itoa(page)}, "per_page": {strconv.Itoa(size)}, "device_mapping": {"true"}}
		if o.AllowLabel != "" {
			query.Set("populate_labels", "true")
		}
		if err := o.Client.request(ctx, "GET", "/api/v1/fleet/hosts?"+query.Encode(), nil, &response); err != nil {
			return nil, err
		}
		if response.Hosts == nil || len(response.Hosts) > size {
			return nil, errors.New("missing or oversized Fleet hosts page")
		}
		for _, h := range response.Hosts {
			if h.ID <= 0 || seen[h.ID] || h.group() < 0 {
				return nil, errors.New("invalid or duplicate Fleet host identity")
			}
			seen[h.ID] = true
			all = append(all, h)
		}
		if len(response.Hosts) < size {
			return all, nil
		}
	}
	return nil, errors.New("fleet pagination exceeds bound")
}
func (o *Observer) inScope(h host, scope domain.InventoryScope) bool {
	id := strconv.Itoa(h.ID)
	if !selected(scope.IDs, id) || !selected(o.HostIDs, id) || !selected(o.TeamIDs, strconv.Itoa(h.group())) {
		return false
	}
	if o.AllowLabel != "" {
		for _, label := range h.Labels {
			if label.Name == o.AllowLabel {
				return true
			}
		}
		return false
	}
	return true
}
func (o *Observer) Fetch(ctx context.Context, scope domain.InventoryScope) (domain.DeviceSnapshot, error) {
	if scope.ProviderID != "fleet" {
		return domain.DeviceSnapshot{}, errors.New("fleet scope provider mismatch")
	}
	hosts, err := o.hosts(ctx)
	if err != nil {
		return domain.DeviceSnapshot{}, err
	}
	devices := []domain.Device{}
	for _, h := range hosts {
		if o.inScope(h, scope) {
			devices = append(devices, h.device())
		}
	}
	if err = ctx.Err(); err != nil {
		return domain.DeviceSnapshot{}, err
	}
	now := time.Now()
	if o.Now != nil {
		now = o.Now()
	}
	return domain.DeviceSnapshot{Scope: scope, Complete: true, ObservedAt: domain.Unix(now), Devices: devices}, nil
}
