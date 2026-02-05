package models

import (
	"context"

	"github.com/EigerCode/ent"
	"github.com/EigerCode/ent/netbirdsettings"
	"github.com/EigerCode/ent/tenant"
)

func (m *Model) GetNetbirdSettings(tenantID int) (*ent.NetbirdSettings, error) {
	return m.Client.NetbirdSettings.Query().Where(netbirdsettings.HasTenantWith(tenant.ID(tenantID))).Only(context.Background())
}
