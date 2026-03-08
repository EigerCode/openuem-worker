package models

import (
	"context"
	"log"
	"strings"
	"time"

	"github.com/open-uem/ent/agent"
	"github.com/open-uem/ent/antivirus"
	"github.com/open-uem/ent/app"
	"github.com/open-uem/ent/computer"
	"github.com/open-uem/ent/nanohubinfo"
	"github.com/open-uem/ent/nanohubuser"
	"github.com/open-uem/ent/operatingsystem"
	"github.com/open-uem/ent/systemupdate"
	openuem_nats "github.com/open-uem/nats"
)

// deriveOS determines the OS from multiple MDM signals.
// On macOS 26+, ProductName may return the model identifier (e.g. "Mac14,15")
// instead of "macOS", so we need fallback logic.
func deriveOS(productName, model, osVersion string) string {
	switch strings.ToLower(productName) {
	case "macos", "mac os x":
		return "macOS"
	case "iphone os":
		return "iOS"
	case "ipad", "ipados":
		return "iPadOS"
	}
	if strings.HasPrefix(model, "Mac") || strings.HasPrefix(model, "Virtual") {
		return "macOS"
	}
	if strings.HasPrefix(model, "iPhone") {
		return "iOS"
	}
	if strings.HasPrefix(model, "iPad") {
		return "iPadOS"
	}
	if osVersion != "" {
		return "macOS"
	}
	if productName != "" {
		return productName
	}
	return "Unknown"
}

func (m *Model) SaveNanoHubDeviceInfo(response openuem_nats.NanoHubDeviceInfoResponse) error {
	ctx := context.Background()
	udid := response.UDID
	qr := response.QueryResponses

	os := deriveOS(qr.ProductName, qr.Model, qr.OSVersion)

	hostname := qr.HostName
	if hostname == "" {
		hostname = qr.LocalHostName
	}
	if hostname == "" {
		hostname = udid
	}

	// Create or update agent
	err := m.Client.Agent.Create().
		SetID(udid).
		SetOs(os).
		SetHostname(hostname).
		SetEndpointType(agent.EndpointTypeNanoHub).
		SetFirstContact(time.Now()).
		SetLastContact(time.Now()).
		SetNickname(qr.DeviceName).
		OnConflictColumns(agent.FieldID).
		UpdateLastContact().
		UpdateOs().
		UpdateHostname().
		Exec(ctx)
	if err != nil {
		log.Printf("[ERROR]: could not save NanoHub agent info into database, reason: %v\n", err)
		return err
	}

	// Assign to default site if no site exists
	a, err := m.Client.Agent.Query().WithSite().Where(agent.ID(udid)).Only(ctx)
	if err != nil {
		return err
	}
	if len(a.Edges.Site) == 0 {
		s, err := m.GetDefaultSite()
		if err != nil {
			log.Printf("[ERROR]: could not get default site for NanoHub agent, reason: %v\n", err)
		} else {
			if err := m.Client.Agent.UpdateOneID(udid).AddSite(s).Exec(ctx); err != nil {
				log.Printf("[ERROR]: could not assign default site to NanoHub agent, reason: %v\n", err)
			}
		}
	}

	// Create or update NanoHubInfo record
	infoCreate := m.Client.NanoHubInfo.Create().
		SetOwnerID(udid).
		SetUdid(udid).
		SetDeviceName(qr.DeviceName).
		SetHostname(qr.HostName).
		SetSerialNumber(qr.SerialNumber).
		SetModel(qr.Model).
		SetModelName(qr.ModelName).
		SetOsVersion(qr.OSVersion).
		SetBuildVersion(qr.BuildVersion).
		SetProductName(qr.ProductName).
		SetIsAppleSilicon(qr.IsAppleSilicon).
		SetIsSupervised(qr.IsSupervised).
		SetAvailableDeviceCapacity(qr.AvailableDeviceCapacity).
		SetAwaitingConfiguration(qr.AwaitingConfiguration).
		SetBatteryLevel(qr.BatteryLevel).
		SetBluetoothMAC(qr.BluetoothMAC).
		SetCurrentConsoleManagedUser(qr.CurrentConsoleManagedUser).
		SetDeviceCapacity(qr.DeviceCapacity).
		SetEacsPreflight(qr.EACSPreflight).
		SetEthernetMAC(qr.EthernetMAC).
		SetWifiMAC(qr.WiFiMAC).
		SetHasBattery(qr.HasBattery).
		SetIsActivationLockEnabled(qr.IsActivationLockEnabled).
		SetIsActivationLockSupported(qr.IsActivationLockSupported).
		SetLocalhostname(qr.LocalHostName).
		SetAutoCheckEnabled(qr.OSUpdateSettings.AutoCheckEnabled).
		SetAutomaticAppInstallationEnabled(qr.OSUpdateSettings.AutomaticAppInstallationEnabled).
		SetAutomaticOsInstallationEnabled(qr.OSUpdateSettings.AutomaticOSInstallationEnabled).
		SetAutomaticSecurityUpdatesEnabled(qr.OSUpdateSettings.AutomaticSecurityUpdatesEnabled).
		SetBackgroundDownloadEnabled(qr.OSUpdateSettings.BackgroundDownloadEnabled).
		SetCatalogURL(qr.OSUpdateSettings.CatalogURL).
		SetIsDefaultCatalog(qr.OSUpdateSettings.IsDefaultCatalog).
		SetPreviousScanResult(int64(qr.OSUpdateSettings.PreviousScanResult)).
		SetPinRequiredForDeviceLock(qr.PINRequiredForDeviceLock).
		SetPinRequiredForEraseDevice(qr.PINRequiredForEraseDevice).
		SetProvisioningUdid(qr.ProvisioningUDID).
		SetSoftwareUpdateDeviceID(qr.SoftwareUpdateDeviceID).
		SetSupplementalBuildVersion(qr.SupplementalBuildVersion).
		SetSupportsLomDevice(qr.SupportsLOMDevice).
		SetSupportsIosAppInstalls(qr.SupportsiOSAppInstalls).
		SetSystemIntegrityProtectionEnabled(qr.SystemIntegrityProtectionEnabled)

	if !qr.OSUpdateSettings.PreviousScanDate.IsZero() {
		infoCreate = infoCreate.SetNillablePreviousScanDate(&qr.OSUpdateSettings.PreviousScanDate)
	}

	err = infoCreate.
		OnConflictColumns(nanohubinfo.OwnerColumn).
		UpdateNewValues().
		Exec(ctx)
	if err != nil {
		log.Printf("[ERROR]: could not save NanoHub info into database, reason: %v\n", err)
		return err
	}

	// Create related records (computer, OS, antivirus, system updates)
	err = m.Client.Computer.Create().
		SetManufacturer("Apple").
		SetModel(qr.ModelName).
		SetSerial(qr.SerialNumber).
		SetProcessor("").
		SetProcessorArch("").
		SetProcessorCores(0).
		SetMemory(0).
		SetOwnerID(udid).
		OnConflictColumns(computer.OwnerColumn).
		UpdateNewValues().
		Exec(ctx)
	if err != nil {
		log.Printf("[ERROR]: could not save NanoHub computer info, reason: %v\n", err)
	}

	err = m.Client.OperatingSystem.Create().
		SetType(os).
		SetVersion(qr.OSVersion).
		SetDescription(qr.ProductName).
		SetArch("").
		SetUsername("").
		SetOwnerID(udid).
		OnConflictColumns(operatingsystem.OwnerColumn).
		UpdateNewValues().
		Exec(ctx)
	if err != nil {
		log.Printf("[ERROR]: could not save NanoHub OS info, reason: %v\n", err)
	}

	err = m.Client.Antivirus.Create().
		SetName("").
		SetIsActive(false).
		SetIsUpdated(false).
		SetOwnerID(udid).
		OnConflictColumns(antivirus.OwnerColumn).
		UpdateNewValues().
		Exec(ctx)
	if err != nil {
		log.Printf("[ERROR]: could not save NanoHub antivirus info, reason: %v\n", err)
	}

	err = m.Client.SystemUpdate.Create().
		SetOwnerID(udid).
		SetSystemUpdateStatus("").
		SetLastInstall(time.Time{}).
		SetLastSearch(time.Time{}).
		SetPendingUpdates(false).
		OnConflictColumns(systemupdate.OwnerColumn).
		UpdateNewValues().
		Exec(ctx)
	if err != nil {
		log.Printf("[ERROR]: could not save NanoHub system update info, reason: %v\n", err)
	}

	return nil
}

func (m *Model) SaveNanoHubInstalledApplications(udid string, apps []openuem_nats.NanoHubApplicationListItem) error {
	ctx := context.Background()

	tx, err := m.Client.Tx(ctx)
	if err != nil {
		return err
	}

	// Delete existing apps for this agent
	_, err = tx.App.Delete().Where(app.HasOwnerWith(agent.ID(udid))).Exec(ctx)
	if err != nil {
		log.Printf("[ERROR]: could not delete previous NanoHub apps, reason: %v\n", err)
		return tx.Rollback()
	}

	for _, a := range apps {
		version := a.ShortVersion
		if version == "" {
			version = a.Version
		}
		if err := tx.App.Create().
			SetName(a.Name).
			SetVersion(version).
			SetPublisher(a.Identifier).
			SetOwnerID(udid).
			Exec(ctx); err != nil {
			return tx.Rollback()
		}
	}

	return tx.Commit()
}

func (m *Model) SaveNanoHubUsers(udid string, users []openuem_nats.NanoHubUser) error {
	ctx := context.Background()

	tx, err := m.Client.Tx(ctx)
	if err != nil {
		return err
	}

	// Delete existing NanoHub users for this agent
	_, err = tx.NanoHubUser.Delete().Where(nanohubuser.HasOwnerWith(agent.ID(udid))).Exec(ctx)
	if err != nil {
		log.Printf("[ERROR]: could not delete previous NanoHub users, reason: %v\n", err)
		return tx.Rollback()
	}

	for _, u := range users {
		if err := tx.NanoHubUser.Create().
			SetOwnerID(udid).
			SetNillableUsername(&u.UserName).
			SetNillableFullname(&u.FullName).
			SetNillableUserGUID(&u.UserGUID).
			SetDataQuota(u.DataQuota).
			SetDataUsed(u.DataUsed).
			SetHasDataToSync(u.HasDataToSync).
			SetHasSecureToken(u.HasSecureToken).
			SetIsLoggedIn(u.IsLoggedIn).
			SetMobileAccount(u.MobileAccount).
			SetUID(u.UID).
			Exec(ctx); err != nil {
			return tx.Rollback()
		}
	}

	return tx.Commit()
}
