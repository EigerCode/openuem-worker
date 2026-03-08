package common

import (
	"log"

	"github.com/nats-io/nats.go"
	openuem_nats "github.com/open-uem/nats"
	"howett.net/plist"
)

func (w *Worker) NanoHubDeviceInfoHandler(msg *nats.Msg) {
	var response openuem_nats.NanoHubDeviceInfoResponse
	if _, err := plist.Unmarshal(msg.Data, &response); err != nil {
		log.Printf("[ERROR]: could not unmarshal NanoHub device info plist, reason: %v\n", err)
		return
	}

	if err := w.Model.SaveNanoHubDeviceInfo(response); err != nil {
		log.Printf("[ERROR]: could not save NanoHub device info into database, reason: %v\n", err)
	}
}

func (w *Worker) NanoHubInstalledApplicationListHandler(msg *nats.Msg) {
	var response struct {
		UDID                    string                                `plist:"UDID"`
		InstalledApplicationList []openuem_nats.NanoHubApplicationListItem `plist:"InstalledApplicationList"`
	}
	if _, err := plist.Unmarshal(msg.Data, &response); err != nil {
		log.Printf("[ERROR]: could not unmarshal NanoHub installed application list plist, reason: %v\n", err)
		return
	}

	if err := w.Model.SaveNanoHubInstalledApplications(response.UDID, response.InstalledApplicationList); err != nil {
		log.Printf("[ERROR]: could not save NanoHub installed applications into database, reason: %v\n", err)
	}
}

func (w *Worker) NanoHubUsersListHandler(msg *nats.Msg) {
	var response struct {
		UDID  string                      `plist:"UDID"`
		Users []openuem_nats.NanoHubUser `plist:"Users"`
	}
	if _, err := plist.Unmarshal(msg.Data, &response); err != nil {
		log.Printf("[ERROR]: could not unmarshal NanoHub users list plist, reason: %v\n", err)
		return
	}

	if err := w.Model.SaveNanoHubUsers(response.UDID, response.Users); err != nil {
		log.Printf("[ERROR]: could not save NanoHub users into database, reason: %v\n", err)
	}
}
