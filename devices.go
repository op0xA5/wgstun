package main

import "golang.zx2c4.com/wireguard/wgctrl"

// command to list wg net devices
func devices_main(args []string) {
	var verbose bool
	_ = verbose

	for _, arg := range args {
		switch arg {
		case "-v", "--verbose":
			verbose = true
		}
	}

	wgClient, err := wgctrl.New()
	defer wgClient.Close()
	if err != nil {
		printf("err create wireguard client instance: %v\n", err)
		return
	}

	devices, err := wgClient.Devices()
	if err != nil {
		printf("err get wireguard interfaces: %v\n", err)
		return
	}

	for _, device := range devices {
		if verbose {
			printf("Interface: %s\n", device.Name)
			printf("\tListenPort: %d\n", device.ListenPort)
			printf("\tPublicKey: %s\n", device.PublicKey.String())
			printf("\tType: %s\n", device.Type.String())
			for _, peer := range device.Peers {
				printf("\tPeer: %s\n", peer.PublicKey.String())
				printf("\t\tEndpoint: %s\n", peer.Endpoint.String())
				//printf("\t\tProtocolVersion: %d\n", peer.ProtocolVersion)
				printf("\t\tLastHandshakeTime: %s\n", peer.LastHandshakeTime.Format("2006-01-02 15:04:05"))
				printf("\t\tPersistentKeepaliveInterval: %s\n", peer.PersistentKeepaliveInterval.String())
				printf("\t\tTransmitBytes: %d\n", peer.TransmitBytes)
				printf("\t\tReceiveBytes: %d\n", peer.ReceiveBytes)
			}
		} else {
			printf("%s\n", device.Name)
		}
	}
}

