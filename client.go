package main

import (
	"golang.zx2c4.com/wireguard/wgctrl"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
	"net"
	"os"
	"strconv"
	"strings"
	"time"
)

// command to start once query for peer IP then update wireguard peers
func client_once(raddr *net.UDPAddr, conn *net.UDPConn, ifname string, peers []wgtypes.Key, force bool, once_print bool) {
	wgClient, err := wgctrl.New()
	defer wgClient.Close()
	if err != nil {
		printf("err create wireguard client instance: %v\n", err)
		return
	}

	device, err := wgClient.Device(ifname)
	if err != nil {
		printf("err open wireguard interface: %v\n", err)
		return
	}

	nPeers := make([]wgtypes.Key, 0, len(peers))
	for _, peer := range peers {
		found := false
		for _, p := range device.Peers {
			if keyEquals(peer, p.PublicKey) {
				found = true
				break
			}
		}
		if found {
			nPeers = append(nPeers, peer)
		} else {
			if once_print {
				printf("%s ignored (not interface peer)\n", peer.String())
			}
			return
		}
	}

	if len(nPeers) == 0 {
		if once_print {
			printf("nothing to query\n")
		}
		return
	}

	time_start_resolve := time.Now()

	var results []ResolveResult
	if conn != nil {
		results, err = StunResolveConn(conn, nPeers)
	} else {
		results, err = StunResolve(raddr, nPeers)
	}
	if err != nil {
		printf("err resolve: %v\n", err)
		return
	}

	time_end_resolve := time.Now()

	if !once_print {
		printf("resolved %d peers in %v\n", len(nPeers), time_end_resolve.Sub(time_start_resolve))
	}

	device, err = wgClient.Device(ifname)
	if err != nil {
		printf("err open wireguard interface: %v\n", err)
		return
	}

	cfg := wgtypes.Config{}
	for _, result := range results {
		if !result.Valid {
			if once_print {
				printf("%s not_resolved\n", result.Key.String())
			} else {
				printf("peer '%s' not_resolved\n", result.Key.String())
			}
			continue
		}

		var peer wgtypes.Peer
		var peerFound = false
		for _, _peer :=range device.Peers {
			if keyEquals(result.Key, _peer.PublicKey) {
				peer = _peer
				peerFound = true
				break
			}
		}

		if !peerFound {
			if once_print {
				printf("%s not_found\n", result.Key.String())
			}
			continue
		}

		if !force {
			if peer.Endpoint != nil &&
				result.Endpoint.IP.Equal(peer.Endpoint.IP) &&
				result.Endpoint.Port == peer.Endpoint.Port {
				if once_print {
					printf("%s no_change\n", result.Key.String())
				}
				continue
			}

			if peer.LastHandshakeTime.Sub(result.HandshakeTime) > 0 {
				if once_print {
					printf("%s newer\n", result.Key.String())
				}
				continue
			}
		}

		if once_print {
			printf("%s %s\n", result.Key.String(), result.Endpoint.String())
		} else {
			printf("peer '%s' ip changed\n", result.Key.String())
		}
		cfg.Peers = append(cfg.Peers, wgtypes.PeerConfig{
			PublicKey:  result.Key,
			UpdateOnly: true,
			Endpoint:   result.Endpoint,
		})
	}

	if len(cfg.Peers) == 0 {
		if once_print {
			printf("up-to-date\n")
		}
		return
	}

	err = wgClient.ConfigureDevice(ifname, cfg)
	if err != nil {
		printf("err submit wireguard config: %v\n", err)
		return
	}

	printf("processed config wireguard\n")
}

// command to continuously update wireguard peers
func client_pull(raddr *net.UDPAddr, ifname string, peers []wgtypes.Key, interval int) {
	conn, err := net.DialUDP("udp", nil, raddr)
	if err != nil {
		printf("err DialUDP: %v\n", err)
		os.Exit(1)
		return
	}

	printf("create UDP connection at '%s'\n", conn.LocalAddr().String())

	ticker := time.Tick(time.Second * time.Duration(interval))
	for _ = range ticker {
		client_once(nil, conn, ifname, peers, false, false)
	}
}

// client command entry
func client_main(args []string, once bool) {
	var server_str string = "10.77.1.1:55550"
	var ifname_str string
	var interval_str string = "10"
	var peers_str []string
	var config string
	var force bool
	var verbose bool
	_ = verbose

	var ps *string
	for _, arg := range args {
		if ps != nil {
			*ps = arg
			ps = nil
			continue
		}

		switch arg {
		case "-s", "--server":
			ps = &server_str
			break
		case "-i", "--interface":
			ps = &ifname_str
			break
		case "-t", "--interval":
			ps = &interval_str
			break
		case "-c", "--config":
			ps = &config
			break
		case "-1", "--once":
			once = true
			break
		case "-f", "--force":
			force = true
			break
		case "-v":
			verbose = true
			break
		default:
			peers_str = append(peers_str, arg)
			break
		}
	}

	if ps != nil {
		printf("parameter value not set\n")
		os.Exit(1)
		return
	}

	if server_str == "" || ifname_str == "" || len(peers_str) == 0 {
		if config != "" {
			printf("some parameter not set in config\n")
			return
		}
		usage()
		return
	}

	if !strings.Contains(server_str, ":") {
		server_str += ":55550"
	}

	raddr, err := net.ResolveUDPAddr("udp", server_str)
	if err != nil {
		printf("error resolve address '%s': %v\n", server_str, err)
		os.Exit(1)
		return
	}

	peers := make([]wgtypes.Key, len(peers_str))
	for i := range peers_str {
		peers[i], err = wgtypes.ParseKey(peers_str[i])
		if err != nil {
			if len(server_str) > 9 {
				server_str = server_str[:6]+"..."
			}
			printf("error parse key '%s': %v\n", server_str, err)
			os.Exit(1)
			return
		}
	}

	if force && !once {
		printf("--force can only be used in once mode\n")
		os.Exit(1)
		return
	}

	if once {
		client_once(raddr, nil, ifname_str, peers, force, true)
		return
	}

	interval, err := strconv.Atoi(interval_str)
	if err != nil {
		printf("error parse interval '%s': %v\n", server_str, err)
		os.Exit(1)
		return
	}

	client_pull(raddr, ifname_str, peers, interval)
}
