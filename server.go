package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"golang.zx2c4.com/wireguard/wgctrl"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
	"net"
	"net/http"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"
)

// minimum count to build cache lookup map
// use O(n) search when peer count less than minCacheDictLen
// set minCacheDictLen larger can reduce map rebuild actions
const minCacheDictLen = 16

type peerCacheItem struct {
	PublicKey         wgtypes.Key
	InternalIP        net.IP
	IP                net.IP
	Port              int
	LastHandshakeTime time.Time
}
var peerCache = struct {
	// items store all peerCacheItems
	items   []peerCacheItem
	// keyDict or ipDict use for speed up retrieve item when items count larger than minCacheDictLen
	keyDict map[wgtypes.Key]*peerCacheItem
	ipDict  map[[net.IPv6len]byte]*peerCacheItem
	expires time.Time
	err     error
	mu      sync.RWMutex
}{}

var errExpired = errors.New("cache expired")
// find peer info by peer's public key
func findPeerCache(key wgtypes.Key) (*peerCacheItem, error) {
	peerCache.mu.RLock()
	defer peerCache.mu.RUnlock()

	if time.Now().After(peerCache.expires) {
		return nil, errExpired
	}

	if peerCache.err != nil {
		return nil, peerCache.err
	}

	if peerCache.keyDict != nil {
		res, _ := peerCache.keyDict[key]
		return res, nil
	}

	for i := range peerCache.items {
		if keyEquals(key, peerCache.items[i].PublicKey) {
			return &peerCache.items[i], nil
		}
	}

	return nil, nil
}
// find peer info by peer's allowed ip, only support /32 CIDR
func findInternalIPCache(ip net.IP) (*peerCacheItem, error) {
	if ip.Equal(net.IPv4zero) {
		return nil, nil
	}

	peerCache.mu.RLock()
	defer peerCache.mu.RUnlock()

	if time.Now().After(peerCache.expires) {
		return nil, errExpired
	}

	if peerCache.err != nil {
		return nil, peerCache.err
	}

	if peerCache.keyDict != nil {
		ip16 := [net.IPv6len]byte{}
		copy(ip16[:], ip.To16())
		res, _ := peerCache.ipDict[ip16]
		return res, nil
	}

	for i := range peerCache.items {
		if ip.Equal(peerCache.items[i].InternalIP) {
			return &peerCache.items[i], nil
		}
	}

	return nil, nil
}

func updateCache() error {
	peerCache.mu.Lock()
	defer peerCache.mu.Unlock()

	now := time.Now()
	if !now.After(peerCache.expires) {
		return nil
	}

	peerCache.expires = now.Add(server_config.expire)

	wgClient, err := wgctrl.New()
	defer wgClient.Close()
	if err != nil {
		peerCache.err = err
		return err
	}

	device, err := wgClient.Device(server_config.ifname)
	if err != nil {
		peerCache.err = err
		return err
	}

	if len(device.Peers) == 0 {
		peerCache.items = peerCache.items[:0]
		peerCache.keyDict = nil
		peerCache.ipDict = nil
		return nil
	}

	if cap(peerCache.items) < len(device.Peers) {
		// extend cache array space
		_cap := ((len(device.Peers)-1)/16 + 1) * 16
		peerCache.items = make([]peerCacheItem, len(device.Peers), _cap)
	} else {
		// reuse cache array
		peerCache.items = peerCache.items[:len(device.Peers)]
	}

	for i, peer := range device.Peers {
		peerCache.items[i] = peerCacheItem{
			PublicKey:         peer.PublicKey,
			InternalIP:        net.IPv4zero,
			IP:                net.IPv4zero,
			Port:              0,
			LastHandshakeTime: peer.LastHandshakeTime,
		}

		if peer.Endpoint != nil {
			peerCache.items[i].IP = peer.Endpoint.IP
			peerCache.items[i].Port = peer.Endpoint.Port
		}

		for _, ipnet := range peer.AllowedIPs {
			ones, bits := ipnet.Mask.Size()
			if ones == bits {
				peerCache.items[i].InternalIP = ipnet.IP
				break
			}
		}
	}

	if len(peerCache.items) > minCacheDictLen {
		peerCache.keyDict = make(map[wgtypes.Key]*peerCacheItem, len(peerCache.items))
		for i := range peerCache.items {
			peerCache.keyDict[peerCache.items[i].PublicKey] = &peerCache.items[i]
		}
		peerCache.ipDict = make(map[[net.IPv6len]byte]*peerCacheItem)
		for i := range peerCache.items {
			ip16 := [net.IPv6len]byte{}
			copy(ip16[:], peerCache.items[i].InternalIP.To16())
			peerCache.ipDict[ip16] = &peerCache.items[i]
		}
	}

	return nil
}

// serve udp connection
func listenFunc(conn *net.UDPConn) {
	// buffer for read udp packet
	bufferPool := sync.Pool{
		New: func() interface{} { return make([]byte, 2048) },
	}
	// buffer for hold response data in handler function
	packetBufferPool := sync.Pool{
		New: func() interface{} { return new(bytes.Buffer) },
	}

	for {
		buffer := bufferPool.Get().([]byte)
		n, addr, err := conn.ReadFromUDP(buffer)
		if err != nil {
			bufferPool.Put(buffer)

			// a hack check an error cause by network closed by user
			str := err.Error()
			if strings.Contains(str, "use of closed network connection") {
				return
			}

			printf("ReadFromUDP err: %v\n", err)
			conn.Close()
			printf("listen goroutine exited\n")
			return
		}

		go func() {
			packetBuffer := packetBufferPool.Get().(*bytes.Buffer)
			packetBuffer.Reset()
			handleFunc(buffer[:n], addr, conn, packetBuffer)
			packetBufferPool.Put(packetBuffer)
			bufferPool.Put(buffer)
		}()
	}
}

// handle once query
func handleFunc(b []byte, addr *net.UDPAddr, conn *net.UDPConn, buffer *bytes.Buffer) {
	var req *PacketBody
	var res Packet

	// response should send separately if individualPacket is true, like Pong packet
	individualPacket := false

	for len(b) > 4 {
		packet, _b, err := ReadPacket(b)
		if err != nil {
			printf("error read packet: %v\n", err)
			continue
		}
		b = _b

		switch packet.PacketType() {
		case PacketTypePing:
			req = packet.(*PacketBody)

			pong := NewPacketBody()
			pong.Type = PacketTypePong
			copy(pong.Identity[:], req.Identity[:])
			res = pong
			individualPacket = true
			break
		case PacketTypeFindPeer:
			req = packet.(*PacketBody)

			item, err := findPeerCache(req.GetKey())
			if err == errExpired {
				err = updateCache()
				if err != nil {
					printf("error communicate wireguard device: %v\n", err)
				}
				item, err = findPeerCache(req.GetKey())
			}

			if item == nil {
				nack := NewPacketBody()
				nack.Type = PacketTypeNack
				nack.SetKey(req.GetKey())
				res = nack
			} else {
				if v4 := item.IP.To4(); v4 != nil {
					_res := NewPacketIPv4Body()
					_res.SetKey(item.PublicKey)
					_res.SetIP(item.IP)
					_res.Port = uint16(item.Port)
					_res.SetHandshakeTime(item.LastHandshakeTime)
					res = _res
				} else {
					_res := NewPacketIPv6Body()
					_res.SetKey(item.PublicKey)
					_res.SetIP(item.IP)
					_res.Port = uint16(item.Port)
					_res.SetHandshakeTime(item.LastHandshakeTime)
					res = _res
				}
			}

			break
		case PacketTypeGetMyIP:
			req = packet.(*PacketBody)

			item, err := findInternalIPCache(addr.IP)
			if err == errExpired {
				err = updateCache()
				if err != nil {
					printf("error communicate wireguard device: %v\n", err)
				}
				item, err = findPeerCache(req.GetKey())
			}

			if item == nil {
				nack := NewPacketBody()
				nack.Type = PacketTypeNack
				res = nack
			} else {
				if v4 := item.IP.To4(); v4 != nil {
					_res := NewPacketIPv4Body()
					_res.SetIP(item.IP)
					_res.Port = uint16(item.Port)
					_res.SetHandshakeTime(item.LastHandshakeTime)
					res = _res
				} else {
					_res := NewPacketIPv6Body()
					_res.SetIP(item.IP)
					_res.Port = uint16(item.Port)
					_res.SetHandshakeTime(item.LastHandshakeTime)
					res = _res
				}
			}

			break
		}

		if individualPacket {
			if buffer.Len() > 0 {
				_, err = conn.WriteToUDP(buffer.Bytes(), addr)
				if err != nil {
					printf("error write packet: %v\n", err)
				}
			}

			buffer.Reset()

			if buffer.Cap() == 0 {
				buffer.Grow(MaxPacketSize)
			}
			WritePacket(buffer, res)
			_, err = conn.WriteToUDP(buffer.Bytes(), addr)
			if err != nil {
				printf("error write packet: %v\n", err)
			}

			buffer.Reset()
		} else {
			bufferLen := buffer.Len()
			if  bufferLen > 0 && bufferLen + res.PacketSize() > MaxPacketSize {
				_, err = conn.WriteToUDP(buffer.Bytes(), addr)
				if err != nil {
					printf("error write packet: %v\n", err)
				}

				buffer.Reset()
			}

			if buffer.Cap() == 0 {
				buffer.Grow(MaxPacketSize)
			}
			WritePacket(buffer, res)
		}
	}

	if buffer.Len() > 0 {
		_, err := conn.WriteToUDP(buffer.Bytes(), addr)
		if err != nil {
			printf("error write packet: %s\n", err)
		}
	}
}

var httpServer *http.Server
func httpListenFunc(l *net.TCPListener, root string) {
	http.Handle("/peer", http.HandlerFunc(httpHandler))
	http.Handle("/", http.FileServer(http.Dir(root)))

	httpServer = &http.Server{
		Addr:              l.Addr().String(),
		ReadTimeout:       60 * time.Second,
		ReadHeaderTimeout: 60 * time.Second,
		WriteTimeout:      300 * time.Second,
		IdleTimeout:       300 * time.Second,
	}

	err := httpServer.Serve(l)
	if err != nil {
		printf("error serve http: %s\n", err)
	}
}

func httpHandler(w http.ResponseWriter, r *http.Request) {
	err := r.ParseForm()
	if err != nil {
		http.Error(w, "400 Bad Request", http.StatusBadRequest)
		return
	}

	key := r.Form.Get("public_key")
	if key == "" {
		key = r.Form.Get("key")
	}
	if key == "" {
		http.Error(w, "404 Not Found", http.StatusNotFound)
		return
	}

	typ := r.Form.Get("type")

	wgkey, err := wgtypes.ParseKey(strings.ReplaceAll(key, " ", "+"))
	if err != nil {
		http.Error(w, "404 Not Found", http.StatusNotFound)
		return
	}

	item, err := findPeerCache(wgkey)
	if err == errExpired {
		err = updateCache()
		if err != nil {
			printf("error communicate wireguard device: %v\n", err)
			http.Error(w, "500 Internal Server Error", http.StatusInternalServerError)
			return
		}
		item, err = findPeerCache(wgkey)
	}

	if item == nil {
		http.Error(w, "404 Not Found", http.StatusNotFound)
		return
	}

	if typ == "json" {
		body, err := json.Marshal(struct {
			Addr          string `json:"addr"`
			IP            string `json:"ip"`
			LastHandshake string `json:"last_handshake"`
		}{
			item.IP.String() + ":" + strconv.Itoa(item.Port),
			item.IP.String(),
			item.LastHandshakeTime.Format("2006-01-02 15:04:05"),
		})
		if err != nil {
			http.Error(w, "500 Internal Server Error", http.StatusInternalServerError)
			return
		}
		w.Header().Set("Expires", time.Now().Add(-1 * time.Second).Format(http.TimeFormat))
		w.Header().Set("Last-Modified", item.LastHandshakeTime.Format(http.TimeFormat))
		w.Header().Set("Cache-Control", "no-cache")
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("Content-Type", "text/json; charset=utf-8")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(body)
		return
	}

	w.Header().Set("Expires", time.Now().Add(-1 * time.Second).Format(http.TimeFormat))
	w.Header().Set("Last-Modified", item.LastHandshakeTime.Format(http.TimeFormat))
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte(item.IP.String() + ":" + strconv.Itoa(item.Port)))
	return
}

var server_config = struct {
	ifname string
	expire time.Duration
}{}

func server_main(args []string) {
	var listen_str string = ":55550"
	var ifname_str string
	var expire_str string = "5"
	var verbose bool
	var listen_http_str string = ""
	var http_root string = "./wwwroot"
	_ = verbose

	var ps *string
	for _, arg := range args {
		if ps != nil {
			*ps = arg
			ps = nil
			continue
		}

		switch arg {
		case "-l", "--listen":
			ps = &listen_str
			break
		case "-e", "--expire":
			ps = &expire_str
			break
		case "-i", "--interface":
			ps = &ifname_str
			break
		case "-v":
			verbose = true
			break
		case "-w", "--web":
			ps = &listen_http_str
			break
		case "-r", "--root":
			ps = &http_root
			break
		default:
			printf("unknown parameter '%s'\n", arg)
			os.Exit(1)
			break
		}
	}

	if ps != nil {
		printf("parameter value not set\n")
		os.Exit(1)
		return
	}

	if ifname_str == ""{
		usage()
		return
	}

	listenAddr, err := net.ResolveUDPAddr("udp", listen_str)
	if err != nil {
		printf("error resolve address '%s': %v\n", listen_str, err)
		os.Exit(1)
		return
	}

	var httpListenAddr *net.TCPAddr
	if listen_http_str != "" {
		httpListenAddr, err = net.ResolveTCPAddr("tcp", listen_http_str)
		if err != nil {
			printf("error resolve address '%s': %v\n", listen_http_str, err)
			os.Exit(1)
			return
		}
	}

	expireSec, err := strconv.Atoi(expire_str)
	if err != nil {
		printf("error parse expire '%s': %v\n", expire_str, err)
		os.Exit(1)
		return
	}

	if expireSec < 1 {
		expireSec = 1
	}
	server_config.expire = time.Second * time.Duration(expireSec)
	server_config.ifname = ifname_str

	listener, err := net.ListenUDP("udp", listenAddr)
	if err != nil {
		printf("error create socket '%s': %v\n", listenAddr.String(), err)
		os.Exit(1)
		return
	}

	printf("server started on '%s'\n", listenAddr.String())

	var httpListener *net.TCPListener
	if httpListenAddr != nil {
		httpListener, err = net.ListenTCP("tcp", httpListenAddr)
		if err != nil {
			printf("error create socket '%s': %v\n", httpListenAddr.String(), err)
			os.Exit(1)
			return
		}

		printf("http server started on '%s'\n", httpListenAddr.String())
	}

	go listenFunc(listener)
	if httpListener != nil {
		go httpListenFunc(httpListener, http_root)
	}

	signalC := make(chan os.Signal)
	signal.Notify(signalC, syscall.SIGHUP, syscall.SIGQUIT, syscall.SIGTERM)
	s := <- signalC
	printf("signal %s received\n", s.String())

	_ = listener.Close()
	if httpServer != nil {
		httpServer.Close()
	}
	if httpListener != nil {
		_ = httpListener.Close()
	}

	printf("server exited\n")
	os.Exit(0)
}
