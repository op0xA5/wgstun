package main

import (
	"fmt"
	"os"
	"strings"
)

type Configure struct {
	Listen       string
	Interface    string
	Expires      int
}

func usage() {
	fmt.Print("Usage: wgstun server [-c config_filename] [-l <listen [addr[:port]]>] [-i interface]\n" +
		          "       wgstun client [-c config_filename] [-s <server addr[:port]>] [-i interface] [-t interval] <peer>\n" +
		          "       wgstun query  -s <server addr:port> <peer>\n")
}

func main() {
	if len(os.Args) == 0 {
		os.Exit(-1)
		return
	}

	if strings.HasSuffix(os.Args[0], "-server") {
		server_main(os.Args[1:])
		return
	}
	if strings.HasSuffix(os.Args[0], "-client") {
		client_main(os.Args[1:], false)
		return
	}
	if strings.HasSuffix(os.Args[0], "-once") {
		client_main(os.Args[1:], true)
		return
	}
	if strings.HasSuffix(os.Args[0], "-query") {
		query_main(os.Args[1:])
		return
	}
	if strings.HasSuffix(os.Args[0], "-devices") {
		devices_main(os.Args[1:])
		return
	}

	if len(os.Args) == 1 {
		usage()
		os.Exit(0)
		return
	}

	switch os.Args[1] {
	case "server":
		server_main(os.Args[2:])
		return
	case "client":
		client_main(os.Args[2:], false)
		return
	case "once":
		client_main(os.Args[2:], true)
		return
	case "query":
		query_main(os.Args[2:])
		return
	case "devices":
		devices_main(os.Args[2:])
		return
	}

	usage()

	os.Exit(0)
	return
}
