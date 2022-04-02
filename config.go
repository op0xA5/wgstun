package main

type Config struct {
	Interface string
	Server    string   `json:"server"`
	Peers     []string `json:"peers"`
	Interval  int      `json:"interval"`
}


