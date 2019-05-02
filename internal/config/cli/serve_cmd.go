package cli

import (
// "net"
)

type ServeCmd struct {
	ConfigFile    string
	CheckConfig   bool
	TimeoutOffset float64
	HistoryLimit  uint64

	ListenAddress ListenAddress
	AdminAddress  ListenAddress
}

type ListenAddress struct {
	Address string
	Port    int
}
