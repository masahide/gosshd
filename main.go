package main

import (
	"flag"

	"github.com/masahide/gosshd/client"
	"github.com/masahide/gosshd/server"
)

func main() {
	var sv bool
	flag.BoolVar(&sv, "server", sv, "server")
	flag.Parse()
	if sv {
		server.StartServe()
	} else {
		client.Dial()
	}
}
