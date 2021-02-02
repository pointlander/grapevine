// Copyright 2021 The Grapevine Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package main

import (
	"crypto/sha1"
	"encoding/hex"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/metricube/upnp"
	"github.com/nictuku/dht"
)

// Port is the server port
var Port = flag.Int("port", 1234, "port")

func main() {
	flag.Parse()

	hash := sha1.Sum([]byte("grapevine#main"))
	room := hex.EncodeToString(hash[:])
	fmt.Println(room)
	ih, err := dht.DecodeInfoHash(room)
	if err != nil {
		panic(err)
	}
	fmt.Println(ih)

	u, err := upnp.NewUPNP()
	if err != nil {
		panic(err)
	}
	u.AddPortMapping(*Port, *Port, "UDP")

	d, err := dht.New(nil)
	if err != nil {
		fmt.Fprintf(os.Stderr, "New DHT error: %v", err)
		os.Exit(1)

	}

	if err = d.Start(); err != nil {
		fmt.Fprintf(os.Stderr, "DHT start error: %v", err)
		os.Exit(1)
	}
	go drainresults(d)

	c := make(chan os.Signal)
	signal.Notify(c, os.Interrupt, syscall.SIGTERM)
	go func() {
		<-c
		fmt.Println("\r- Ctrl+C pressed in Terminal")
		u.DelPortMapping(*Port, "UDP")
		d.RemoveInfoHash(string(ih))
		os.Exit(0)
	}()

	for {
		d.PeersRequestPort(string(ih), true, *Port)
		time.Sleep(5 * time.Second)
	}
}

func drainresults(n *dht.DHT) {
	fmt.Println("=========================== DHT")
	fmt.Println("Note that there are many bad nodes that reply to anything you ask.")
	fmt.Println("Peers found:")
	for r := range n.PeersRequestResults {
		for _, peers := range r {
			for _, x := range peers {
				fmt.Printf("%v\n", dht.DecodePeerAddress(x))
			}
		}
	}
}
