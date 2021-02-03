// Copyright 2021 The Grapevine Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package main

import (
	"crypto/sha1"
	"encoding/binary"
	"encoding/hex"
	"flag"
	"fmt"
	"log"
	"net"
	"os"
	"os/signal"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/c-bata/go-prompt"
	"github.com/metricube/upnp"
	"github.com/nictuku/dht"
	"golang.org/x/crypto/scrypt"
)

// Peer is a node peer
type Peer struct {
	Address string
}

// Message is a message
type Message struct {
	Message string
	Cost    uint64
	Time    time.Time
}

var (
	// Port is the server port
	Port       = flag.Int("port", 1337, "port")
	u          *upnp.UPNP
	nodes      = make(map[string]Peer)
	nodesMutex sync.Mutex
	address    string
	messages   = make([]Message, 0, 8)
)

func cost(hash []byte) (cost uint64) {
	for i, value := range hash {
		if i == 0 {
			cost = uint64(value & 1)
			value >>= 1
			for j := 1; j < 8; j++ {
				if value&1 != 0 {
					return cost
				}
				cost <<= 1
				value >>= 1
			}
		} else {
			for j := 0; j < 8; j++ {
				if value&1 != 0 {
					return cost
				}
				cost <<= 1
				value >>= 1
			}
		}
	}
	return cost
}

func completer(d prompt.Document) []prompt.Suggest {
	s := []prompt.Suggest{
		{Text: "exit", Description: "Exit the application"},
	}
	return prompt.FilterHasPrefix(s, d.GetWordBeforeCursor(), true)
}

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

	ip := upnp.GetLocalAddress()
	if ip != nil {
		address = fmt.Sprintf("%v:%d", ip, *Port)
	}
	u, err = upnp.NewUPNP()
	if err != nil {
		u = nil
	}
	if u != nil {
		u.AddPortMapping(*Port, *Port, "UDP")
		u.AddPortMapping(*Port+2, *Port+2, "UDP")
		ip, err := u.ExternalIPAddress()
		if err != nil {
			panic(err)
		}
		address = fmt.Sprintf("%v:%d", ip, *Port)
	}

	config := dht.NewConfig()
	config.Port = *Port
	d, err := dht.New(config)
	if err != nil {
		panic(err)
	}

	if err = d.Start(); err != nil {
		panic(err)
	}
	go drainresults(d)

	c, done := make(chan os.Signal), make(chan bool)
	signal.Notify(c, os.Interrupt, syscall.SIGTERM)
	go func() {
		select {
		case <-c:
		case <-done:
		}
		fmt.Println("\rCleaning up...")
		if u != nil {
			u.DelPortMapping(*Port, "UDP")
			u.DelPortMapping(*Port+2, "UDP")
		}
		d.RemoveInfoHash(string(ih))
		os.Exit(0)
	}()

	ticker, packets, commands := time.Tick(5*time.Second), make(chan []byte, 8), make(chan string, 8)
	go func() {
		connection, err := net.ListenPacket("udp", fmt.Sprintf(":%d", *Port+2))
		if err != nil {
			return
		}
		defer connection.Close()
		for {
			buffer := make([]byte, 1024+8*8)
			_, _, err := connection.ReadFrom(buffer)
			if err != nil {
				log.Println(err)
				return
			}
			packets <- buffer
		}
	}()
	go func() {
		for {
			command := prompt.Input("> ", completer)
			if command == "exit" {
				done <- true
				return
			}
			commands <- command
		}
	}()
	for {
		select {
		case <-ticker:
			d.PeersRequestPort(string(ih), true, *Port+2)
		case packet := <-packets:
			text := packet[:1024]
			proofs := packet[1024:]
			total := uint64(0)
			for i := 0; i < len(proofs); i += 8 {
				hash, err := scrypt.Key(text, proofs[i:i+8], 32768, 8, 1, 32)
				if err != nil {
					log.Println(err)
				}
				total += cost(hash)
			}
			runes := make([]rune, 256)
			for i := range runes {
				runes[i] = rune(binary.LittleEndian.Uint32(text[i*4 : i*4+4]))
			}
			messages = append(messages, Message{
				Message: string(runes),
				Cost:    total,
				Time:    time.Now(),
			})
		case command := <-commands:
			parts := strings.Split(command, " ")
			if parts[0] == "send" {

			}
		}
	}
}

func drainresults(n *dht.DHT) {
	for r := range n.PeersRequestResults {
		for _, peers := range r {
			for _, x := range peers {
				peer := dht.DecodePeerAddress(x)
				nodesMutex.Lock()
				nodes[peer] = Peer{
					Address: peer,
				}
				nodesMutex.Unlock()
			}
		}
	}
}