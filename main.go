// Copyright 2021 The Grapevine Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package main

import (
	"bytes"
	"crypto/sha1"
	"encoding/binary"
	"encoding/hex"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"os/signal"
	"sort"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/c-bata/go-prompt"
	"github.com/metricube/upnp"
	"github.com/nictuku/dht"
	"golang.org/x/crypto/scrypt"
)

// DefaultCost is the default cost
const DefaultCost = 1 << 5

// Peer is a node peer
type Peer struct {
	Address string
}

// Message is a message
type Message struct {
	ID      int
	Buffer  []byte
	Message string
	Cost    uint64
	Time    time.Time
}

var (
	// Port is the server port
	Port          = flag.Int("port", 1337, "port")
	u             *upnp.UPNP
	nodes         = make(map[string]Peer)
	nodesMutex    sync.Mutex
	blacklist     = make(map[string]bool)
	id            = 0
	messages      = make([]Message, 0, 8)
	messagesMutex sync.Mutex
)

func cost(hash []byte) (cost uint64) {
	for i, value := range hash {
		if i == 0 {
			if value&1 == 0 {
				cost = 1
			} else {
				return 0
			}
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

func pow(buffer []byte, min uint64) []byte {
	nonce, n := make([]byte, 8), uint64(0)
	binary.LittleEndian.PutUint64(nonce, n)
	hash, err := scrypt.Key(buffer, nonce, 32768, 8, 1, 32)
	if err != nil {
		panic(err)
	}
	c := cost(hash)
	for c < min {
		n++
		binary.LittleEndian.PutUint64(nonce, n)
		hash, err := scrypt.Key(buffer, nonce, 32768, 8, 1, 32)
		if err != nil {
			panic(err)
		}
		c = cost(hash)
	}
	return nonce
}

func send(buffer []byte) {
	nodesMutex.Lock()
	for addr := range nodes {
		raddr, err := net.ResolveUDPAddr("udp", addr)
		if err != nil {
			log.Println(err)
			break
		}
		connection, err := net.DialUDP("udp", nil, raddr)
		if err != nil {
			log.Println(err)
			break
		}
		reader := bytes.NewReader(buffer)
		_, err = io.Copy(connection, reader)
		if err != nil {
			delete(nodes, addr)
		}
		connection.Close()
	}
	nodesMutex.Unlock()
}

func completer(d prompt.Document) []prompt.Suggest {
	s := []prompt.Suggest{
		{Text: "send", Description: "send a message"},
		{Text: "messages", Description: "list messages in the database"},
		{Text: "peers", Description: "list peer nodes"},
		{Text: "like", Description: "like a message in the database: like 123 5"},
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
		blacklist[fmt.Sprintf("%v:%d", ip, *Port)] = true
		blacklist[fmt.Sprintf("%v:%d", ip, *Port+2)] = true
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
		blacklist[fmt.Sprintf("%v:%d", ip, *Port)] = true
		blacklist[fmt.Sprintf("%v:%d", ip, *Port+2)] = true
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

	ticker, packets, commands, processed :=
		time.Tick(5*time.Second), make(chan []byte, 8), make(chan string, 8), make(chan bool, 8)
	go func() {
		connection, err := net.ListenPacket("udp", fmt.Sprintf(":%d", *Port+2))
		if err != nil {
			return
		}
		defer connection.Close()
		for {
			buffer := make([]byte, 1024+8*8)
			n, _, err := connection.ReadFrom(buffer)
			if n < 1024 {
				continue
			}
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
			<-processed
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
				hash, err := scrypt.Key(text[:1024+i], proofs[i:i+8], 32768, 8, 1, 32)
				if err != nil {
					panic(err)
				}
				total += cost(hash)
			}
			if total < DefaultCost {
				break
			}
			runes := make([]rune, 256)
			for i := range runes {
				runes[i] = rune(binary.LittleEndian.Uint32(text[i*4 : i*4+4]))
			}
			messagesMutex.Lock()
			messages = append(messages, Message{
				ID:      id,
				Buffer:  packet,
				Message: string(runes),
				Cost:    total,
				Time:    time.Now(),
			})
			id++
			messagesMutex.Unlock()
		case command := <-commands:
			parts := strings.Split(command, " ")
			if parts[0] == "send" {
				message := strings.Join(parts[1:], " ")
				runes := make([]rune, 256)
				for i := range runes {
					runes[i] = ' '
				}
				for i, r := range []rune(message) {
					runes[i] = r
				}
				buffer := make([]byte, 1024)
				for i, r := range runes {
					binary.LittleEndian.PutUint32(buffer[4*i:4*i+4], uint32(r))
				}
				nonce := pow(buffer, DefaultCost)
				buffer = append(buffer, nonce...)
				send(buffer)
			} else if parts[0] == "messages" {
				messagesMutex.Lock()
				sort.Slice(messages, func(i, j int) bool {
					if messages[j].Cost == messages[i].Cost {
						return messages[j].Time.Before(messages[i].Time)
					}
					return messages[j].Cost < messages[i].Cost
				})
				for _, message := range messages {
					fmt.Printf("%d: \"%s\" %d\n", message.ID, strings.TrimSpace(message.Message), message.Cost)
				}
				messagesMutex.Unlock()
			} else if parts[0] == "peers" {
				nodesMutex.Lock()
				for node := range nodes {
					fmt.Println(node)
				}
				nodesMutex.Unlock()
			} else if parts[0] == "like" {
				if len(parts) == 3 {
					id, err := strconv.Atoi(parts[1])
					if err != nil {
						log.Println(err)
					}
					cost, err := strconv.Atoi(parts[2])
					if err != nil {
						log.Println(err)
					}
					var buffer []byte
					messagesMutex.Lock()
					for _, message := range messages {
						if message.ID == id {
							buffer = message.Buffer
						}
					}
					messagesMutex.Unlock()
					nonce := pow(buffer, 1<<cost)
					buffer = append(buffer, nonce...)
					send(buffer)
				}
			}
			processed <- true
		}
	}
}

func drainresults(n *dht.DHT) {
	for r := range n.PeersRequestResults {
		for _, peers := range r {
			for _, x := range peers {
				peer := dht.DecodePeerAddress(x)
				if blacklist[peer] {
					continue
				}
				nodesMutex.Lock()
				nodes[peer] = Peer{
					Address: peer,
				}
				nodesMutex.Unlock()
			}
		}
	}
}
