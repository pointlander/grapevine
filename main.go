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
	"math/big"
	"net"
	"os"
	"os/signal"
	"sort"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/pointlander/upnp"

	"github.com/c-bata/go-prompt"
	"github.com/nictuku/dht"
	"golang.org/x/crypto/scrypt"
)

const (
	// MaxPacketSize is the maximum packet size
	MaxPacketSize = (1 << 16) - 1 - 8 - 20
	// DefaultCost is the default cost
	DefaultCost = 1 << 5
)

// Peer is a node peer
type Peer struct {
	Address string
}

// Message is a message
type Message struct {
	ID      int
	Buffer  []byte
	Message string
	Cost    *big.Int
	Time    time.Time
}

// Command is a command
type Command struct {
	Command   string
	Processed chan bool
}

var (
	// Port is the server port
	Port          = flag.Int("port", 1337, "port")
	external      string
	u             *upnp.UPNP
	nodes         = make(map[string]Peer)
	nodesMutex    sync.Mutex
	blacklist     = make(map[string]bool)
	id            = 1
	messages      = make([]Message, 0, 8)
	messagesMutex sync.Mutex
)

func cost(hash []byte) (cost *big.Int) {
	cost = big.NewInt(0)
	for i, value := range hash {
		if i == 0 {
			if value&1 == 0 {
				cost.SetUint64(1)
			} else {
				return cost
			}
			value >>= 1
			for j := 1; j < 8; j++ {
				if value&1 != 0 {
					return cost
				}
				cost = cost.Lsh(cost, 1)
				value >>= 1
			}
		} else {
			for j := 0; j < 8; j++ {
				if value&1 != 0 {
					return cost
				}
				cost = cost.Lsh(cost, 1)
				value >>= 1
			}
		}
	}
	return cost
}

func pow(buffer []byte, min *big.Int) []byte {
	nonce, n := make([]byte, 8), uint64(0)
	binary.LittleEndian.PutUint64(nonce, n)
	hash, err := scrypt.Key(buffer, nonce, 32768, 8, 1, 32)
	if err != nil {
		panic(err)
	}
	c := cost(hash)
	for c.Cmp(min) < 0 {
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
		{Text: "drop", Description: "drop a message in the database: drop 123"},
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
		external = fmt.Sprintf("%v:", ip)
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
	go drainresults(d, u)

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
		d.Stop()
		os.Exit(0)
	}()

	ticker, packets, commands :=
		time.Tick(5*time.Second), make(chan []byte, 8), make(chan Command, 8)
	go func() {
		connection, err := net.ListenPacket("udp", fmt.Sprintf(":%d", *Port+2))
		if err != nil {
			return
		}
		defer connection.Close()
		for {
			buffer := make([]byte, MaxPacketSize)
			n, _, err := connection.ReadFrom(buffer)
			if n < 1032 || ((n-1032)%8) != 0 {
				continue
			}
			buffer = buffer[:n]
			if err != nil {
				log.Println(err)
				return
			}
			packets <- buffer
		}
	}()
	go func() {
		processed := make(chan bool, 8)
		for {
			command := prompt.Input("> ", completer)
			if command == "exit" {
				done <- true
				return
			}
			commands <- Command{
				Command:   command,
				Processed: processed,
			}
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
			total := big.NewInt(0)
			for i := 0; i < len(proofs); i += 8 {
				hash, err := scrypt.Key(text[:1024+i], proofs[i:i+8], 32768, 8, 1, 32)
				if err != nil {
					panic(err)
				}
				total = total.Add(total, cost(hash))
			}
			if total.Cmp(big.NewInt(DefaultCost)) < 0 {
				break
			}
			runes := make([]rune, 256)
			for i := range runes {
				runes[i] = rune(binary.LittleEndian.Uint32(text[i*4 : i*4+4]))
			}
			messagesMutex.Lock()
			var found = 0
			for i, message := range messages {
				if message.ID == 0 {
					found = i
					break
				}
			}
			message := Message{
				ID:      id,
				Buffer:  packet,
				Message: string(runes),
				Cost:    total,
				Time:    time.Now(),
			}
			id++
			if found != 0 {
				messages[found] = message
			} else {
				messages = append(messages, message)
			}
			messagesMutex.Unlock()
		case command := <-commands:
			parts := strings.Split(command.Command, " ")
			switch parts[0] {
			case "send":
				message := strings.TrimSpace(strings.TrimPrefix(command.Command, "send"))
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
				nonce := pow(buffer, big.NewInt(DefaultCost))
				buffer = append(buffer, nonce...)
				send(buffer)
			case "messages":
				messagesMutex.Lock()
				sort.Slice(messages, func(i, j int) bool {
					if messages[i].ID == 0 || messages[j].ID == 0 {
						return true
					}
					if messages[i].Cost.Cmp(messages[j].Cost) == 0 {
						return messages[i].Time.Before(messages[j].Time)
					}
					return messages[i].Cost.Cmp(messages[j].Cost) < 0
				})
				for _, message := range messages {
					if message.ID == 0 {
						continue
					}
					fmt.Printf("%d: \"%s\" %v\n", message.ID, strings.TrimSpace(message.Message), message.Cost)
				}
				messagesMutex.Unlock()
			case "peers":
				nodesMutex.Lock()
				for node := range nodes {
					fmt.Println(node)
				}
				nodesMutex.Unlock()
			case "like":
				if len(parts) >= 2 {
					id, err := strconv.Atoi(parts[1])
					if err != nil {
						log.Println(err)
					}
					cost := -1
					if len(parts) == 3 {
						cost, err = strconv.Atoi(parts[2])
						if err != nil {
							log.Println(err)
						}
					}
					var buffer []byte
					messagesMutex.Lock()
					for _, message := range messages {
						if message.ID == id {
							buffer = message.Buffer
						}
					}
					messagesMutex.Unlock()
					if cost >= 0 {
						min := big.NewInt(1)
						min = min.Lsh(min, uint(cost))
						nonce := pow(buffer, min)
						buffer = append(buffer, nonce...)
					}
					send(buffer)
				} else {
					fmt.Printf("like required message id parameter: like 123\n")
					fmt.Printf("adding a proof of work is also allowed: like 123 6\n")
				}
			case "drop":
				if len(parts) == 2 {
					id, err := strconv.Atoi(parts[1])
					if err != nil {
						log.Println(err)
					}
					messagesMutex.Lock()
					for i, message := range messages {
						if message.ID == id {
							messages[i] = Message{}
						}
					}
					messagesMutex.Unlock()
				} else {
					fmt.Printf("drop requires a message id: drop 123\n")
				}
			default:
				fmt.Printf("unknown command %s\n", parts[0])
			}
			command.Processed <- true
		}
	}
}

func drainresults(n *dht.DHT, u *upnp.UPNP) {
	for r := range n.PeersRequestResults {
		local := make(map[string]string)
		if external != "" {
			mappings, err := u.GetPortMappings()
			if err == nil {
				for _, mapping := range mappings {
					entry := mapping.Body.GetGenericPortMappingEntryResponse
					local[fmt.Sprintf("%d", entry.NewExternalPort)] =
						fmt.Sprintf("%s:%d", entry.NewInternalClient, entry.NewInternalPort)
				}
			}
		}
		for _, peers := range r {
			for _, x := range peers {
				peer := dht.DecodePeerAddress(x)
				if blacklist[peer] {
					continue
				}
				if external != "" && strings.HasPrefix(peer, external) {
					port := strings.TrimPrefix(peer, external)
					if localPeer, ok := local[port]; ok {
						peer = localPeer
					}
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
