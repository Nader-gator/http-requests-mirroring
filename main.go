// Original Copyright 2012 Google, Inc. All rights reserved.
//
// Use of this source code is governed by a BSD-style license
// that can be found in the LICENSE file in the root of the source
// tree.

// Modification Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: BSD-3-Clause

package main

import (
	"bufio"
	"flag"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/IBM/sarama"
	"github.com/google/gopacket"
	"github.com/google/gopacket/examples/util"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	"github.com/google/gopacket/tcpassembly"
	"github.com/google/gopacket/tcpassembly/tcpreader"
)

var kafkaTopic = flag.String("kafka-topic", "", "Kafka topic to write to.")
var kafkaBrokers = flag.String("kafka-brokers", "", "Comma-separated list of Kafka brokers.")

// Build a simple HTTP request parser using tcpassembly.StreamFactory and tcpassembly.Stream interfaces

// httpStreamFactory implements tcpassembly.StreamFactory
type httpStreamFactory struct {
	producer sarama.SyncProducer
}

// httpStream will handle the actual decoding of http requests.
type httpStream struct {
	net, transport gopacket.Flow
	r              tcpreader.ReaderStream
	producer       sarama.SyncProducer
}

func (h *httpStreamFactory) New(net, transport gopacket.Flow) tcpassembly.Stream {
	hstream := &httpStream{
		net:       net,
		transport: transport,
		r:         tcpreader.NewReaderStream(),
		producer:  h.producer,
	}
	go hstream.run() // Important... we must guarantee that data from the reader stream is read.

	// ReaderStream implements tcpassembly.Stream, so we can return a pointer to it.
	return &hstream.r
}

func (h *httpStream) run() {
	buf := bufio.NewReader(&h.r)
	for {
		req, err := http.ReadRequest(buf)
		if err == io.EOF {
			// We must read until we see an EOF... very important!
			return
		} else if err != nil {
			log.Println("Error reading stream", h.net, h.transport, ":", err)
		} else {
			body, bErr := io.ReadAll(req.Body)
			if bErr != nil {
				return
			}
			req.Body.Close()
			go h.writeToKafka(req, body)
		}
	}
}

type RequestInfo struct {
	Method  string      `json:"method"`
	URL     string      `json:"url"`
	Headers http.Header `json:"headers"`
	Body    string      `json:"body"`
}

func (h *httpStream) writeToKafka(req *http.Request, body []byte) {
	requestInfo := &RequestInfo{
		Method:  req.Method,
		URL:     req.RequestURI,
		Headers: req.Header,
		Body:    string(body),
	}

	log.Println("Write to kafka:", requestInfo)
	// jsonData, err := json.Marshal(requestInfo)
	// if err != nil {
	// 	log.Println("Error marshalling JSON:", err)
	// 	return
	// }

	// msg := &sarama.ProducerMessage{
	// 	Topic: *kafkaTopic,
	// 	Value: sarama.StringEncoder(jsonData),
	// }

	// _, _, err = h.producer.SendMessage(msg)
	// if err != nil {
	// 	log.Println("Failed to send message to Kafka:", err)
	// }
}

// Listen for incoming connections.
func openTCPClient() {
	ln, err := net.Listen("tcp", ":4789")
	if err != nil {
		// If TCP listener cannot be established, NLB health checks would fail
		// For this reason, we OS.exit
		log.Println("Error listening on TCP", ":", err)
		os.Exit(1)
	}
	log.Println("Listening on TCP 4789")
	for {
		// Listen for an incoming connection and close it immediately.
		conn, _ := ln.Accept()
		conn.Close()
	}
}

func run(netit string) {
	defer util.Run()()
	var handle *pcap.Handle
	var err error

	if *kafkaTopic == "" || *kafkaBrokers == "" {
		log.Fatal("Kafka topic and brokers must be specified.")
	}

	logfile, err := os.OpenFile("/home/ec2-user/logfile.txt", os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0666)
	if err != nil {
		log.Fatal("Failed to open log file:", err)
	}
	defer logfile.Close()
	// log.SetOutput(logfile)

	config := sarama.NewConfig()
	config.Producer.Return.Successes = true
	producer, err := sarama.NewSyncProducer(strings.Split(*kafkaBrokers, ","), config)
	if err != nil {
		log.Println("Failed to create Kafka producer:", err)
	}
	// defer producer.Close()

	log.Printf("Starting capture on interface %s", netit)
	handle, err = pcap.OpenLive(netit, 262144, true, pcap.BlockForever)
	if err != nil {
		log.Fatal(err)
	}
	// Set up assembly
	streamFactory := &httpStreamFactory{producer: producer}
	streamPool := tcpassembly.NewStreamPool(streamFactory)
	assembler := tcpassembly.NewAssembler(streamPool)

	log.Println("reading in packets")
	// Read in packets, pass to assembler.
	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
	packets := packetSource.Packets()
	ticker := time.Tick(time.Minute)

	//Open a TCP Client, for NLB Health Checks only

	for {
		select {
		case packet := <-packets:
			// A nil packet indicates the end of a pcap file.
			if packet == nil {
				return
			}
			if packet.NetworkLayer() == nil || packet.TransportLayer() == nil || packet.TransportLayer().LayerType() != layers.LayerTypeTCP {
				log.Println("Unusable packet")
				continue
			}
			tcp := packet.TransportLayer().(*layers.TCP)
			assembler.AssembleWithTimestamp(packet.NetworkLayer().NetworkFlow(), tcp, packet.Metadata().Timestamp)

		case <-ticker:
			// Every minute, flush connections that haven't seen activity in the past 1 minute.
			assembler.FlushOlderThan(time.Now().Add(time.Minute * -1))
		}
	}
}
func main() {
	flag.Parse()
	go openTCPClient()

	go run("vxlan0")
	go run("vxlan1")
	c := make(chan struct{})
	<-c
}
