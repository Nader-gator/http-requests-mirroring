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
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"runtime"
	"strings"
	"time"

	"github.com/IBM/sarama"
	"github.com/aws/aws-msk-iam-sasl-signer-go/signer"
	"github.com/google/gopacket"
	"github.com/google/gopacket/examples/util"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	"github.com/google/gopacket/tcpassembly"
	"github.com/google/gopacket/tcpassembly/tcpreader"
	"github.com/google/uuid"
)

var kafkaTopic = flag.String("kafka-topic", "", "Kafka topic to write to.")
var kafkaBrokers = flag.String("kafka-brokers", "", "Comma-separated list of Kafka brokers.")
var networkIDs = flag.String("network-ids", "", "Network IDs of mirroring sessions")
var skipKafka = flag.Bool("skip-kafka", false, "Whether to exit or not on kafka avaialbility")
var readSome = flag.Int("read-msg", 0, "Number of messages to read(0 for producer mode)")

// var filter = flag.String("filter", "tcp and dst port 80", "BPF filter for pcap")

const (
	HeartBeat = iota
	NetworkReq
)

type httpStreamFactory struct {
	producer sarama.AsyncProducer
}

const SNAPLEN = 1600

type httpStream struct {
	net, transport gopacket.Flow
	r              tcpreader.ReaderStream
	producer       sarama.AsyncProducer
}

func (h *httpStreamFactory) New(net, transport gopacket.Flow) tcpassembly.Stream {
	hstream := &httpStream{
		net:       net,
		transport: transport,
		r:         tcpreader.NewReaderStream(),
		producer:  h.producer,
	}
	go hstream.run()

	return &hstream.r
}

func (h *httpStream) run() {
	buf := bufio.NewReader(&h.r)
	for {
		req, err := http.ReadRequest(buf)
		if err == io.EOF {
			return
		} else if err != nil {
			e := fmt.Sprint(err)
			if !(strings.HasPrefix(e, "malformed HTTP") || strings.HasPrefix(e, "invalid method")) {
				log.Println("Error reading stream", h.net, h.transport, ":", err)
			}
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

type RequestMeta struct {
	Timestamp     time.Time   `json:"timestamp"`
	SrcIP         string      `json:"src_ip"`
	DstIP         string      `json:"dst_ip"`
	Method        string      `json:"method"`
	URL           string      `json:"url"`
	Proto         string      `json:"proto"`
	Host          string      `json:"host"`
	ContentLength int64       `json:"content_length"`
	Header        http.Header `json:"header"`
	Body          string      `json:"body,omitempty"`
}

type Msg struct {
	Timestamp time.Time       `json:"timestamp"`
	Data      json.RawMessage `json:"data"`
	Type      int             `json:"type"`
}

func printMsg(msg Msg) {
	switch msg.Type {
	case NetworkReq:
		{
			var data RequestMeta
			if err := json.Unmarshal(msg.Data, &data); err != nil {
				log.Fatal(err)
			}
			log.Println(fmt.Sprintf("%v+", data))
		}
	case HeartBeat:
		{
			log.Println(fmt.Sprintf("Heartbeat: %v+", msg))
		}
	default:
		{
			log.Fatal("Unknow msg type")
		}
	}
}

func writeHeartBeatToKafka(producer sarama.AsyncProducer) {
	location, err := time.LoadLocation("America/Los_Angeles")
	timestamp := time.Now().Local().In(location)
	if producer == nil {
		fmt.Println("Got heartbeat without kafka", timestamp)
		return
	}
	if err != nil {
		panic(err)
	}
	meta := Msg{
		Timestamp: timestamp,
		Type:      HeartBeat,
	}
	jsonData, err := json.Marshal(meta)
	if err != nil {
		log.Println("Error marshalling JSON:", err)
		return
	}
	msg := &sarama.ProducerMessage{
		Topic: *kafkaTopic,
		Value: sarama.StringEncoder(jsonData),
	}
	producer.Input() <- msg
}
func (h *httpStream) writeToKafka(req *http.Request, body []byte) {
	meta := RequestMeta{
		Timestamp:     time.Now().UTC(),
		SrcIP:         h.net.Src().String(),
		DstIP:         h.net.Dst().String(),
		Method:        req.Method,
		URL:           req.URL.String(),
		Proto:         req.Proto,
		Host:          req.Host,
		ContentLength: req.ContentLength,
		Header:        req.Header,
		Body:          string(body),
	}

	jsonData, err := json.Marshal(meta)
	if err != nil {
		log.Println("Error marshalling JSON:", err)
		return
	}

	msg := &sarama.ProducerMessage{
		Topic: *kafkaTopic,
		Value: sarama.StringEncoder(jsonData),
	}

	if h.producer != nil {
		h.producer.Input() <- msg
	} else {
		log.Println(fmt.Sprintf("%+v", meta))
	}
}

func openTCPClient() {
	http.HandleFunc(
		"/",
		func(w http.ResponseWriter, r *http.Request) { fmt.Fprintln(w, "Ok") },
	)
	port := 4789
	log.Println("Listening on:", port)
	log.Fatal(http.ListenAndServe(fmt.Sprintf(":%d", port), nil))
}

type MSKTokenProvider struct {
}

func (t *MSKTokenProvider) Token() (*sarama.AccessToken, error) {
	token, _, err := signer.GenerateAuthToken(context.TODO(), "us-east-1")
	return &sarama.AccessToken{Token: token}, err
}

func watchNetwork(netit string) {
	defer util.Run()()
	var err error
	successes := 0

	if !(*skipKafka) && (*kafkaTopic == "" || *kafkaBrokers == "" || *networkIDs == "") {
		log.Fatal("Kafka topic, brokers, and network IDs must be specified.")
	}

	var producer sarama.AsyncProducer
	if *skipKafka {
		log.Println("Skipping kafka...")

	} else {
		log.Println("Connecting..")
		// AWS configuration

		log.Println("Got IAM session")
		// Kafka configuration
		config := sarama.NewConfig()
		config.Producer.Return.Successes = false
		config.Producer.Return.Errors = false
		config.Producer.RequiredAcks = sarama.WaitForAll
		config.Producer.Retry.Max = 5

		// Configure IAM authentication
		config.Net.SASL.Enable = true
		config.Net.SASL.Mechanism = sarama.SASLTypeOAuth
		config.ClientID = uuid.NewString()
		config.Net.SASL.TokenProvider = &MSKTokenProvider{}

		// TLS configuration for AWS MSK
		config.Net.TLS.Enable = true
		config.Net.DialTimeout = 5 * time.Second

		// Create producer
		log.Println("Starting producer")

		err = config.Validate()
		if err != nil {
			log.Fatal(err)
		}
		log.Println("Connected..")

		producer, err = sarama.NewAsyncProducer(strings.Split(*kafkaBrokers, ","), config)
		if err != nil {
			log.Fatalf("Failed to create producer: %v", err)
		}
		defer producer.AsyncClose()
		log.Println("starting producer", successes)
		go func() {
			for {
				<-producer.Successes()
				successes += 1
				if successes%10 == 0 {
					log.Println("Current success num: ", successes)
				}
			}
		}()
	}

	log.Printf("Starting capture on interface %s", netit)
	handle, err := pcap.OpenLive(netit, int32(SNAPLEN), true, pcap.BlockForever)
	if err != nil {
		log.Fatal(err)
	}
	// if err := handle.SetBPFFilter(*filter); err != nil {
	// 	log.Fatal(err)
	// }
	streamFactory := &httpStreamFactory{producer: producer}
	streamPool := tcpassembly.NewStreamPool(streamFactory)
	assembler := tcpassembly.NewAssembler(streamPool)

	log.Println("reading in packets")
	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
	packets := packetSource.Packets()
	ticker := time.Tick(time.Second * 30)

	go writeHeartBeatToKafka(producer)

	count := 0
	for {
		select {
		case packet := <-packets:
			if packet == nil {
				return
			}
			if packet.NetworkLayer() == nil || packet.TransportLayer() == nil || packet.TransportLayer().LayerType() != layers.LayerTypeTCP {
				count += 1
				if count%100 == 0 {
					log.Println("Unusable packet, error num %i", count)
				}
				continue
			}
			tcp := packet.TransportLayer().(*layers.TCP)
			assembler.AssembleWithTimestamp(packet.NetworkLayer().NetworkFlow(), tcp, packet.Metadata().Timestamp)
		case <-ticker:
			go writeHeartBeatToKafka(producer)
			assembler.FlushOlderThan(time.Now().Add(time.Minute * -1))
		}
	}
}
func main() {
	flag.Parse()

	if *readSome > 0 {
		// Configure Sarama
		log.Println("reading messages")
		config := sarama.NewConfig()
		config.Net.SASL.Enable = true
		config.Net.SASL.Mechanism = sarama.SASLTypeOAuth
		config.ClientID = uuid.NewString()
		config.Net.SASL.TokenProvider = &MSKTokenProvider{}

		// Consumer settings
		config.Consumer.Return.Errors = false
		config.Consumer.Offsets.Initial = sarama.OffsetNewest // or OffsetOldest

		// TLS configuration for AWS MSK
		config.Net.TLS.Enable = true
		config.Net.DialTimeout = 5 * time.Second

		// Create consumer
		consumer, err := sarama.NewConsumer(strings.Split(*kafkaBrokers, ","), config)
		if err != nil {
			log.Fatalf("Failed to create consumer: %v", err)
		}
		log.Println("consumer started")
		defer consumer.Close()

		// Consume from topic
		topics, err := consumer.Topics()
		if err != nil {
			log.Fatal(err)
		}
		log.Println(topics)

		parts, err := consumer.Partitions(*kafkaTopic)
		if err != nil {
			log.Fatal(err)
		}
		log.Println(parts)
		for _, v := range parts {
			go func() {
				partitionConsumer, err := consumer.ConsumePartition(*kafkaTopic, v, sarama.OffsetOldest)
				if err != nil {
					log.Fatalf("Failed to start consumer: %v", err)
				}
				defer partitionConsumer.Close()

				fmt.Println("Consumer started. Waiting for messages...")

				// Consume messages
				cnt := 0
				for {
					if cnt < *readSome {
						select {
						case msg := <-partitionConsumer.Messages():
							var data Msg
							err := json.Unmarshal(msg.Value, &data)
							if err != nil {
								log.Fatalf("msg not readable: %s", string(msg.Value))
							}
							printMsg(data)
							cnt++
						case err := <-partitionConsumer.Errors():
							log.Printf("Error: %v\n", err)
						}
					}
				}
			}()
		}
	} else {
		logfile, err := os.OpenFile("logfile.txt", os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0666)
		if err != nil {
			log.Fatal("Failed to open log file:", err)
		}
		defer logfile.Close()
		log.SetOutput(logfile)
		go openTCPClient()
		go func() {
			for {
				log.Println("Goroutine count: ", runtime.NumGoroutine())
				time.Sleep(time.Minute)
			}
		}()
		for _, v := range strings.Split(*networkIDs, ",") {
			go watchNetwork(v)
		}
	}
	c := make(chan struct{})
	<-c
}
