package main

import (
	"bufio"
	"encoding/json"
	"flag"
	"fmt"
	"github.com/Nader-gator/http-requests-mirroring/deidentify"
	"io"
	"log"
	"net/http"
	"os"
	"runtime"
	"strings"
	"sync"
	"time"

	"github.com/IBM/sarama"
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
var printKafka = flag.Bool("print-kafka", false, "Whether to print to stout kafka messages instead of sending them")
var filter = flag.String("filter", "", "BPF filter for pcap, exp:`tcp and dst port 4789`")

const (
	HeartBeat = iota
	NetworkReq
)

var location *time.Location
var d *deidentify.Deidentifier

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
		if err == io.EOF || err == io.ErrUnexpectedEOF {
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

func writeHeartBeatToKafka(producer sarama.AsyncProducer) {
	timestamp := time.Now().Local().In(location)
	if producer == nil {
		fmt.Println("Got heartbeat without kafka", timestamp)
		return
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
	var scrubbed string
	var err error
	if len(body) > 0 {
		scrubbed_b, err := scrub(body)
		if err != nil {
			log.Println("Error scrubbing JSON:", err)
			scrubbed = string(body)
		} else {
			scrubbed = string(scrubbed_b)

		}
	} else {
		scrubbed = string(body)
	}

	scrubbed_body, err := d.Text(scrubbed)
	if err != nil {
		log.Println("Error deidentifying body:", err)
	}
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
		Body:          scrubbed_body,
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
		if *printKafka {
			log.Println(fmt.Sprintf("%+v", meta))
		} else {
			h.producer.Input() <- msg
		}
	} else {
		log.Println(fmt.Sprintf("%+v", meta))
	}
}

func watchNetwork(netit string, producer sarama.AsyncProducer) {
	defer util.Run()()
	var err error
	log.Printf("Starting capture on interface %s", netit)
	handle, err := pcap.OpenLive(netit, int32(SNAPLEN), true, pcap.BlockForever)
	if err != nil {
		log.Fatal(err)
	}
	if *filter != "" {
		if err := handle.SetBPFFilter(*filter); err != nil {
			log.Fatal(err)
		}
	}
	streamFactory := &httpStreamFactory{producer: producer}
	streamPool := tcpassembly.NewStreamPool(streamFactory)

	log.Println("reading in packets")

	count := 0
	wg := sync.WaitGroup{}
	for range 10 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			assembler := tcpassembly.NewAssembler(streamPool)
			ticker := time.Tick(time.Second * 10)
			packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
			packets := packetSource.Packets()
			for {
				select {
				case packet := <-packets:
					if packet == nil {
						break
					}
					if packet.NetworkLayer() == nil || packet.TransportLayer() == nil || packet.TransportLayer().LayerType() != layers.LayerTypeTCP {
						count += 1
						log.Println("Unusable packet, error num:", count)
						continue
					}
					tcp := packet.TransportLayer().(*layers.TCP)
					assembler.AssembleWithTimestamp(packet.NetworkLayer().NetworkFlow(), tcp, packet.Metadata().Timestamp)
				case <-ticker:
					assembler.FlushOlderThan(time.Now().Add(time.Minute * -2))
				}
			}
		}()
	}
	wg.Wait()
}

func consumeMsgs() {
	log.Println("reading messages")
	config := sarama.NewConfig()
	config.Net.SASL.Enable = true
	config.Net.SASL.Mechanism = sarama.SASLTypeOAuth
	config.ClientID = uuid.NewString()
	config.Net.SASL.TokenProvider = &MSKTokenProvider{}

	config.Consumer.Return.Errors = true
	config.Consumer.Offsets.Initial = sarama.OffsetNewest // or OffsetOldest

	config.Net.TLS.Enable = true
	config.Net.DialTimeout = 5 * time.Second

	consumer, err := sarama.NewConsumer(strings.Split(*kafkaBrokers, ","), config)
	if err != nil {
		log.Fatalf("Failed to create consumer: %v", err)
	}
	log.Println("consumer started")
	defer func() {
		if err := consumer.Close(); err != nil {
			log.Printf("Failed to close consumer: %v", err)
		}
	}()

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
	wg := sync.WaitGroup{}
	for _, v := range parts {
		wg.Add(1)
		go func() {
			defer wg.Done()
			partitionConsumer, err := consumer.ConsumePartition(*kafkaTopic, v, sarama.OffsetOldest)
			if err != nil {
				log.Fatalf("Failed to start consumer: %v", err)
			}
			defer partitionConsumer.Close()
			fmt.Println("Consumer started. Waiting for messages...")

			cnt := 0
			for cnt < *readSome {
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
		}()
	}
	wg.Wait()
}
func main() {
	flag.Parse()
	secretKey := uuid.New().String()
	d = deidentify.NewDeidentifier(secretKey)

	var err error
	location, err = time.LoadLocation("America/Los_Angeles")
	if err != nil {
		log.Fatal(err)
	}
	if *readSome > 0 {
		consumeMsgs()
		os.Exit(0)
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
		if !(*skipKafka) && (*kafkaTopic == "" || *kafkaBrokers == "" || *networkIDs == "") {
			log.Fatal("Kafka topic, brokers, and network IDs must be specified.")
		}

		var producer sarama.AsyncProducer
		if *skipKafka {
			log.Println("Skipping kafka...")

		} else {
			log.Println("Connecting..")

			log.Println("Got IAM session")
			config := sarama.NewConfig()
			config.Producer.Return.Successes = true
			config.Producer.Return.Errors = true
			config.Producer.RequiredAcks = sarama.WaitForAll
			config.Producer.Retry.Max = 5

			config.Net.SASL.Enable = true
			config.Net.SASL.Mechanism = sarama.SASLTypeOAuth
			config.ClientID = uuid.NewString()
			config.Net.SASL.TokenProvider = &MSKTokenProvider{}

			config.Net.TLS.Enable = true
			config.Net.DialTimeout = 5 * time.Second

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
			successes := 0
			log.Println("starting producer", successes)
			go func() {
				for {
					select {
					case <-producer.Successes():
						successes += 1
						if successes%100 == 0 && !*printKafka {
							log.Println("Num successesful writes: ", successes)
						}
					case msg := <-producer.Errors():
						log.Println("Error writing to kafka:", *msg)
					}
				}
			}()
			writeHeartBeatToKafka(producer)
		}
		for _, v := range strings.Split(*networkIDs, ",") {
			go watchNetwork(v, producer)
		}
	}
	c := make(chan struct{})
	<-c
}
