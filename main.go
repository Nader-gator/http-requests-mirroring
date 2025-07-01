package main

import (
	"bufio"
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"log"
	"math"
	"net/http"
	"os"
	"runtime"
	"strings"
	"sync"
	"time"

	"github.com/IBM/sarama"
	"github.com/Nader-gator/http-requests-mirroring/deidentify"
	"github.com/google/gopacket"
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
var readSome = flag.Int("read-msg", 0, "Number of messages to read(-1 for unlimited)")
var printKafka = flag.Bool("print-kafka", false, "Whether to print to stout kafka messages instead of sending them")
var filter = flag.String("filter", "", "BPF filter for pcap, exp:`tcp and dst port 4789`")
var pp = flag.Bool("pp", false, "pretty print read output")
var jj = flag.Bool("jj", false, "print single json line")
var kafkaOffset = flag.Int64("kafka-offset", -1, "Kafka offset to start consuming from (-1=newest, -2=oldest).")
var statsPct = flag.Float64("stats-pct", 0.0, "percentage of last messages to read")

var location *time.Location
var d *deidentify.Deidentifier

type httpStreamFactory struct {
	producer     sarama.AsyncProducer
	trackingChan chan struct{}
	ctx          context.Context
	matcher      *Matcher
}

const SNAPLEN = 4200

type httpStream struct {
	net, transport gopacket.Flow
	r              tcpreader.ReaderStream
	producer       sarama.AsyncProducer
	trackingChan   chan struct{}
	matcher        *Matcher
	ctx            context.Context
}

func (h *httpStreamFactory) New(net, transport gopacket.Flow) tcpassembly.Stream {
	ctx := context.WithValue(h.ctx, "id", uuid.New().String())
	hstream := &httpStream{
		net:          net,
		transport:    transport,
		r:            tcpreader.NewReaderStream(),
		producer:     h.producer,
		trackingChan: h.trackingChan,
		matcher:      h.matcher,
		ctx:          ctx,
	}
	go hstream.run()

	return &hstream.r
}

func (h *httpStream) run() {
	timestamp := time.Now()
	buf := bufio.NewReader(&h.r)
	for {
		if isResponse(buf) {
			res, err := http.ReadResponse(buf, nil)

			if err == io.EOF || err == io.ErrUnexpectedEOF {
				return
			} else if err != nil {
				e := fmt.Sprint(err)
				if !(strings.HasPrefix(e, "malformed HTTP") || strings.HasPrefix(e, "invalid method")) {
				}
			} else {
				body, bErr := io.ReadAll(res.Body)
				if bErr != nil {
					return
				}
				res.Body.Close()
				go h.writeResponseToKafka(res, body, timestamp)
			}

		} else {
			req, err := http.ReadRequest(buf)
			if err == io.EOF || err == io.ErrUnexpectedEOF {
				return
			} else if err != nil {
				e := fmt.Sprint(err)
				if !(strings.HasPrefix(e, "malformed HTTP") || strings.HasPrefix(e, "invalid method")) {
				}
			} else {
				body, bErr := io.ReadAll(req.Body)
				if bErr != nil {
					return
				}
				req.Body.Close()
				go h.writeRequestToKafka(req, body, timestamp)
			}

		}
	}
}

func maskApiKey(value string) string {
	trimmedValue := strings.Trim(value, " \t\n")
	if len(trimmedValue) > 10 {
		shortened := trimmedValue[:5] + "*****" + trimmedValue[len(trimmedValue)-5:]
		return shortened
	} else {
		return "**********"
	}
}

func scrubPrefix(prefixTarget, value string) string {
	if strings.HasPrefix(strings.ToLower(strings.Trim(value, " \t\n")), strings.ToLower(prefixTarget)) {
		prefix := value[:len(prefixTarget)]
		shortened := maskApiKey(value[len(prefixTarget):])
		return prefix + " " + shortened
	}
	return value
}

func scrubHeaders(headers http.Header) http.Header {
	newHeaders := make(http.Header)
	prefixTarget := "Bearer"
	for key, values := range headers {
		scrubbedValues := make([]string, len(values))
		for i, value := range values {
			if key == "Authorization" {
				if strings.HasPrefix(strings.ToLower(strings.Trim(value, " \t\n")), prefixTarget) {
					scrubbedValues[i] = scrubPrefix(prefixTarget, value)
				} else {
					scrubbedValues[i] = maskApiKey(value)
				}
			} else {
				scrubbedValues[i] = scrubPrefix(prefixTarget, value)
			}
		}
		newHeaders[key] = scrubbedValues
	}
	return newHeaders
}

func (h *httpStream) writeRequestToKafka(req *http.Request, body []byte, timestamp time.Time) {
	var finalBody json.RawMessage
	if len(body) > 0 && json.Valid(body) && isJSONObject(body) {
		scrubbed_b, err := scrub(body)
		scrubbed_b = scrubApikey(scrubbed_b)
		if err != nil {
			log.Println("Error scrubbing JSON:", err, "body: ", string(body))
			deidentifiedText, textErr := d.Text(string(body))
			if textErr != nil {
				log.Println("Error deidentifying plain text body after scrub failure:", textErr)
				errorObj := map[string]string{"error": "scrubbing_failed", "original_body": string(body)}
				finalBody, _ = json.Marshal(errorObj)
			} else {
				textObj := map[string]string{"msg": deidentifiedText}
				finalBody, _ = json.Marshal(textObj)
			}
		} else {
			finalBody = scrubbed_b
		}
	} else {
		deidentifiedText, err := d.Text(string(body))
		if err != nil {
			log.Println("Error deidentifying plain text body:", err)
			errorObj := map[string]string{"error": "deidentification_failed", "original_body": string(body)}
			finalBody, _ = json.Marshal(errorObj)
		} else {
			if deidentifiedText != "" {
				textObj := map[string]string{"msg": deidentifiedText}
				finalBody, _ = json.Marshal(textObj)
			}
		}
	}

	url, _ := req.URL.MarshalBinary()
	meta := RequestMeta{
		SrcIP:         h.net.Src().String(),
		DstIP:         h.net.Dst().String(),
		Method:        req.Method,
		URL:           string(scrubApikey(url)),
		Proto:         req.Proto,
		Host:          req.Host,
		ContentLength: req.ContentLength,
		Header:        scrubHeaders(req.Header),
		Body:          finalBody,
		SrcTransport:  h.transport.Src().String(),
		DstTransport:  h.transport.Dst().String(),
		PacketTime:    timestamp,
		IngestedAt:    time.Now(),
	}
	h.matcher.req <- meta
}

func (h *httpStream) writeResponseToKafka(res *http.Response, body []byte, timestamp time.Time) {
	var finalBody json.RawMessage
	if len(body) > 0 && json.Valid(body) && isJSONObject(body) {
		scrubbed_b, err := scrub(body)
		if err != nil {
			log.Println("Error scrubbing JSON:", err, "body: ", string(body))
			deidentifiedText, textErr := d.Text(string(body))
			if textErr != nil {
				log.Println("Error deidentifying plain text body after scrub failure:", textErr)
				errorObj := map[string]string{"error": "scrubbing_failed", "original_body": string(body)}
				finalBody, _ = json.Marshal(errorObj)
			} else {
				textObj := map[string]string{"msg": deidentifiedText}
				finalBody, _ = json.Marshal(textObj)
			}
		} else {
			finalBody = scrubbed_b
		}
	} else {
		deidentifiedText, err := d.Text(string(body))
		if err != nil {
			log.Println("Error deidentifying plain text body:", err)
			errorObj := map[string]string{"error": "deidentification_failed", "original_body": string(body)}
			finalBody, _ = json.Marshal(errorObj)
		} else {
			textObj := map[string]string{"msg": deidentifiedText}
			finalBody, _ = json.Marshal(textObj)
		}
	}

	meta := ResponseMeta{
		SrcIP:         h.net.Src().String(),
		DstIP:         h.net.Dst().String(),
		Status:        res.Status,
		StatusCode:    res.StatusCode,
		Proto:         res.Proto,
		ContentLength: res.ContentLength,
		Header:        scrubHeaders(res.Header),
		Body:          finalBody,
		SrcTransport:  h.transport.Src().String(),
		DstTransport:  h.transport.Dst().String(),
		PacketTime:    timestamp,
		IngestedAt:    time.Now(),
	}
	h.matcher.res <- meta
}

func watchNetwork(netit string, producer sarama.AsyncProducer, trackingChan chan struct{}, matcher *Matcher) {
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
	ctx := context.Background()
	streamFactory := &httpStreamFactory{
		producer:     producer,
		trackingChan: trackingChan,
		ctx:          ctx,
		matcher:      matcher,
	}
	streamPool := tcpassembly.NewStreamPool(streamFactory)

	log.Println("reading in packets")

	count := 0
	wg := sync.WaitGroup{}
	for range 512 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			assembler := tcpassembly.NewAssembler(streamPool)
			ticker := time.Tick(time.Second * 5)
			packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
			packets := packetSource.Packets()
			for {
				select {
				case <-ticker:
					assembler.FlushOlderThan(time.Now().Add(time.Minute * -1))
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
				}
			}
		}()
	}
	wg.Wait()
}

func consumeMsgs() {
	if !*jj {
		log.Println("reading messages")
	}
	config := sarama.NewConfig()
	config.Net.SASL.Enable = true
	config.Net.SASL.Mechanism = sarama.SASLTypeOAuth
	config.ClientID = uuid.NewString()
	config.Net.SASL.TokenProvider = &MSKTokenProvider{}

	config.Consumer.Return.Errors = true
	config.Consumer.Offsets.Initial = *kafkaOffset // or OffsetOldest

	config.Net.TLS.Enable = true
	config.Net.DialTimeout = 5 * time.Second

	consumer, err := sarama.NewConsumer(strings.Split(*kafkaBrokers, ","), config)
	if err != nil {
		log.Fatalf("Failed to create consumer: %v", err)
	}
	if !*jj {
		log.Println("consumer started")
	}
	defer func() {
		if err := consumer.Close(); err != nil {
			log.Printf("Failed to close consumer: %v", err)
		}
	}()

	topics, err := consumer.Topics()
	if err != nil {
		log.Fatal(err)
	}
	if !*jj {
		log.Println(topics)
	}

	parts, err := consumer.Partitions(*kafkaTopic)
	if err != nil {
		log.Fatal(err)
	}
	if !*jj {
		log.Println(parts)
	}
	wg := sync.WaitGroup{}
	for _, v := range parts {
		wg.Add(1)
		go func() {
			defer wg.Done()
			partitionConsumer, err := consumer.ConsumePartition(*kafkaTopic, v, *kafkaOffset)
			if err != nil {
				log.Fatalf("Failed to start consumer: %v", err)
			}
			defer partitionConsumer.Close()
			if !*jj {
				fmt.Println("Consumer started. Waiting for messages...")
			}

			cnt := 0
			for cnt < *readSome || *readSome == -1 {
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
	if *jj {
		log.SetFlags(log.Flags() &^ (log.Ldate | log.Ltime))
	}

	var err error
	location, err = time.LoadLocation("America/Los_Angeles")
	if err != nil {
		log.Fatal(err)
	}
	if *statsPct > 0.0 {
		consumeForStats()
		return
	}
	if *readSome > 0 || *readSome == -1 {
		log.SetOutput(os.Stdout)
		consumeMsgs()
		os.Exit(0)
	} else {
		trackingChan := make(chan struct{}, 1024)
		logfile, err := os.OpenFile("logfile.txt", os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0666)
		if err != nil {
			log.Fatal("Failed to open log file:", err)
		}
		defer logfile.Close()
		log.SetOutput(logfile)
		go openTCPClient()
		if !(*skipKafka) && (*kafkaTopic == "" || *kafkaBrokers == "" || *networkIDs == "") {
			log.Fatal("Kafka topic, brokers, and network IDs must be specified.")
		}

		var producer sarama.AsyncProducer

		if *skipKafka {
			if !*jj {
				log.Println("Skipping kafka...")
			}
		} else {
			go func() {
				for {
					log.Println("Goroutine count: ", runtime.NumGoroutine())
					time.Sleep(time.Minute)
				}
			}()
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
			log.Println("Connected!")

			producer, err = sarama.NewAsyncProducer(strings.Split(*kafkaBrokers, ","), config)
			if err != nil {
				log.Fatalf("Failed to create producer: %v", err)
			}
			defer producer.AsyncClose()
			go func() {
				successes := 0
				for range trackingChan {
					successes++
					if successes%100 == 0 && !*printKafka {
						log.Println("Num successesful writes: ", successes)
					}
				}
			}()
			for range 4 {
				go readProducerRes(producer, trackingChan)
			}
			go writeHeartBeatToKafka(producer)
		}
		matcher := NewMatcher(producer, trackingChan)
		for _, v := range strings.Split(*networkIDs, ",") {
			go watchNetwork(v, producer, trackingChan, matcher)
		}
	}
	c := make(chan struct{})
	<-c
}

func formatDuration(d time.Duration) string {
	d = d.Round(time.Second)
	h := d / time.Hour
	d -= h * time.Hour
	m := d / time.Minute
	d -= m * time.Minute
	s := d / time.Second
	return fmt.Sprintf("%02d:%02d:%02d", h, m, s)
}

func consumeForStats() {
	scriptStartTime := time.Now()
	log.Printf("Collecting statistics for the last %d%% of requests...\n", int(*statsPct))

	config := sarama.NewConfig()
	config.Net.SASL.Enable = true
	config.Net.SASL.Mechanism = sarama.SASLTypeOAuth
	config.ClientID = uuid.NewString()
	config.Net.SASL.TokenProvider = &MSKTokenProvider{}

	config.Consumer.Return.Errors = true
	config.Net.TLS.Enable = true
	config.Net.DialTimeout = 5 * time.Second

	consumer, err := sarama.NewConsumer(strings.Split(*kafkaBrokers, ","), config)
	if err != nil {
		log.Fatalf("Failed to create consumer: %v", err)
	}
	log.Println("Consumer started for statistics collection...")

	defer func() {
		if err := consumer.Close(); err != nil {
			log.Printf("Failed to close consumer: %v", err)
		}
	}()

	parts, err := consumer.Partitions(*kafkaTopic)
	if err != nil {
		log.Fatal(err)
	}

	allMessages := make(chan Msg, 100)
	wg := sync.WaitGroup{}

	client, err := sarama.NewClient(strings.Split(*kafkaBrokers, ","), config)
	if err != nil {
		log.Fatalf("Failed to create client: %v", err)
	}
	defer client.Close()

	for _, partition := range parts {
		wg.Add(1)
		go func(p int32) {
			defer wg.Done()

			offsetStart, err := client.GetOffset(*kafkaTopic, p, sarama.OffsetOldest)
			if err != nil {
				log.Panicf("can't get offset, error:'%s'", err)
			}
			offsetEnd, err := client.GetOffset(*kafkaTopic, p, sarama.OffsetNewest)

			if err != nil {
				log.Panicf("can't get offset, error:'%s'", err)
			}
			diff := float64(offsetEnd - offsetStart)
			log.Println("TOPIC DIFF", diff)
			diff = math.Floor(float64(diff) * (*statsPct / 100))
			log.Println("READING DIFF", diff)
			startingOffset := offsetEnd - int64(diff)

			partitionConsumer, err := consumer.ConsumePartition(*kafkaTopic, p, startingOffset)
			if err != nil {
				log.Printf("Failed to start consumer for partition %d: %v", p, err)
				return
			}
			defer partitionConsumer.Close()

			log.Printf("Starting from offset %d for partition %d", startingOffset, p)

			messageCount := 0
			startTime := time.Now()
			for {
				select {
				case msg := <-partitionConsumer.Messages():
					var data Msg
					err := json.Unmarshal(msg.Value, &data)
					if err != nil {
						continue
					}

					// if data.Timestamp.Before(cutoffTime) {
					// 	continue
					// }
					//
					if data.Timestamp.After(scriptStartTime) {
						log.Printf("Partition %d: reached events after script start, stopping", p)
						return
					}

					allMessages <- data
					messageCount++

					if (*readSome != 0) && (messageCount >= *readSome) {
						log.Printf("read requested ammount: %d, stopping...", *readSome)
						return
					}

					if messageCount%25000 == 0 {
						elapsed_s := max(time.Now().Sub(startTime).Seconds(), 1)
						remaining_cnt := int(diff) - messageCount
						rate_per_s := float64(messageCount) / elapsed_s
						if rate_per_s > 0 {
							remaining_seconds := int(float64(remaining_cnt) / rate_per_s)
							remaining_duration := time.Duration(remaining_seconds) * time.Second
							eta_str := formatDuration(remaining_duration)
							log.Printf(
								"P%d: read %s messages, last timstamp %s, minutes remaining: %d, count remaining %d, rate: %d, ETA: %s",
								p,
								formatNumber(int64(messageCount)),
								data.Timestamp.Format("2006-01-02 15:04:05.000"),
								int(scriptStartTime.Sub(data.Timestamp).Minutes()),
								remaining_cnt,
								int(rate_per_s),
								eta_str,
							)
						}
					}

				case err := <-partitionConsumer.Errors():
					log.Printf("Error from partition %d: %v\n", p, err)
					return
				case <-time.After(15 * time.Second):
					log.Printf("Partition %d: timeout reached, collected %d messages", p, messageCount)
					return
				}
			}
		}(partition)
	}
	done := make(chan struct{})
	go generateStatistics(allMessages, done)
	wg.Wait()
	close(allMessages)
	<-done
}
