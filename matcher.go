package main

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"strings"
	"time"

	"github.com/IBM/sarama"
)

const MATCH_TIMEOUT = time.Second * 30

type RequestMeta struct {
	SrcIP         string          `json:"src_ip"`
	DstIP         string          `json:"dst_ip"`
	Method        string          `json:"method"`
	URL           string          `json:"url"`
	Proto         string          `json:"proto"`
	Host          string          `json:"host"`
	ContentLength int64           `json:"content_length"`
	Header        http.Header     `json:"header"`
	Body          json.RawMessage `json:"body,omitempty"`
	SrcTransport  string          `json:"src_transport"`
	DstTransport  string          `json:"dst_transport"`
	PacketTime    time.Time       `json:"packet_time"`
	IngestedAt    time.Time       `json:"ingested_at"`
}

type ResponseMeta struct {
	SrcIP         string          `json:"src_ip"`
	DstIP         string          `json:"dst_ip"`
	Status        string          `json:"status"`
	StatusCode    int             `json:"status_code"`
	Proto         string          `json:"proto"`
	ContentLength int64           `json:"content_length"`
	Header        http.Header     `json:"header"`
	Body          json.RawMessage `json:"body,omitempty"`
	SrcTransport  string          `json:"src_transport"`
	DstTransport  string          `json:"dst_transport"`
	PacketTime    time.Time       `json:"packet_time"`
	IngestedAt    time.Time       `json:"ingested_at"`
}
type PairedMessage struct {
	Request             RequestMeta  `json:"request"`
	Response            ResponseMeta `json:"response"`
	LatencyMicroseconds int64        `json:"latency_ms"`
}

type Matcher struct {
	producer     sarama.AsyncProducer
	trackingChan chan struct{}
	reqHist      map[string]RequestMeta
	resHist      map[string]ResponseMeta
	req          chan RequestMeta
	res          chan ResponseMeta
}

type MsgType = int

const (
	HeartBeat MsgType = iota
	NetworkReq
	NetworkRes
	PairedReqRes
)

type Msg struct {
	Timestamp time.Time       `json:"timestamp"`
	Data      json.RawMessage `json:"data,omitempty"`
	Type      int             `json:"type"`
}

func NewMatcher(producer sarama.AsyncProducer, trackingChan chan struct{}) *Matcher {
	matcher := &Matcher{
		producer:     producer,
		trackingChan: trackingChan,
		reqHist:      make(map[string]RequestMeta),
		resHist:      make(map[string]ResponseMeta),
		req:          make(chan RequestMeta, 4096),
		res:          make(chan ResponseMeta, 4096),
	}
	go matcher.run()
	return matcher
}

func shouldSendReq(req RequestMeta) bool {
	if strings.ToLower(req.Header.Get("User-Agent")) == strings.ToLower("ELB-HealthChecker/2.0") {
		return false
	}
	return true
}

func (m *Matcher) run() {

	ticker := time.Tick(time.Second * 30)
	for {
		select {
		case <-ticker:
			cutoff := time.Now().Add(-MATCH_TIMEOUT)
			for k, v := range m.resHist {
				if v.IngestedAt.After(cutoff) {
					continue
				}
				jsonData, err := json.Marshal(v)
				msg := Msg{
					Timestamp: time.Now().UTC(),
					Type:      NetworkRes,
					Data:      jsonData,
				}
				if err != nil {
					log.Println("Error marshalling JSON:", err)
					return
				}
				writeToKafka(m.producer, msg)
				delete(m.resHist, k)
			}
			for k, v := range m.reqHist {
				if v.IngestedAt.After(cutoff) {
					continue
				}
				delete(m.reqHist, k)
				jsonData, err := json.Marshal(v)
				if err != nil {
					log.Println("Error marshalling JSON:", err)
					return
				}
				msg := Msg{
					Timestamp: time.Now().UTC(),
					Type:      NetworkReq,
					Data:      jsonData,
				}
				if shouldSendReq(v) {
					writeToKafka(m.producer, msg)
				}
			}
		case msg := <-m.req:
			res, ok := m.resHist[msg.SrcTransport]
			if ok {
				delete(m.resHist, msg.SrcTransport)
				latency := res.PacketTime.Sub(msg.PacketTime).Abs().Microseconds()
				pairedMsg := PairedMessage{
					Request:             msg,
					Response:            res,
					LatencyMicroseconds: latency,
				}
				jsonData, err := json.Marshal(pairedMsg)
				if err != nil {
					log.Println("Error marshalling paired message JSON:", err)
					return
				}
				msg := Msg{
					Timestamp: time.Now().UTC(),
					Type:      PairedReqRes,
					Data:      jsonData,
				}
				if shouldSendReq(pairedMsg.Request) {
					writeToKafka(m.producer, msg)
				}
			} else {
				m.reqHist[msg.SrcTransport] = msg
			}
		case msg := <-m.res:
			req, ok := m.reqHist[msg.DstTransport]
			if ok {
				delete(m.reqHist, msg.DstTransport)
				latency := msg.PacketTime.Sub(req.PacketTime).Abs().Microseconds()
				pairedMsg := PairedMessage{
					Request:             req,
					Response:            msg,
					LatencyMicroseconds: latency,
				}
				jsonData, err := json.Marshal(pairedMsg)
				if err != nil {
					log.Println("Error marshalling paired message JSON:", err)
					return
				}
				msg := Msg{
					Timestamp: time.Now().UTC(),
					Type:      PairedReqRes,
					Data:      jsonData,
				}
				if shouldSendReq(pairedMsg.Request) {
					writeToKafka(m.producer, msg)
				}
			} else {
				m.resHist[msg.DstTransport] = msg
			}
		}
	}
}

func writeToKafka(producer sarama.AsyncProducer, msg_ Msg) {
	if producer != nil {
		if *printKafka {
			printMsg(msg_)
		} else {
			finalJson, err := json.Marshal(msg_)
			if err != nil {
				log.Println("Error marshalling final message JSON:", err)
				return
			}
			msg := &sarama.ProducerMessage{
				Topic: *kafkaTopic,
				Value: sarama.StringEncoder(finalJson),
			}
			producer.Input() <- msg
		}
	} else {
		printMsg(msg_)
	}
}

func writeHeartBeatToKafka(producer sarama.AsyncProducer) {

	for {
		timestamp := time.Now().Local().In(location)
		if producer == nil {
			fmt.Println("Got heartbeat without kafka", timestamp)
			return
		}
		msg := Msg{
			Timestamp: timestamp,
			Type:      HeartBeat,
		}
		writeToKafka(producer, msg)
		time.Sleep(time.Second * 30)
	}
}
