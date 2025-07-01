// File: vxlan_http_sniffer.go
//
// go mod init example.com/sniffer && go get github.com/google/gopacket@v1
// go build -o vxlan_http_sniffer vxlan_http_sniffer.go
//
// sudo ./vxlan_http_sniffer               # listens on UDP/4789
// sudo ./vxlan_http_sniffer -p 9000       # custom port

package main

import (
	"bufio"
	"bytes"
	"encoding/json"
	"io"
	"log"
	"net"
	"net/http"
	"sync"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/tcpassembly"
	"github.com/google/gopacket/tcpassembly/tcpreader"
)

// ----- pretty output --------------------------------------------------------

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

var pj sync.Mutex

func prettyPrint(v any) {
	pj.Lock()
	js, _ := json.MarshalIndent(v, "", "  ")
	log.Println(string(js))
	pj.Unlock()
}

// ----- HTTP stream ----------------------------------------------------------

type httpStreamD struct {
	net, transport gopacket.Flow
	reader         tcpreader.ReaderStream
}

func (h *httpStreamD) run() {
	log.Println("GOT HERE 2")
	r := bufio.NewReader(&h.reader)
	log.Println("GOT HERE 10")
	for {
		log.Println("GOT HERE 11")
		req, err := http.ReadRequest(r)
		log.Println("GOT HERE 12")
		req.Body.Close()
		log.Println("GOT HERE 13")
		if err != nil {
			log.Println("GOT HERE 14")
			if err == io.EOF {
				log.Println("GOT HERE 3")
				log.Println("GOT EOF")
				return
			}
			log.Println("GOT HERE 15")
			continue
		}
		log.Println("GOT HERE 16")
		var buf bytes.Buffer
		log.Println("GOT HERE 3")
		_, _ = io.Copy(&buf, req.Body)

		log.Println("GOT HERE 4")
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
			Body:          buf.String(),
		}
		log.Println("GOT HERE 5")
		prettyPrint(meta)
	}
}

type httpStreamFactoryD struct{}

func (f *httpStreamFactoryD) New(netf, transport gopacket.Flow) tcpassembly.Stream {
	log.Println("GOT HERE")
	s := &httpStreamD{net: netf, transport: transport, reader: tcpreader.NewReaderStream()}
	go s.run()
	return &s.reader
}

// ----- VXLAN helpers --------------------------------------------------------

const vxlanHeaderLen = 8 // flags+reserved(4) + VNI(3) + reserved(1)

func decapVXLAN(pkt []byte) ([]byte, bool) {
	if len(pkt) < vxlanHeaderLen {
		return nil, false
	}
	return pkt[vxlanHeaderLen:], true
}

func OtherListen() {
	addr := net.UDPAddr{IP: net.IPv4zero, Port: 4789}
	conn, err := net.ListenUDP("udp", &addr)
	if err != nil {
		log.Fatalf("ListenUDP: %v", err)
	}
	defer conn.Close()

	log.Printf("Listening for VXLAN mirrored traffic on %s\n", addr.String())

	streamPool := tcpassembly.NewStreamPool(&httpStreamFactoryD{})
	assembler := tcpassembly.NewAssembler(streamPool)
	ticker := time.NewTicker(time.Minute)

	buf := make([]byte, 65535)
	for {
		select {
		case <-ticker.C:
			// Flush connections idle > 2 min
			assembler.FlushOlderThan(time.Now().Add(-2 * time.Minute))
		default:
		}

		n, _, err := conn.ReadFrom(buf)
		if err != nil {
			log.Printf("UDP read error: %v", err)
			continue
		}
		payload, ok := decapVXLAN(buf[:n])
		if !ok {
			continue
		}

		packet := gopacket.NewPacket(
			payload,
			layers.LayerTypeEthernet,
			gopacket.NoCopy,
		)
		if errLayer := packet.ErrorLayer(); errLayer != nil {
			log.Printf("decode error: %v", errLayer.Error())
		}
		log.Println(packet.Layers())
		var (
			eth           layers.Ethernet
			ip4           layers.IPv4
			ip6           layers.IPv6
			tcp           layers.TCP
			udp           layers.UDP
			payloadPacket gopacket.Payload
			d             gopacket.DecodingLayerParser
		)
		d = *gopacket.NewDecodingLayerParser(
			layers.LayerTypeEthernet,
			&eth,
			&ip4,
			&ip6,
			&tcp,
			&udp,
			&payloadPacket,
		)
		var decoded []gopacket.LayerType
		if err := d.DecodeLayers(payload, &decoded); err != nil {
			log.Println("couldn't decode, err:", err)
			continue
		}
		log.Println("decoded:", decoded)
		var flow gopacket.Flow
		if tcp.SYN || len(tcp.Payload) > 0 || len(tcp.LayerContents()) > 0 {
			if ip4.Version == 4 {
				flow = ip4.NetworkFlow()
			} else {
				flow = ip6.NetworkFlow()
			}
			assembler.AssembleWithTimestamp(
				flow,
				&tcp,
				time.Now(),
			)
		}
	}
}
