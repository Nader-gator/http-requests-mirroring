// File: vxlan_traffic_generator.go
//
// Build:
//   go get github.com/google/gopacket
//   go build -o vxlan_traffic_generator vxlan_traffic_generator.go
//
// Run:
//   sudo ./vxlan_traffic_generator
//   sudo ./vxlan_traffic_generator -target 127.0.0.1 -vni 42 -rate 10

package main

import (
	"bytes"
	"flag"
	"fmt"
	"log"
	"math/rand"
	"net"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

var (
	methods = []string{"GET", "POST", "PUT", "DELETE", "PATCH"}
	paths   = []string{
		"/api/users",
		"/api/products",
		"/health",
		"/metrics",
		"/api/v1/orders",
		"/api/v2/inventory",
		"/login",
		"/logout",
		"/api/search",
		"/webhook",
	}
	userAgents = []string{
		"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
		"Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36",
		"curl/7.68.0",
		"Python-urllib/3.8",
		"PostmanRuntime/7.28.4",
		"Apache-HttpClient/4.5.13",
	}
	contentTypes = []string{
		"application/json",
		"application/x-www-form-urlencoded",
		"text/plain",
		"application/xml",
	}
)

type PacketGenerator struct {
	targetIP   net.IP
	targetPort int
	vni        uint32
	srcMAC     net.HardwareAddr
	dstMAC     net.HardwareAddr
	conn       net.PacketConn
}

func NewPacketGenerator(target string, port int, vni uint32) (*PacketGenerator, error) {
	targetIP := net.ParseIP(target)
	if targetIP == nil {
		return nil, fmt.Errorf("invalid target IP: %s", target)
	}

	// Create UDP socket
	conn, err := net.ListenPacket("udp4", ":0")
	if err != nil {
		return nil, err
	}

	return &PacketGenerator{
		targetIP:   targetIP,
		targetPort: port,
		vni:        vni,
		srcMAC:     net.HardwareAddr{0x02, 0x00, 0x00, 0x00, 0x00, 0x01},
		dstMAC:     net.HardwareAddr{0x02, 0x00, 0x00, 0x00, 0x00, 0x02},
		conn:       conn,
	}, nil
}

func (pg *PacketGenerator) Close() {
	pg.conn.Close()
}

func (pg *PacketGenerator) generateHTTPRequest() string {
	method := methods[rand.Intn(len(methods))]
	path := paths[rand.Intn(len(paths))]
	host := fmt.Sprintf("10.0.%d.%d", rand.Intn(255), rand.Intn(255))
	userAgent := userAgents[rand.Intn(len(userAgents))]

	var req bytes.Buffer

	// Request line
	fmt.Fprintf(&req, "%s %s HTTP/1.1\r\n", method, path)

	// Headers
	fmt.Fprintf(&req, "Host: %s\r\n", host)
	fmt.Fprintf(&req, "User-Agent: %s\r\n", userAgent)
	fmt.Fprintf(&req, "Accept: */*\r\n")
	fmt.Fprintf(&req, "X-Request-ID: %d\r\n", rand.Int63())
	fmt.Fprintf(&req, "X-Forwarded-For: %d.%d.%d.%d\r\n",
		rand.Intn(255), rand.Intn(255), rand.Intn(255), rand.Intn(255))

	// Add body for non-GET requests
	if method != "GET" {
		contentType := contentTypes[rand.Intn(len(contentTypes))]
		var body string

		switch contentType {
		case "application/json":
			body = fmt.Sprintf(`{"id":%d,"name":"test-%d","value":%f}`,
				rand.Intn(1000), rand.Intn(100), rand.Float64()*100)
		case "application/x-www-form-urlencoded":
			body = fmt.Sprintf("param1=value%d&param2=test%d",
				rand.Intn(100), rand.Intn(100))
		default:
			body = fmt.Sprintf("Random test data %d", rand.Int())
		}

		fmt.Fprintf(&req, "Content-Type: %s\r\n", contentType)
		fmt.Fprintf(&req, "Content-Length: %d\r\n", len(body))
		fmt.Fprintf(&req, "\r\n")
		fmt.Fprintf(&req, "%s", body)
	} else {
		fmt.Fprintf(&req, "\r\n")
	}

	return req.String()
}

func (pg *PacketGenerator) createTCPPacket(srcIP, dstIP net.IP, srcPort, dstPort uint16, payload []byte) []byte {
	// Ethernet layer
	eth := layers.Ethernet{
		SrcMAC:       pg.srcMAC,
		DstMAC:       pg.dstMAC,
		EthernetType: layers.EthernetTypeIPv4,
	}

	// IP layer
	ip := layers.IPv4{
		Version:  4,
		IHL:      5,
		TOS:      0,
		Length:   0, // Will be set by serialization
		Id:       uint16(rand.Intn(65535)),
		Flags:    layers.IPv4DontFragment,
		TTL:      64,
		Protocol: layers.IPProtocolTCP,
		SrcIP:    srcIP,
		DstIP:    dstIP,
	}

	// TCP layer
	tcp := layers.TCP{
		SrcPort:    layers.TCPPort(srcPort),
		DstPort:    layers.TCPPort(dstPort),
		Seq:        rand.Uint32(),
		Ack:        rand.Uint32(),
		DataOffset: 5,
		Window:     65535,
		Urgent:     0,
		ACK:        true,
		PSH:        true,
	}

	// Set TCP checksum
	tcp.SetNetworkLayerForChecksum(&ip)

	// Serialize layers
	buf := gopacket.NewSerializeBuffer()
	opts := gopacket.SerializeOptions{
		FixLengths:       true,
		ComputeChecksums: true,
	}

	gopacket.SerializeLayers(buf, opts,
		&eth,
		&ip,
		&tcp,
		gopacket.Payload(payload),
	)

	return buf.Bytes()
}

func (pg *PacketGenerator) encapsulateVXLAN(innerPacket []byte) []byte {
	// VXLAN header (8 bytes)
	// Flags: 0x08 (I flag set)
	// Reserved: 24 bits (0)
	// VNI: 24 bits
	// Reserved: 8 bits (0)

	vxlanHeader := make([]byte, 8)
	vxlanHeader[0] = 0x08 // I flag
	// VNI in bytes 4, 5, 6
	vxlanHeader[4] = byte(pg.vni >> 16)
	vxlanHeader[5] = byte(pg.vni >> 8)
	vxlanHeader[6] = byte(pg.vni)

	return append(vxlanHeader, innerPacket...)
}

func (pg *PacketGenerator) SendHTTPPacket() error {
	// Generate random IPs and ports
	srcIP := net.IPv4(10, 0, byte(rand.Intn(255)), byte(rand.Intn(255)))
	dstIP := net.IPv4(10, 0, byte(rand.Intn(255)), byte(rand.Intn(255)))
	srcPort := uint16(30000 + rand.Intn(30000))
	dstPort := uint16(80) // HTTP port

	if rand.Float32() < 0.3 {
		dstPort = 8080 // Sometimes use 8080
	}

	// Generate HTTP request
	httpData := pg.generateHTTPRequest()

	// Create TCP packet with HTTP payload
	tcpPacket := pg.createTCPPacket(srcIP, dstIP, srcPort, dstPort, []byte(httpData))

	// Encapsulate in VXLAN
	vxlanPacket := pg.encapsulateVXLAN(tcpPacket)

	// Send via UDP to VXLAN port
	addr := &net.UDPAddr{
		IP:   pg.targetIP,
		Port: pg.targetPort,
	}

	_, err := pg.conn.WriteTo(vxlanPacket, addr)
	if err != nil {
		return fmt.Errorf("failed to send packet: %w", err)
	}

	log.Printf("Sent %s request from %s:%d to %s:%d (VNI: %d, %d bytes)",
		methods[rand.Intn(len(methods))], srcIP, srcPort, dstIP, dstPort, pg.vni, len(httpData))

	return nil
}

func main() {
	target := flag.String("target", "0.0.0.0", "Target IP for VXLAN packets")
	port := flag.Int("port", 4789, "VXLAN UDP port")
	vni := flag.Uint("vni", 69, "VXLAN Network Identifier")
	rate := flag.Int("rate", 5, "Packets per second")
	duration := flag.Duration("duration", 0, "Duration to run (0 = forever)")
	burst := flag.Bool("burst", false, "Send burst of 100 packets then exit")
	flag.Parse()

	gen, err := NewPacketGenerator(*target, *port, uint32(*vni))
	if err != nil {
		log.Fatal("Failed to create generator:", err)
	}
	defer gen.Close()

	log.Printf("Sending VXLAN traffic to %s:%d (VNI: %d)", *target, *port, *vni)

	if *burst {
		// Burst mode
		log.Println("Sending burst of 100 packets...")
		for range 100 {
			if err := gen.SendHTTPPacket(); err != nil {
				log.Printf("Error: %v", err)
			}
			time.Sleep(10 * time.Millisecond)
		}
		log.Println("Burst complete")
		return
	}

	// Continuous mode
	ticker := time.NewTicker(time.Second / time.Duration(*rate))
	defer ticker.Stop()

	start := time.Now()
	count := 0

	for {
		select {
		case <-ticker.C:
			if err := gen.SendHTTPPacket(); err != nil {
				log.Printf("Error: %v", err)
			}
			count++

			// Check duration
			if *duration > 0 && time.Since(start) > *duration {
				log.Printf("Sent %d packets in %v", count, time.Since(start))
				return
			}
		}
	}
}
