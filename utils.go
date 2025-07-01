package main

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"sync"

	"github.com/BobuSumisu/aho-corasick"
	"github.com/IBM/sarama"
	"github.com/aws/aws-msk-iam-sasl-signer-go/signer"
	"github.com/buger/jsonparser"
	"github.com/tidwall/sjson"
)

var (
	keywords = []string{
		"password",
		"passwd",
		"secret",
		"ssn",
		"creditcard",
		"token",
		"key",
	}
	// a list of keys that contain "token" but should not be scrubbed
	tokenExclusions = []string{
		"numtoken",
	}

	aho  = ahocorasick.NewTrieBuilder().AddStrings(keywords).Build()
	sink = []byte("REDACTED")
	pool = sync.Pool{New: func() any { return &bytes.Buffer{} }}
)
var apiKeyRegex = regexp.MustCompile(`(api_key=)([^&]+)`)

func scrub(raw []byte) ([]byte, error) {
	returnErr := jsonparser.ObjectEach(
		raw,
		func(key, val []byte, vt jsonparser.ValueType, off int) error {
			var err error
			if matches := aho.Match(key); len(matches) > 0 {
				isExcluded := slices.Contains(tokenExclusions, string(key))
				if !isExcluded {
					raw, err = sjson.SetBytes(raw, string(key), sink)
					return err
				}
			}

			switch vt {
			case jsonparser.Object:
				sub, _, _, err := jsonparser.Get(raw, string(key))
				if err != nil {
					return err
				}
				scrubbed, err := scrub(sub)
				if err != nil {
					return err
				}
				raw, err = sjson.SetRawBytes(raw, string(key), scrubbed)
				return err
			case jsonparser.Array:
				var i int
				_, err := jsonparser.ArrayEach(val, func(value []byte, vt jsonparser.ValueType, offset int, returnErr error) {
					if returnErr != nil {
						return
					}
					if vt == jsonparser.Object {
						scrubbed, err := scrub(value)
						if err != nil {
							returnErr = err
							return
						}
						path := fmt.Sprintf("%s.%d", string(key), i)
						raw, err = sjson.SetRawBytes(raw, path, scrubbed)
						if err != nil {
							returnErr = err
							return
						}
					}
					i++
				})
				return err
			}
			return nil
		},
	)
	return raw, returnErr
}

func printMsg(msg Msg) {
	printInner := func(prefix, logMsg string) {
		if *jj {
			log.Println(logMsg)
		} else {
			log.Println(prefix, string(logMsg))
		}
	}
	switch msg.Type {
	case NetworkReq:
		{
			var data RequestMeta
			if err := json.Unmarshal(msg.Data, &data); err != nil {
				log.Fatal(err)
			}
			var pretty []byte
			var err error
			if *pp {
				pretty, err = json.MarshalIndent(data, "", "  ")
			} else {
				pretty, err = json.Marshal(data)
			}

			if err != nil {
				printInner("RequestMeta: ", fmt.Sprintf("%+v", data))
			} else {
				printInner("RequestMeta:", string(pretty))
			}
		}
	case NetworkRes:
		{
			var data ResponseMeta
			if err := json.Unmarshal(msg.Data, &data); err != nil {
				log.Fatal(err)
			}
			var pretty []byte
			var err error
			if *pp {
				pretty, err = json.MarshalIndent(data, "", "  ")
			} else {
				pretty, err = json.Marshal(data)
			}
			if err != nil {
				printInner("ResponseMeta: ", fmt.Sprintf("%+v", data))
			} else {
				printInner("ResponseMeta", string(pretty))
			}
		}
	case PairedReqRes:
		{
			var data PairedMessage
			if err := json.Unmarshal(msg.Data, &data); err != nil {
				log.Fatal(err)
			}
			var pretty []byte
			var err error
			if *pp {
				pretty, err = json.MarshalIndent(data, "", "  ")
			} else {
				pretty, err = json.Marshal(data)
			}
			if err != nil {
				printInner("PairedMessage: ", fmt.Sprintf("%+v", data))
			} else {
				printInner("PairedMessage", string(pretty))
			}
		}
	case HeartBeat:
		{
			var pretty []byte
			var err error
			if *pp {
				pretty, err = json.MarshalIndent(msg, "", "  ")
			} else {
				pretty, err = json.Marshal(msg)
			}
			if err != nil {
				printInner("Heartbeat: ", fmt.Sprintf("%+v", msg))
			} else {
				printInner("Heartbeat", string(pretty))
			}
		}
	default:
		{
			log.Fatal("Unknow msg type")
		}
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

type MSKTokenProvider struct{}

func (t *MSKTokenProvider) Token() (*sarama.AccessToken, error) {
	token, _, err := signer.GenerateAuthToken(context.TODO(), "us-east-1")
	return &sarama.AccessToken{Token: token}, err
}

func readProducerRes(producer sarama.AsyncProducer, successes chan struct{}) {
	select {
	case <-producer.Successes():
		successes <- struct{}{}
	case msg := <-producer.Errors():
		log.Println("Error writing to kafka:", *msg)
	}
}

func isJSONObject(data []byte) bool {
	trimmed := bytes.TrimSpace(data)
	return len(trimmed) > 0 && trimmed[0] == '{'
}

func scrubApikey(url []byte) []byte {
	if apiKeyRegex.Match(url) {
		return apiKeyRegex.ReplaceAll(url, []byte("apikey=[REDACTED]"))
	} else {
		return url
	}
}

func isResponse(reader *bufio.Reader) bool {
	// Peek at a reasonable number of bytes (e.g., 1024)
	b, err := reader.Peek(SNAPLEN)
	if err != nil && err != io.EOF {
		// Handle error
	}

	// Search for the newline character within the peeked bytes
	lineEnd := bytes.IndexByte(b, '\n')
	if lineEnd != -1 {
		// The first line is within b[:lineEnd+1]
		line := string(b[:lineEnd+1])
		proto, rest, ok := strings.Cut(line, " ")
		if !ok {
			return false
		}

		statusCode, rest, ok := strings.Cut(strings.TrimLeft(rest, " "), " ")
		if !ok || len(statusCode) != 3 {
			return false
		}
		s, err := strconv.Atoi(statusCode)
		if err != nil || s < 0 {
			return false
		}
		if _, _, ok = http.ParseHTTPVersion(proto); !ok {
			return false
		}
		return true
	} else {
		return false
	}
}
