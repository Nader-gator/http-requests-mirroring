package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"regexp"
	"slices"
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
	switch msg.Type {
	case NetworkReq:
		{
			var data RequestMeta
			if err := json.Unmarshal(msg.Data, &data); err != nil {
				log.Fatal(err)
			}
			log.Println(fmt.Sprintf("Data: %+v", data))
		}
	case HeartBeat:
		{
			log.Println(fmt.Sprintf("Heartbeat: %+v", msg))
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

func scrubUrl(url []byte) []byte {
	apiKeyRegex := regexp.MustCompile(`(api_key=)([^&]+)`)
	if apiKeyRegex.Match(url) {
		return apiKeyRegex.ReplaceAll(url, []byte("apikey=[REDACTED]"))
	} else {
		return url
	}
}
