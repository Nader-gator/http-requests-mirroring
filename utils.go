package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
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

	aho  = ahocorasick.NewTrieBuilder().AddStrings(keywords).Build()
	sink = []byte("REDACTED")
	pool = sync.Pool{New: func() any { return &bytes.Buffer{} }}
)

func scrub(raw []byte) ([]byte, error) {
	// Walk top-level; for deep walk wrap jsonparser.ArrayEach/ObjectEach recursively.
	err := jsonparser.ObjectEach(
		raw,
		func(key, val []byte, vt jsonparser.ValueType, off int) error {
			// Fast path: Aho-Corasick on key.
			if matches := aho.Match(key); len(matches) > 0 {
				// Mutate in-place.
				var err error
				raw, err = sjson.SetBytes(raw, string(key), sink)
				return err
			}

			// Handle nested objects/arrays.
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
				var errSet error
				raw, errSet = sjson.SetRawBytes(raw, string(key), scrubbed)
				return errSet
			case jsonparser.Array:
				// Left as exercise: jsonparser.ArrayEach + recursive call.
			}
			return nil
		},
	)
	return raw, err
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
