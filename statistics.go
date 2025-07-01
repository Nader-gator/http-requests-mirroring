package main

import (
	"encoding/json"
	"fmt"
	"net/url"
	"regexp"
	"slices"
	"sort"
	"strconv"
	"strings"
)

type EndpointStats struct {
	Endpoint                   string
	HitCount                   int
	LatencyMicros              []int64
	MedianLatency              int64
	MeanLatency                int64
	Worst1PercentMeanLatency   int64
	Worst5PercentMeanLatency   int64
	Middle80PercentMeanLatency int64
	ResponseStats              map[string]int
}

type ResponseInfo struct {
	Response   string
	Count      int
	Percentage float64
}

func stripURLParams(rawURL string) string {
	parsedURL, err := url.Parse(rawURL)
	if err != nil {
		return rawURL
	}
	parsedURL.RawQuery = ""
	parsedURL.Fragment = ""
	return parsedURL.String()
}

func normalizeURLWithIDs(rawURL string) string {
	parsedURL, err := url.Parse(rawURL)
	if err != nil {
		return rawURL
	}

	numericPattern := regexp.MustCompile(`/\d+(/|$)`)

	normalizedPath := numericPattern.ReplaceAllStringFunc(parsedURL.Path, func(match string) string {
		if strings.HasSuffix(match, "/") {
			return "/_ID_/"
		}
		return "/_ID_"
	})

	parsedURL.Path = normalizedPath
	parsedURL.RawQuery = ""
	parsedURL.Fragment = ""

	return parsedURL.String()
}

func generateStatistics(messages chan Msg, done chan struct{}) {
	endpointMap := make(map[string]*EndpointStats)

	for msg := range messages {

		if msg.Type == PairedReqRes {
			var pairedMsg PairedMessage
			if err := json.Unmarshal(msg.Data, &pairedMsg); err != nil {
				continue
			}

			cleanURL := stripURLParams(pairedMsg.Request.URL)
			normalizedURL := normalizeURLWithIDs(cleanURL)
			endpoint := fmt.Sprintf("%s %s", pairedMsg.Request.Method, normalizedURL)

			if _, exists := endpointMap[endpoint]; !exists {
				endpointMap[endpoint] = &EndpointStats{
					Endpoint:      endpoint,
					HitCount:      0,
					LatencyMicros: make([]int64, 0),
					ResponseStats: make(map[string]int),
				}
			}

			stats := endpointMap[endpoint]
			stats.HitCount++
			stats.LatencyMicros = append(stats.LatencyMicros, pairedMsg.LatencyMicroseconds)

			responseKey := fmt.Sprintf("%d", pairedMsg.Response.StatusCode)
			stats.ResponseStats[responseKey]++
		}
	}

	for _, stats := range endpointMap {
		calculateLatencyStats(stats)
	}

	printStatisticsTable(endpointMap)
	done <- struct{}{}
}

func calculateLatencyStats(stats *EndpointStats) {
	if len(stats.LatencyMicros) == 0 {
		return
	}

	slices.SortFunc(stats.LatencyMicros, func(i, j int64) int {
		return int(i - j)
	})

	n := len(stats.LatencyMicros)
	if n%2 == 0 {
		stats.MedianLatency = (stats.LatencyMicros[n/2-1] + stats.LatencyMicros[n/2]) / 2
	} else {
		stats.MedianLatency = stats.LatencyMicros[n/2]
	}

	var sum int64
	for _, latency := range stats.LatencyMicros {
		sum += latency
	}
	stats.MeanLatency = sum / int64(n)

	// Calculate worst 1%
	p1Index := int(float64(n) * 0.99)
	if p1Index < n {
		sum = 0
		count := 0
		for i := p1Index; i < n; i++ {
			sum += stats.LatencyMicros[i]
			count++
		}
		if count > 0 {
			stats.Worst1PercentMeanLatency = sum / int64(count)
		}
	}

	// Calculate worst 5%
	p5Index := int(float64(n) * 0.95)
	if p5Index < n {
		sum = 0
		count := 0
		for i := p5Index; i < n; i++ {
			sum += stats.LatencyMicros[i]
			count++
		}
		if count > 0 {
			stats.Worst5PercentMeanLatency = sum / int64(count)
		}
	}

	// Calculate middle 80%
	p10Index := int(float64(n) * 0.10)
	p90Index := int(float64(n) * 0.90)
	if p10Index < p90Index {
		sum = 0
		count := 0
		for i := p10Index; i < p90Index; i++ {
			sum += stats.LatencyMicros[i]
			count++
		}
		if count > 0 {
			stats.Middle80PercentMeanLatency = sum / int64(count)
		}
	}
}

func printStatisticsTable(endpointMap map[string]*EndpointStats) {
	endpoints := make([]*EndpointStats, 0, len(endpointMap))
	for _, stats := range endpointMap {
		endpoints = append(endpoints, stats)
	}

	sort.Slice(endpoints, func(i, j int) bool {
		return endpoints[i].HitCount > endpoints[j].HitCount
	})

	fmt.Printf("\n%-60s %-10s %-15s %-15s %-20s %-20s %-20s %-50s\n", "ENDPOINT", "HIT COUNT", "MEDIAN (ms)", "MEAN (ms)", "WORST 1% MEAN (ms)", "WORST 5% MEAN (ms)", "MIDDLE 80% MEAN(ms)", "TOP 3 RESPONSES")
	fmt.Println(strings.Repeat("-", 220))

	for _, stats := range endpoints {
		topResponses := getTopResponses(stats.ResponseStats, 3)
		responseStr := formatTopResponses(topResponses, stats.HitCount)

		fmt.Printf("% -60s %-10s %-15s %-15s %-20s %-20s %-20s %-50s\n",
			truncateString(stats.Endpoint, 60),
			formatNumber(int64(stats.HitCount)),
			formatNumber(stats.MedianLatency/1000),
			formatNumber(stats.MeanLatency/1000),
			formatNumber(stats.Worst1PercentMeanLatency/1000),
			formatNumber(stats.Worst5PercentMeanLatency/1000),
			formatNumber(stats.Middle80PercentMeanLatency/1000),
			responseStr)
	}
}

func getTopResponses(responseStats map[string]int, top int) []ResponseInfo {
	responses := make([]ResponseInfo, 0, len(responseStats))

	for response, count := range responseStats {
		responses = append(responses, ResponseInfo{
			Response: response,
			Count:    count,
		})
	}

	sort.Slice(responses, func(i, j int) bool {
		return responses[i].Count > responses[j].Count
	})

	if len(responses) > top {
		responses = responses[:top]
	}

	return responses
}

func formatTopResponses(responses []ResponseInfo, totalHits int) string {
	if len(responses) == 0 {
		return ""
	}

	parts := make([]string, 0, len(responses))
	for _, resp := range responses {
		percentage := float64(resp.Count) / float64(totalHits) * 100
		parts = append(parts, fmt.Sprintf("%s (%.1f%%)", resp.Response, percentage))
	}

	return strings.Join(parts, ", ")
}

func truncateString(s string, maxLen int) string {
	if len(s) <= maxLen {
		return s
	}
	return s[:maxLen-3] + "..."
}

func formatNumber(n int64) string {
	in := strconv.FormatInt(n, 10)
	out := &strings.Builder{}
	if n < 0 {
		out.WriteByte('-')
		in = in[1:]
	}
	l := len(in)
	for i, r := range in {
		if i > 0 && (l-i)%3 == 0 {
			out.WriteByte(',')
		}
		out.WriteRune(r)
	}
	return out.String()
}
