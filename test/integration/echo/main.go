//go:build integration

package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"sort"
	"strings"
	"sync"
	"time"

	"google.golang.org/grpc"
	_ "google.golang.org/grpc/encoding/gzip"
	"google.golang.org/grpc/metadata"
	"google.golang.org/protobuf/types/known/structpb"

	"github.com/0x4272616E646F6E/ailuros/test/integration/echo/echopb"
)

const (
	maxBody    = 8 << 20
	maxRecords = 10000
)

type record struct {
	Kind    string              `json:"kind"`
	Method  string              `json:"method"`
	Path    string              `json:"path"`
	Query   string              `json:"query"`
	Headers map[string][]string `json:"headers"`
	Body    []byte              `json:"body_b64"`
}

func (r record) contains(marker string) bool {
	if strings.Contains(r.Path, marker) || strings.Contains(r.Query, marker) || strings.Contains(string(r.Body), marker) {
		return true
	}
	for name, values := range r.Headers {
		if strings.Contains(name, marker) {
			return true
		}
		for _, v := range values {
			if strings.Contains(v, marker) {
				return true
			}
		}
	}
	return false
}

type echo struct {
	grpc *grpc.Server
	mu   sync.Mutex
	seen []record
}

func newEcho() *echo {
	e := &echo{grpc: grpc.NewServer()}
	echopb.Register(e.grpc, e)
	return e
}

func (e *echo) add(r record) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.seen = append(e.seen, r)
	if len(e.seen) > maxRecords {
		e.seen = e.seen[len(e.seen)-maxRecords:]
	}
}

func (e *echo) handler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.ProtoMajor == 2 && strings.HasPrefix(r.Header.Get("Content-Type"), "application/grpc") {
			e.grpc.ServeHTTP(w, r)
			return
		}
		body, err := io.ReadAll(io.LimitReader(r.Body, maxBody))
		if err != nil {
			http.Error(w, "read body: "+err.Error(), http.StatusBadRequest)
			return
		}
		headers := r.Header.Clone()
		headers["Host"] = []string{r.Host}
		rec := record{Kind: "http", Method: r.Method, Path: r.URL.Path, Query: r.URL.RawQuery, Headers: headers, Body: body}
		e.add(rec)
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(rec)
	})
}

func (e *echo) admin() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, _ *http.Request) { _, _ = w.Write([]byte("ok\n")) })
	mux.HandleFunc("GET /seen", func(w http.ResponseWriter, r *http.Request) {
		marker := r.URL.Query().Get("contains")
		e.mu.Lock()
		out := []record{}
		for _, rec := range e.seen {
			if rec.contains(marker) {
				out = append(out, rec)
			}
		}
		e.mu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(out)
	})
	return mux
}

func (e *echo) recordMessage(ctx context.Context, method string, msg *echopb.Msg) map[string][]string {
	md, _ := metadata.FromIncomingContext(ctx)
	e.add(record{Kind: "grpc", Method: "POST", Path: method, Headers: md, Body: []byte(msg.GetValue())})
	return md
}

func reply(text string, md map[string][]string) (*echopb.Reply, error) {
	fields := map[string]any{"text": text}
	if md != nil {
		seen := map[string]any{}
		keys := make([]string, 0, len(md))
		for k := range md {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		for _, k := range keys {
			seen[k] = strings.Join(md[k], ",")
		}
		fields["metadata"] = seen
	}
	return structpb.NewStruct(fields)
}

func (e *echo) Unary(ctx context.Context, in *echopb.Msg) (*echopb.Reply, error) {
	md := e.recordMessage(ctx, echopb.UnaryMethod, in)
	return reply(in.GetValue(), md)
}

func (e *echo) Stream(stream echopb.StreamServer) error {
	first := true
	for {
		in, err := stream.Recv()
		if errors.Is(err, io.EOF) {
			return nil
		}
		if err != nil {
			return err
		}
		md := e.recordMessage(stream.Context(), echopb.StreamMethod, in)
		if !first {
			md = nil
		}
		first = false
		out, err := reply(in.GetValue(), md)
		if err != nil {
			return err
		}
		if err := stream.Send(out); err != nil {
			return err
		}
	}
}

func healthcheck(url string) error {
	c := &http.Client{Timeout: 2 * time.Second}
	resp, err := c.Get(url)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return errors.New(resp.Status)
	}
	return nil
}

func main() {
	addr := flag.String("addr", ":8080", "HTTP and gRPC (h2c) listen address")
	adminAddr := flag.String("admin", ":8081", "listen address for /seen and /healthz")
	check := flag.String("healthcheck", "", "probe this URL and exit 0 if it answers 200")
	flag.Parse()
	if *check != "" {
		if err := healthcheck(*check); err != nil {
			fmt.Fprintln(os.Stderr, "unhealthy:", err)
			os.Exit(1)
		}
		return
	}
	e := newEcho()
	var protocols http.Protocols
	protocols.SetHTTP1(true)
	protocols.SetUnencryptedHTTP2(true)
	go func() {
		log.Fatal((&http.Server{Addr: *adminAddr, Handler: e.admin(), ReadHeaderTimeout: 10 * time.Second}).ListenAndServe())
	}()
	log.Printf("echo listening on %s (admin %s)", *addr, *adminAddr)
	log.Fatal((&http.Server{Addr: *addr, Handler: e.handler(), Protocols: &protocols, ReadHeaderTimeout: 10 * time.Second}).ListenAndServe())
}
