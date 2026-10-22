//go:build integration

package main

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/encoding/gzip"
	"google.golang.org/grpc/metadata"

	"github.com/0x4272616E646F6E/decision-waf/test/integration/echo/echopb"
)

func startEcho(t *testing.T) (*echo, *httptest.Server, *httptest.Server) {
	t.Helper()
	e := newEcho()
	srv := httptest.NewUnstartedServer(e.handler())
	srv.Config.Protocols = new(http.Protocols)
	srv.Config.Protocols.SetHTTP1(true)
	srv.Config.Protocols.SetUnencryptedHTTP2(true)
	srv.Start()
	admin := httptest.NewServer(e.admin())
	t.Cleanup(func() { srv.Close(); admin.Close() })
	return e, srv, admin
}

func seen(t *testing.T, admin *httptest.Server, marker string) []record {
	t.Helper()
	resp, err := admin.Client().Get(admin.URL + "/seen?contains=" + marker)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	var out []record
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		t.Fatal(err)
	}
	return out
}

func TestEchoDescribesHTTPRequest(t *testing.T) {
	_, srv, admin := startEcho(t)
	body := []byte{0, 1, 2, 0xff, 'h', 'i'}
	req, _ := http.NewRequest("POST", srv.URL+"/items/m1?q=2", bytes.NewReader(body))
	req.Header.Set("X-Test", "yes")
	resp, err := srv.Client().Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	var got record
	if err := json.NewDecoder(resp.Body).Decode(&got); err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != 200 || got.Method != "POST" || got.Path != "/items/m1" || got.Query != "q=2" ||
		got.Headers["X-Test"][0] != "yes" || !bytes.Equal(got.Body, body) || got.Kind != "http" {
		t.Errorf("echo = %d %+v", resp.StatusCode, got)
	}
	if recs := seen(t, admin, "m1"); len(recs) != 1 || recs[0].Path != "/items/m1" {
		t.Errorf("seen(m1) = %+v, want the one request", recs)
	}
	if recs := seen(t, admin, "m2"); len(recs) != 0 {
		t.Errorf("seen(m2) = %+v, want none", recs)
	}
}

func TestEchoServesGRPCOnTheHTTPPort(t *testing.T) {
	_, srv, admin := startEcho(t)
	conn, err := grpc.NewClient(strings.TrimPrefix(srv.URL, "http://"), grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	ctx = metadata.AppendToOutgoingContext(ctx, "x-ailuros-request-id", "rid-1")

	out, err := echopb.Unary(ctx, conn, &echopb.Msg{Value: "unary-m3"}, grpc.UseCompressor(gzip.Name))
	if err != nil {
		t.Fatal(err)
	}
	if out.Fields["text"].GetStringValue() != "unary-m3" ||
		out.Fields["metadata"].GetStructValue().Fields["x-ailuros-request-id"].GetStringValue() != "rid-1" {
		t.Errorf("Unary reply = %v", out)
	}

	stream, err := echopb.Stream(ctx, conn)
	if err != nil {
		t.Fatal(err)
	}
	for i, text := range []string{"first-m4", "second-m4"} {
		if err := stream.Send(&echopb.Msg{Value: text}); err != nil {
			t.Fatal(err)
		}
		r, err := stream.Recv()
		if err != nil {
			t.Fatal(err)
		}
		_, hasMD := r.Fields["metadata"]
		if r.Fields["text"].GetStringValue() != text || hasMD != (i == 0) {
			t.Errorf("reply %d = %v, want text %q with metadata only on the first", i, r, text)
		}
	}
	if err := stream.CloseSend(); err != nil {
		t.Fatal(err)
	}
	if recs := seen(t, admin, "-m4"); len(recs) != 2 || recs[0].Kind != "grpc" || recs[0].Path != echopb.StreamMethod {
		t.Errorf("seen(-m4) = %+v, want two gRPC stream records", recs)
	}
}

func TestEchoHealthcheck(t *testing.T) {
	_, _, admin := startEcho(t)
	if err := healthcheck(admin.URL + "/healthz"); err != nil {
		t.Errorf("healthcheck = %v, want nil", err)
	}
}
