package inspect

import (
	"encoding/base64"
	"strings"
	"testing"
)

func grpcWebFrame(payload string) []byte {
	n := len(payload)
	return append([]byte{0, byte(n >> 24), byte(n >> 16), byte(n >> 8), byte(n)}, payload...)
}

func b64(b []byte) string { return base64.StdEncoding.EncodeToString(b) }

func TestDecodeGRPCWebText(t *testing.T) {
	one, two := grpcWebFrame("\x0a\x05admin"), grpcWebFrame("\x0a\x04next")
	cases := []struct {
		name      string
		body      string
		truncated bool
		want      []byte
		ok        bool
	}{
		{"single chunk", b64(one), false, one, true},
		{"padded chunks concatenated", b64(one) + b64(two), false, append(append([]byte{}, one...), two...), true},
		{"line breaks ignored", b64(one)[:8] + "\r\n" + b64(one)[8:], false, one, true},
		{"truncated mid-quad drops the partial quad", b64(one)[:10], true, one[:6], true},
		{"length not a multiple of 4 and not truncated", b64(one)[:10], false, nil, false},
		{"not base64", "attack!!", false, nil, false},
		{"padding inside a quad", "QQ=A", false, nil, false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got, ok := DecodeGRPCWebText([]byte(c.body), c.truncated)
			if ok != c.ok || string(got) != string(c.want) {
				t.Errorf("DecodeGRPCWebText(%q, %v) = %q, %v; want %q, %v", c.body, c.truncated, got, ok, c.want, c.ok)
			}
		})
	}
}

func grpcWebRequest(ct string, body []byte, truncated bool) *Request {
	return &Request{
		Method: "POST", Path: "/echo.v1.Echo/Unary", GRPCService: "echo.v1.Echo", GRPCMethod: "Unary",
		Headers: map[string][]string{"content-type": {ct}}, Body: body, BodyTruncated: truncated,
	}
}

func TestRenderDecodesGRPCWebText(t *testing.T) {
	payload := "\x0a\x1bx' UNION SELECT password --"
	for _, ct := range []string{"application/grpc-web-text", "application/grpc-web-text+proto", "Application/GRPC-Web-Text; charset=utf-8"} {
		got := grpcWebRequest(ct, []byte(b64(grpcWebFrame(payload))), false).Render()
		if !strings.Contains(got, "body (decoded from grpc-web-text) [text runs]:\n| x' UNION SELECT password --\n") {
			t.Errorf("%s: prompt does not show the decoded message:\n%s", ct, got)
		}
	}
	got := grpcWebRequest("application/grpc-web-text", []byte(b64(grpcWebFrame(payload))[:20]), true).Render()
	if !strings.Contains(got, "body (truncated, decoded from grpc-web-text)") {
		t.Errorf("truncated body label missing:\n%s", got)
	}
}

func TestRenderGRPCWebTextInvalidBase64IsLabelled(t *testing.T) {
	got := grpcWebRequest("application/grpc-web-text", []byte("plain attack text, not base64!"), false).Render()
	if !strings.Contains(got, "body (grpc-web-text, not valid base64) [text runs]:\n| plain attack text, not base64!\n") {
		t.Errorf("undecodable body must still be shown, labelled:\n%s", got)
	}
}

func TestRenderGRPCWebBinaryUnchanged(t *testing.T) {
	got := grpcWebRequest("application/grpc-web+proto", grpcWebFrame("\x0a\x05hello"), false).Render()
	if !strings.Contains(got, "body [text runs]:\n| hello\n") || strings.Contains(got, "decoded") {
		t.Errorf("binary gRPC-Web rendering changed:\n%s", got)
	}
}
