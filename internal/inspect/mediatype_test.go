package inspect

import "testing"

func TestMediaType(t *testing.T) {
	for _, tc := range []struct {
		ct                       []string
		want                     string
		grpc, framed, web, multi bool
	}{
		{nil, "", false, false, false, false},
		{[]string{"application/json; charset=utf-8"}, "application/json", false, false, false, false},
		{[]string{" Application/GRPC "}, "application/grpc", true, true, false, false},
		{[]string{"application/grpc+proto"}, "application/grpc+proto", true, true, false, false},
		{[]string{"application/grpc-web+proto"}, "application/grpc-web+proto", true, false, true, false},
		{[]string{"application/grpc-web-text"}, "application/grpc-web-text", true, false, true, false},
		{[]string{"application/grpcx"}, "application/grpcx", false, false, false, false},
		{[]string{"text/plain", "application/grpc"}, "text/plain", false, false, false, true},
		{[]string{"text/plain,application/grpc"}, "text/plain,application/grpc", false, false, false, true},
		{[]string{`multipart/form-data; boundary="a,b"`}, "multipart/form-data", false, false, false, false},
		{[]string{"text/plain; charset=utf-8,application/grpc"}, "text/plain", false, false, false, true},
	} {
		r := &Request{Headers: map[string][]string{}}
		if tc.ct != nil {
			r.Headers["content-type"] = tc.ct
		}
		if got := r.MediaType(); got != tc.want {
			t.Errorf("%q: MediaType = %q, want %q", tc.ct, got, tc.want)
		}
		if r.GRPCContent() != tc.grpc || r.GRPCFramed() != tc.framed || r.GRPCWeb() != tc.web || r.MultipleContentTypes() != tc.multi {
			t.Errorf("%q: grpc %v framed %v web %v multi %v, want %v %v %v %v", tc.ct,
				r.GRPCContent(), r.GRPCFramed(), r.GRPCWeb(), r.MultipleContentTypes(), tc.grpc, tc.framed, tc.web, tc.multi)
		}
	}
}
