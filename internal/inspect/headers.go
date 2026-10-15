package inspect

import (
	"iter"
	"slices"
	"strings"
)

var inspectedHeaders = []string{
	"content-type",
	"transfer-encoding", "content-length", "host", "connection", "upgrade",
	"origin", "sec-websocket-key", "sec-websocket-version", "sec-websocket-protocol",
	"content-encoding", "grpc-encoding",
	"referer", "authorization", "cookie",
	"x-forwarded-for",
	"traceparent", "tracestate", "baggage",
}

func InspectedHeaders() []string { return slices.Clone(inspectedHeaders) }

func IsInspectedHeader(name string) bool { return slices.Contains(inspectedHeaders, name) }

func ListElements(values []string) iter.Seq[string] {
	return func(yield func(string) bool) {
		for _, v := range values {
			for e := range strings.SplitSeq(v, ",") {
				if e = strings.TrimSpace(e); e != "" && !yield(e) {
					return
				}
			}
		}
	}
}
