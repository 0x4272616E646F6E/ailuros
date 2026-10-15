package extproc

import (
	corev3 "github.com/envoyproxy/go-control-plane/envoy/config/core/v3"
	extprocv3 "github.com/envoyproxy/go-control-plane/envoy/service/ext_proc/v3"
	typev3 "github.com/envoyproxy/go-control-plane/envoy/type/v3"

	"github.com/0x4272616E646F6E/ailuros/internal/decision"
	"github.com/0x4272616E646F6E/ailuros/internal/frontend"
	"github.com/0x4272616E646F6E/ailuros/internal/frontend/envoyreq"
)

func (st *stream) continueFor(msg *extprocv3.ProcessingRequest, extra []byte, set []*corev3.HeaderValueOption) []*extprocv3.ProcessingResponse {
	switch m := msg.GetRequest().(type) {
	case *extprocv3.ProcessingRequest_RequestHeaders:
		return []*extprocv3.ProcessingResponse{headersResponse(set)}
	case *extprocv3.ProcessingRequest_RequestBody:
		if !st.fullDuplex {
			return []*extprocv3.ProcessingResponse{bodyResponse(set)}
		}
		data := extra
		if !st.absorbed {
			data = append(data, m.RequestBody.GetBody()...)
		}
		return emit(data, m.RequestBody.GetEndOfStream(), false)
	case *extprocv3.ProcessingRequest_RequestTrailers:
		if st.fullDuplex {
			return emit(extra, true, true)
		}
		return []*extprocv3.ProcessingResponse{trailersResponse()}
	case *extprocv3.ProcessingRequest_ResponseHeaders:
		return []*extprocv3.ProcessingResponse{{Response: &extprocv3.ProcessingResponse_ResponseHeaders{ResponseHeaders: &extprocv3.HeadersResponse{}}}}
	case *extprocv3.ProcessingRequest_ResponseBody:
		return []*extprocv3.ProcessingResponse{{Response: &extprocv3.ProcessingResponse_ResponseBody{ResponseBody: &extprocv3.BodyResponse{}}}}
	case *extprocv3.ProcessingRequest_ResponseTrailers:
		return []*extprocv3.ProcessingResponse{{Response: &extprocv3.ProcessingResponse_ResponseTrailers{ResponseTrailers: &extprocv3.TrailersResponse{}}}}
	}
	return nil
}

func (st *stream) immediate(d decision.Decision) *extprocv3.ProcessingResponse {
	dn := frontend.DenialFor(d)
	headers := envoyreq.DenyHeaders(d, st.s.cfg.ExposeVerdict)
	ir := &extprocv3.ImmediateResponse{
		Status:  &typev3.HttpStatus{Code: typev3.StatusCode(dn.HTTPStatus)}, //nolint:gosec // G115: Denial status codes are fixed constants (400/403/413/503, gRPC 3/7/8/14)
		Headers: &extprocv3.HeaderMutation{SetHeaders: headers},
		Body:    dn.Body(d.RequestID),
		Details: "ailuros_" + string(d.Outcome),
	}
	if st.req != nil && st.req.GRPCContent() {
		ir.GrpcStatus = &extprocv3.GrpcStatus{Status: uint32(dn.GRPCStatus)}
	}
	return &extprocv3.ProcessingResponse{Response: &extprocv3.ProcessingResponse_ImmediateResponse{ImmediateResponse: ir}}
}

func headersResponse(set []*corev3.HeaderValueOption) *extprocv3.ProcessingResponse {
	return &extprocv3.ProcessingResponse{Response: &extprocv3.ProcessingResponse_RequestHeaders{
		RequestHeaders: &extprocv3.HeadersResponse{Response: commonResponse(set)},
	}}
}

func bodyResponse(set []*corev3.HeaderValueOption) *extprocv3.ProcessingResponse {
	return &extprocv3.ProcessingResponse{Response: &extprocv3.ProcessingResponse_RequestBody{
		RequestBody: &extprocv3.BodyResponse{Response: commonResponse(set)},
	}}
}

func trailersResponse() *extprocv3.ProcessingResponse {
	return &extprocv3.ProcessingResponse{Response: &extprocv3.ProcessingResponse_RequestTrailers{
		RequestTrailers: &extprocv3.TrailersResponse{},
	}}
}

func commonResponse(set []*corev3.HeaderValueOption) *extprocv3.CommonResponse {
	cr := &extprocv3.CommonResponse{Status: extprocv3.CommonResponse_CONTINUE}
	if len(set) > 0 {
		cr.HeaderMutation = &extprocv3.HeaderMutation{SetHeaders: set}
	}
	return cr
}

func emit(data []byte, end, trailers bool) []*extprocv3.ProcessingResponse {
	var out []*extprocv3.ProcessingResponse
	for len(data) > 0 || (end && !trailers && len(out) == 0) {
		n := min(len(data), maxChunk)
		last := n == len(data)
		out = append(out, &extprocv3.ProcessingResponse{Response: &extprocv3.ProcessingResponse_RequestBody{
			RequestBody: &extprocv3.BodyResponse{Response: &extprocv3.CommonResponse{
				BodyMutation: &extprocv3.BodyMutation{Mutation: &extprocv3.BodyMutation_StreamedResponse{
					StreamedResponse: &extprocv3.StreamedBodyResponse{Body: data[:n], EndOfStream: last && end && !trailers},
				}},
			}},
		}})
		data = data[n:]
		if last {
			break
		}
	}
	if end && trailers {
		out = append(out, trailersResponse())
	}
	return out
}
