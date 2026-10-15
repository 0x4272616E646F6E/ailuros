//go:build integration || k8s

package echopb

import (
	"context"

	"google.golang.org/grpc"
	"google.golang.org/protobuf/types/known/structpb"
	"google.golang.org/protobuf/types/known/wrapperspb"
)

const (
	ServiceName  = "echo.v1.Echo"
	UnaryMethod  = "/echo.v1.Echo/Unary"
	StreamMethod = "/echo.v1.Echo/Stream"
)

type (
	Msg          = wrapperspb.StringValue
	Reply        = structpb.Struct
	StreamServer = grpc.BidiStreamingServer[Msg, Reply]
	StreamClient = grpc.BidiStreamingClient[Msg, Reply]
)

type Server interface {
	Unary(ctx context.Context, in *Msg) (*Reply, error)
	Stream(stream StreamServer) error
}

var serviceDesc = grpc.ServiceDesc{
	ServiceName: ServiceName,
	HandlerType: (*Server)(nil),
	Methods:     []grpc.MethodDesc{{MethodName: "Unary", Handler: unaryHandler}},
	Streams:     []grpc.StreamDesc{{StreamName: "Stream", Handler: streamHandler, ServerStreams: true, ClientStreams: true}},
}

func Register(s grpc.ServiceRegistrar, srv Server) { s.RegisterService(&serviceDesc, srv) }

func unaryHandler(srv any, ctx context.Context, dec func(any) error, interceptor grpc.UnaryServerInterceptor) (any, error) {
	in := new(Msg)
	if err := dec(in); err != nil {
		return nil, err
	}
	call := func(ctx context.Context, req any) (any, error) { return srv.(Server).Unary(ctx, req.(*Msg)) }
	if interceptor == nil {
		return call(ctx, in)
	}
	return interceptor(ctx, in, &grpc.UnaryServerInfo{Server: srv, FullMethod: UnaryMethod}, call)
}

func streamHandler(srv any, stream grpc.ServerStream) error {
	return srv.(Server).Stream(&grpc.GenericServerStream[Msg, Reply]{ServerStream: stream})
}

func Unary(ctx context.Context, cc grpc.ClientConnInterface, in *Msg, opts ...grpc.CallOption) (*Reply, error) {
	out := new(Reply)
	if err := cc.Invoke(ctx, UnaryMethod, in, out, opts...); err != nil {
		return nil, err
	}
	return out, nil
}

func Stream(ctx context.Context, cc grpc.ClientConnInterface, opts ...grpc.CallOption) (StreamClient, error) {
	s, err := cc.NewStream(ctx, &serviceDesc.Streams[0], StreamMethod, opts...)
	if err != nil {
		return nil, err
	}
	return &grpc.GenericClientStream[Msg, Reply]{ClientStream: s}, nil
}
