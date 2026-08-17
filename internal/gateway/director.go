package gateway

import (
	"fmt"
	"io"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/mem"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
)

// rawCodec is a passthrough gRPC codec: it moves opaque message bytes without
// decoding them, so the gateway can forward any method for any service without
// compiling in its protos. Message bytes are materialized into a plain slice on
// receipt, trading a copy for freedom from buffer-pool refcount lifetimes —
// correct-by-default matters more than zero-copy on the control-plane path.
type rawCodec struct{}

// frame carries opaque message bytes through Recv/SendMsg.
type frame struct{ data []byte }

func (rawCodec) Name() string { return "vmd-gateway-raw" }

func (rawCodec) Marshal(v any) (mem.BufferSlice, error) {
	f, ok := v.(*frame)
	if !ok {
		return nil, fmt.Errorf("gateway raw codec: cannot marshal %T", v)
	}
	return mem.BufferSlice{mem.SliceBuffer(f.data)}, nil
}

func (rawCodec) Unmarshal(data mem.BufferSlice, v any) error {
	f, ok := v.(*frame)
	if !ok {
		return fmt.Errorf("gateway raw codec: cannot unmarshal into %T", v)
	}
	f.data = data.Materialize()
	return nil
}

// direct is the gateway's UnknownServiceHandler: it transparently proxies an
// incoming stream (unary or streaming) to the active upstream generation.
func (g *Gateway) direct(_ any, serverStream grpc.ServerStream) error {
	method, ok := grpc.MethodFromServerStream(serverStream)
	if !ok {
		return status.Error(codes.Internal, "gateway: no method in stream")
	}

	up, quiescing := g.router.Active()
	if quiescing || up.Socket == "" {
		// Bounded quiesce for gRPC: refuse with a retryable status. The control
		// plane retries Unavailable across a cutover, so this is invisible for
		// unary RPCs.
		return status.Error(codes.Unavailable, "gateway draining; retry")
	}

	conn, err := g.upstreamConn(up.Socket)
	if err != nil {
		return status.Errorf(codes.Unavailable, "gateway: dial upstream: %v", err)
	}

	clientCtx := serverStream.Context()
	if md, ok := metadata.FromIncomingContext(clientCtx); ok {
		clientCtx = metadata.NewOutgoingContext(clientCtx, md.Copy())
	}

	clientStream, err := conn.NewStream(
		clientCtx,
		&grpc.StreamDesc{ServerStreams: true, ClientStreams: true},
		method,
	)
	if err != nil {
		return err
	}

	// Pump both directions concurrently. Request frames flow client→upstream;
	// response frames (with header on the first, trailer at the end) flow
	// upstream→client.
	reqErr := forward(serverStream, clientStream, nil)
	respErr := forward(clientStream, serverStream, clientStream)

	for i := 0; i < 2; i++ {
		select {
		case err := <-reqErr:
			// Client finished sending. Half-close the upstream so it can
			// complete; a real error aborts.
			if err == io.EOF {
				_ = clientStream.CloseSend()
				continue
			}
			return status.Errorf(codes.Internal, "gateway: request stream: %v", err)
		case err := <-respErr:
			// Upstream finished responding. Its trailer is the RPC's trailer.
			serverStream.SetTrailer(clientStream.Trailer())
			if err == io.EOF {
				return nil
			}
			return err
		}
	}
	return status.Error(codes.Internal, "gateway: stream ended without resolution")
}

// stream is the minimal Recv/SendMsg surface shared by grpc.ServerStream and
// grpc.ClientStream, so one forward loop handles both directions.
type stream interface {
	SendMsg(m any) error
	RecvMsg(m any) error
}

// headerSource, when non-nil, is a ClientStream whose header must be relayed to
// the destination (a ServerStream) before the first response frame.
type headerSource interface {
	Header() (metadata.MD, error)
}

func forward(src, dst stream, hdr headerSource) chan error {
	ret := make(chan error, 1)
	go func() {
		f := &frame{}
		for i := 0; ; i++ {
			if err := src.RecvMsg(f); err != nil {
				ret <- err // io.EOF on clean end
				return
			}
			if i == 0 && hdr != nil {
				md, err := hdr.Header()
				if err != nil {
					ret <- err
					return
				}
				if ss, ok := dst.(grpc.ServerStream); ok {
					if err := ss.SendHeader(md); err != nil {
						ret <- err
						return
					}
				}
			}
			if err := dst.SendMsg(f); err != nil {
				ret <- err
				return
			}
		}
	}()
	return ret
}
