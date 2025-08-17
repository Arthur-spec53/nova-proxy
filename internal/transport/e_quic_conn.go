package transport

import (
	"errors"
	"fmt"
	"net"
	"nova-proxy/internal/e_quic"
	"nova-proxy/internal/shaping"
	"nova-proxy/pkg/log"
	"syscall"
)

// EQUICTransport is a net.PacketConn that wraps a real net.PacketConn
// and applies the E-QUIC and traffic shaping layers.
type EQUICTransport struct {
	net.PacketConn
	key    []byte
	shaper *shaping.Shaper
}

// This interface is checked by quic-go to get the underlying file descriptor.
type syscallConn interface {
	SyscallConn() (syscall.RawConn, error)
}

// SyscallConn returns the underlying connection's syscall conn.
// This is needed for quic-go to be able to set socket options.
func (c *EQUICTransport) SyscallConn() (syscall.RawConn, error) {
	if sc, ok := c.PacketConn.(syscallConn); ok {
		return sc.SyscallConn()
	}
	return nil, errors.New("underlying PacketConn does not implement SyscallConn")
}

// NewEQUICTransport creates a new EQUICTransport without a shaper.
func NewEQUICTransport(conn net.PacketConn, key []byte) *EQUICTransport {
	return &EQUICTransport{
		PacketConn: conn,
		key:        key,
	}
}

// SetShaper attaches a shaper to the transport.
func (c *EQUICTransport) SetShaper(shaper *shaping.Shaper) {
	c.shaper = shaper
}

// WriteToNetwork is the actual function that packs and sends a packet.
// It is passed to the shaper.
func (c *EQUICTransport) WriteToNetwork(p []byte, addr net.Addr) (int, error) {
	packed, err := e_quic.Pack(p, c.key)
	if err != nil {
		return 0, err
	}
	// The underlying write to the network
	n, err := c.PacketConn.WriteTo(packed, addr)
	if err != nil {
		return 0, err
	}
	if n != len(packed) {
		return 0, fmt.Errorf("short write to underlying conn")
	}
	return len(p), nil
}

// WriteTo now queues the packet in the shaper instead of sending it directly.
func (c *EQUICTransport) WriteTo(p []byte, addr net.Addr) (int, error) {
	// We need to copy the packet buffer `p` because it will be reused by quic-go.
	pCopy := make([]byte, len(p))
	copy(pCopy, p)
	if c.shaper != nil {
		c.shaper.Write(pCopy, addr)
		return len(p), nil
	} else {
		return c.WriteToNetwork(pCopy, addr)
	}
}

// Close stops the shaper and closes the underlying connection.
func (c *EQUICTransport) Close() error {
	c.shaper.Stop()
	return c.PacketConn.Close()
}

// ReadFrom reads an E-QUIC packet from the underlying connection and unpacks it.
// It loops internally to discard invalid packets, making it resilient.
func (c *EQUICTransport) ReadFrom(p []byte) (int, net.Addr, error) {
	for {
		n, addr, err := c.PacketConn.ReadFrom(p)
		if err != nil {
			return 0, nil, err
		}
		log.Logger.Printf("Received raw packet from %v, size %d", addr, n)
		packet := p[:n]
		if c.shaper != nil {
			packet = c.shaper.Unshape(packet)
		}
		unpacked, err := e_quic.Unpack(packet, c.key)
		if err != nil {
			if err == e_quic.ErrInvalidPacket {
				log.Logger.Printf("Discarding invalid packet from %v: %v", addr, err)
				continue
			}
			log.Logger.Printf("e_quic unpack failed for packet from %v: %v", addr, err)
			return 0, nil, err
		}
		copy(p, unpacked)
		return len(unpacked), addr, nil
	}
}
