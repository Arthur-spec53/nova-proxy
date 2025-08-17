package protocol

import (
	"encoding/binary"
	"errors"
	"io"
	"net"
)

const (
	Version = 1

	AddrTypeIPv4   = 1
	AddrTypeIPv6   = 2
	AddrTypeDomain = 3
)

var (
	ErrUnknownAddrType = errors.New("unknown address type")
	ErrInvalidVersion  = errors.New("invalid protocol version")
)

// Frame represents the metadata frame for a proxy request.
type Frame struct {
	Version  byte
	Options  byte
	AddrType byte
	Host     string
	Port     uint16
}

// Encode writes the frame to the given writer.
func (f *Frame) Encode(w io.Writer) error {
	buf := make([]byte, 0, 256)
	buf = append(buf, f.Version, f.Options, f.AddrType)

	var hostBytes []byte
	if f.AddrType == AddrTypeDomain {
		hostBytes = []byte(f.Host)
	} else {
		ip := net.ParseIP(f.Host)
		if ip4 := ip.To4(); ip4 != nil {
			hostBytes = ip4
		} else {
			hostBytes = ip
		}
	}

	addrLen := uint16(len(hostBytes))
	buf = binary.BigEndian.AppendUint16(buf, addrLen)
	buf = append(buf, hostBytes...)
	buf = binary.BigEndian.AppendUint16(buf, f.Port)

	_, err := w.Write(buf)
	return err
}

// Decode reads and parses a frame from the given reader.
func Decode(r io.Reader) (*Frame, error) {
	// Read Version(1), Options(1), AddrType(1), AddrLen(2)
	header := make([]byte, 5)
	if _, err := io.ReadFull(r, header); err != nil {
		return nil, err
	}

	if header[0] != Version {
		return nil, ErrInvalidVersion
	}

	f := &Frame{
		Version:  header[0],
		Options:  header[1],
		AddrType: header[2],
	}

	addrLen := binary.BigEndian.Uint16(header[3:])
	addrBuf := make([]byte, addrLen)
	if _, err := io.ReadFull(r, addrBuf); err != nil {
		return nil, err
	}

	switch f.AddrType {
	case AddrTypeIPv4, AddrTypeIPv6:
		f.Host = net.IP(addrBuf).String()
	case AddrTypeDomain:
		f.Host = string(addrBuf)
	default:
		return nil, ErrUnknownAddrType
	}

	portBuf := make([]byte, 2)
	if _, err := io.ReadFull(r, portBuf); err != nil {
		return nil, err
	}
	f.Port = binary.BigEndian.Uint16(portBuf)

	return f, nil
}
