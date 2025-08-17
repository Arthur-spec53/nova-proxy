package protocol

import (
	"bytes"
	"net"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestEncodeDecode(t *testing.T) {
	testCases := []struct {
		name  string
		frame *Frame
	}{
		{
			name: "Domain Address",
			frame: &Frame{
				Version:  Version,
				Options:  0,
				AddrType: AddrTypeDomain,
				Host:     "example.com",
				Port:     80,
			},
		},
		{
			name: "IPv4 Address",
			frame: &Frame{
				Version:  Version,
				Options:  0,
				AddrType: AddrTypeIPv4,
				Host:     "192.168.1.1",
				Port:     443,
			},
		},
		{
			name: "IPv6 Address",
			frame: &Frame{
				Version:  Version,
				Options:  0,
				AddrType: AddrTypeIPv6,
				Host:     "2001:0db8:85a3:0000:0000:8a2e:0370:7334",
				Port:     8080,
			},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			var buf bytes.Buffer
			err := tc.frame.Encode(&buf)
			assert.NoError(t, err)

			decodedFrame, err := Decode(&buf)
			assert.NoError(t, err)

			assert.Equal(t, tc.frame.Version, decodedFrame.Version)
			assert.Equal(t, tc.frame.Options, decodedFrame.Options)
			assert.Equal(t, tc.frame.AddrType, decodedFrame.AddrType)
			assert.Equal(t, tc.frame.Port, decodedFrame.Port)

			// For IP addresses, compare the net.IP objects, not the string representation
			// as it can be canonicalized (e.g., IPv6 compression).
			if tc.frame.AddrType == AddrTypeIPv4 || tc.frame.AddrType == AddrTypeIPv6 {
				expectedIP := net.ParseIP(tc.frame.Host)
				actualIP := net.ParseIP(decodedFrame.Host)
				assert.True(t, expectedIP.Equal(actualIP), "IP addresses should be equal")
			} else {
				assert.Equal(t, tc.frame.Host, decodedFrame.Host)
			}
		})
	}
}
