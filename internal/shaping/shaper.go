package shaping

import (
	"crypto/rand"
	"net"
	"sync"
	"time"
)

// Packet represents a data packet to be sent.
type Packet struct {
	Data []byte
	Addr net.Addr
}

// Shaper controls the timing, rate, and size of outgoing packets based on a profile.
type Shaper struct {
	mu         sync.Mutex
	queue      []Packet
	writeFunc  func(p []byte, addr net.Addr) (int, error)
	stopChan   chan struct{}
	wg         sync.WaitGroup
	profile    *Profile
	isPacing   bool // True if the pacer goroutine is running

	// remoteAddr is only set for the client-side shaper, to know where to send padding.
	remoteAddr net.Addr
}

// NewShaper creates and starts a new Shaper.
// If the profile's interval is <= 0, it will operate in a simple passthrough mode.
func NewShaper(writeFunc func(p []byte, addr net.Addr) (int, error), profile *Profile, remoteAddr net.Addr) *Shaper {
	s := &Shaper{
		queue:      make([]Packet, 0, 128),
		writeFunc:  writeFunc,
		stopChan:   make(chan struct{}),
		profile:    profile,
		remoteAddr: remoteAddr,
	}

	// Interval > 0 enables shaping.
	if profile.GetRandomIntervalMs() > 0 {
		s.isPacing = true
		s.wg.Add(1)
		go s.run()
	}
	return s
}

// Write queues a packet to be sent by the shaper, or sends it directly if shaping is disabled.
func (s *Shaper) Write(p []byte, addr net.Addr) {
	if !s.isPacing { // Passthrough mode
		s.writeFunc(p, addr)
		return
	}

	s.mu.Lock()
	defer s.mu.Unlock()
	s.queue = append(s.queue, Packet{Data: p, Addr: addr})
}

// Stop halts the shaper's background goroutine if it's running.
func (s *Shaper) Stop() {
	if s.isPacing {
		close(s.stopChan)
		s.wg.Wait()
	}
}

// run is the main loop for the shaper, using a dynamic timer.
func (s *Shaper) run() {
	defer s.wg.Done()
	for {
		interval := s.profile.GetRandomIntervalMs()
		if interval <= 0 {
			interval = 1 // Prevent timer from firing immediately in a tight loop
		}
		timer := time.NewTimer(time.Duration(interval) * time.Millisecond)

		select {
		case <-timer.C:
			s.sendNextPacket()
		case <-s.stopChan:
			timer.Stop()
			return
		}
	}
}

func (s *Shaper) sendNextPacket() {
	s.mu.Lock()
	var packet Packet
	if len(s.queue) > 0 {
		packet = s.queue[0]
		s.queue = s.queue[1:]
	}
	s.mu.Unlock()

	if packet.Data != nil {
		s.writeFunc(packet.Data, packet.Addr)
	} // else if s.remoteAddr != nil { // Temporarily disable padding
	// 	padding := s.generatePadding()
	// 	s.writeFunc(padding, s.remoteAddr)
	// }
}

// generatePadding creates a random-sized padding packet based on the profile.
func (s *Shaper) generatePadding() []byte {
	size := s.profile.GetRandomSize()
	padding := make([]byte, size)
	rand.Read(padding)
	return padding
}

// Unshape reverses any shaping applied to the received packet.
// Currently, since shaping does not modify packet contents, this is a no-op.
func (s *Shaper) Unshape(packet []byte) []byte {
	return packet
}
