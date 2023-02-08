//go:build !js
// +build !js

package webrtc

import (
	"io"
	"sync"
	"sync/atomic"
	"time"

	"github.com/icn-team/srtp/v2"
	"github.com/pion/rtp"
)

// srtpWriterFuture blocks Read/Write calls until
// the SRTP Session is available
type srtpWriterFuture struct {
	ssrc           SSRC
	rtpSender      *RTPSender
	rtcpReadStream atomic.Value // *srtp.ReadStreamSRTCP
	rtpWriteStream atomic.Value // *srtp.WriteStreamSRTP
	mu             sync.Mutex
	closed         bool
}

func (s *srtpWriterFuture) init(returnWhenNoSRTP bool) error {
	srtpReady := s.rtpSender.transport.SRTPReady()

	if returnWhenNoSRTP {
		select {
		case <-s.rtpSender.stopCalled:
			return io.ErrClosedPipe
		case <-srtpReady:
		default:
			return nil
		}
	} else {
		select {
		case <-s.rtpSender.stopCalled:
			return io.ErrClosedPipe
		case <-srtpReady:
		}
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	if s.closed {
		return io.ErrClosedPipe
	}

	srtcpSession, err := s.rtpSender.transport.getSRTCPSession()
	if err != nil {
		return err
	}

	rtcpReadStream, err := srtcpSession.OpenReadStream(uint32(s.ssrc))
	if err != nil {
		return err
	}

	srtpSession, err := s.rtpSender.transport.getSRTPSession()
	if err != nil {
		return err
	}

	rtpWriteStream, err := srtpSession.OpenWriteStream()
	if err != nil {
		return err
	}

	s.rtcpReadStream.Store(rtcpReadStream)
	s.rtpWriteStream.Store(rtpWriteStream)
	return nil
}

func (s *srtpWriterFuture) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.closed {
		return nil
	}
	s.closed = true

	if value, ok := s.rtcpReadStream.Load().(*srtp.ReadStreamSRTCP); ok {
		return value.Close()
	}

	return nil
}

func (s *srtpWriterFuture) Read(b []byte) (n int, err error) {
	if value, ok := s.rtcpReadStream.Load().(*srtp.ReadStreamSRTCP); ok {
		return value.Read(b)
	}

	if err := s.init(false); err != nil || s.rtcpReadStream.Load() == nil {
		return 0, err
	}

	return s.Read(b)
}

func (s *srtpWriterFuture) SetReadDeadline(t time.Time) error {
	if value, ok := s.rtcpReadStream.Load().(*srtp.ReadStreamSRTCP); ok {
		return value.SetReadDeadline(t)
	}

	if err := s.init(false); err != nil || s.rtcpReadStream.Load() == nil {
		return err
	}

	return s.SetReadDeadline(t)
}

func (s *srtpWriterFuture) WriteRTP(header *rtp.Header, payload []byte) (int, error) {
	if s.rtpSender.api.settingEngine.iris.enabled {
		return s.writeIRISRTP(header, payload)
	}

	if value, ok := s.rtpWriteStream.Load().(*srtp.WriteStreamSRTP); ok {
		return value.WriteRTP(header, payload)
	}

	if err := s.init(true); err != nil || s.rtpWriteStream.Load() == nil {
		return 0, err
	}

	return s.WriteRTP(header, payload)
}

func (s *srtpWriterFuture) WriteInsecureRTP(header *rtp.Header, payload []byte) (int, error) {
	if s.rtpSender.api.settingEngine.iris.enabled {
		return s.writeInsecureIRISRTP(header, payload)
	}

	if value, ok := s.rtpWriteStream.Load().(*srtp.WriteStreamSRTP); ok {
		return value.WriteInsecureRTP(header, payload)
	}

	if err := s.init(true); err != nil || s.rtpWriteStream.Load() == nil {
		return 0, err
	}

	return s.WriteInsecureRTP(header, payload)
}

func (s *srtpWriterFuture) Write(b []byte) (int, error) {
	if s.rtpSender.api.settingEngine.iris.enabled {
		return s.writeIRIS(b)
	}

	if value, ok := s.rtpWriteStream.Load().(*srtp.WriteStreamSRTP); ok {
		return value.Write(b)
	}

	if err := s.init(true); err != nil || s.rtpWriteStream.Load() == nil {
		return 0, err
	}

	return s.Write(b)
}

func (s *srtpWriterFuture) WriteInsecure(b []byte) (int, error) {
	if s.rtpSender.api.settingEngine.iris.enabled {
		return s.writeInsecureIRIS(b)
	}

	if value, ok := s.rtpWriteStream.Load().(*srtp.WriteStreamSRTP); ok {
		return value.WriteInsecure(b)
	}

	if err := s.init(true); err != nil || s.rtpWriteStream.Load() == nil {
		return 0, err
	}

	return s.WriteInsecure(b)
}

func (s *srtpWriterFuture) writeIRISRTP(header *rtp.Header, payload []byte) (int, error) {
	if value, ok := s.rtpWriteStream.Load().(*srtp.WriteStreamSRTP); ok {
		encrypted, err := value.EncryptRTP(header, payload)
		if err != nil {
			return 0, err
		}

		return s.sendIRIS(encrypted)
	}

	if err := s.init(true); err != nil || s.rtpWriteStream.Load() == nil {
		return 0, err
	}

	return s.writeIRISRTP(header, payload)

}

func (s *srtpWriterFuture) writeInsecureIRISRTP(header *rtp.Header, payload []byte) (int, error) {
	headerRaw, err := header.Marshal()
	if err != nil {
		return 0, err
	}

	return s.sendIRIS(append(headerRaw, payload...))
}

func (s *srtpWriterFuture) writeIRIS(b []byte) (int, error) {
	if value, ok := s.rtpWriteStream.Load().(*srtp.WriteStreamSRTP); ok {
		encrypted, err := value.Encrypt(b)
		if err != nil {
			return 0, err
		}

		return s.sendIRIS(encrypted)
	}

	if err := s.init(true); err != nil || s.rtpWriteStream.Load() == nil {
		return 0, err
	}

	return s.writeIRIS(b)
}

func (s *srtpWriterFuture) writeInsecureIRIS(b []byte) (int, error) {
	return s.sendIRIS(b)
}

func (s *srtpWriterFuture) sendIRIS(b []byte) (int, error) {
	switch s.rtpSender.kind {
	case RTPCodecTypeAudio:
		s.rtpSender.irisClient.ProduceAudioRtp(string(b), uint(len(b)))
	case RTPCodecTypeVideo:
		s.rtpSender.irisClient.ProduceVideoRtp(string(b), uint(len(b)))
	}
	return len(b), nil
}
