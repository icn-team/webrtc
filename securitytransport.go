package webrtc

import (
	"github.com/icn-team/srtp/v2"
	"github.com/pion/interceptor"
	"github.com/pion/rtcp"
)

type SecurityTransportType uint

const (
	SecurityTransportTypeDTLS SecurityTransportType = iota
	SecurityTransportTypeShared
)

type SecurityTransport interface {
	ICETransport() *ICETransport
	OnStateChange(f func(SecurityTransportState))
	State() SecurityTransportState
	WriteRTCP(pkts []rtcp.Packet) (int, error)
	WriteInsecureRTCP(pkts []rtcp.Packet) (int, error)
	GetLocalParameters() (SecurityParameters, error)
	GetRemoteCertificate() []byte
	getSRTPSession() (*srtp.SessionSRTP, error)
	getSRTCPSession() (*srtp.SessionSRTCP, error)
	dtlsRole() DTLSRole
	Start(remoteParameters SecurityParameters) error
	Stop() error
	storeSimulcastStream(s *srtp.ReadStreamSRTP)
	streamsForSSRC(ssrc SSRC, streamInfo interceptor.StreamInfo) (*srtp.ReadStreamSRTP, interceptor.RTPReader, *srtp.ReadStreamSRTCP, interceptor.RTCPReader, error)
	SRTPReady() <-chan struct{}
}

type GKA interface {
	UpdateKeys(exporter srtp.KeyingMaterialExporter) error
}
