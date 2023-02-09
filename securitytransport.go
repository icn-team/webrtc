package webrtc

import (
	"bitbucket-eng-gpk1.cisco.com/bitbucket/scm/icn/iris/goiris/pkg/iris"
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
	WriteIRISRTCP(pkts []rtcp.Packet, kind RTPCodecType) (int, error)
	WriteInsecureRTCP(pkts []rtcp.Packet) (int, error)
	WriteInsecureIRISRTCP(pkts []rtcp.Packet, kind RTPCodecType) (int, error)
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
	irisClient() iris.IrisClient
}

type GKA interface {
	UpdateKeys(exporter srtp.KeyingMaterialExporter) error
}

func receiveAudio(st SecurityTransport) iris.IrisCallbackFunc {
	return iris.IrisCallbackFunc(func(b string, size uint64, index uint64) {
		srtpSession, err := st.getSRTPSession()
		if err != nil {
			return
		}
		if err = srtpSession.Decrypt([]byte(b)); err != nil {
			return
		}
	})
}

func receiveVideo(st SecurityTransport) iris.IrisCallbackFunc {
	return iris.IrisCallbackFunc(func(b string, size uint64, index uint64) {
		srtpSession, err := st.getSRTPSession()
		if err != nil {
			return
		}
		if err = srtpSession.Decrypt([]byte(b)); err != nil {
			return
		}
	})
}

func receiveRTCP(st SecurityTransport) iris.IrisCallbackFunc {
	return iris.IrisCallbackFunc(func(b string, size uint64, index uint64) {
		srtcpSession, err := st.getSRTCPSession()
		if err != nil {
			return
		}
		if err = srtcpSession.Decrypt([]byte(b)); err != nil {
			return
		}
	})
}
