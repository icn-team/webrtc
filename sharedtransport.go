//go:build !js
// +build !js

package webrtc

import (
	"crypto/sha256"
	"fmt"
	"io"
	"sync"
	"sync/atomic"

	"bitbucket-eng-gpk1.cisco.com/bitbucket/scm/icn/iris/goiris/pkg/iris"
	"github.com/icn-team/srtp/v2"
	"github.com/icn-team/webrtc/v3/internal/mux"
	"github.com/icn-team/webrtc/v3/internal/util"
	"github.com/pion/interceptor"
	"github.com/pion/logging"
	"github.com/pion/rtcp"
	"golang.org/x/crypto/hkdf"
)

// SharedTransport allows an application access to information about the Shared
// transport over which RTP and RTCP packets are sent and received by
// RTPSender and RTPReceiver, as well other data such as SCTP packets sent
// and received by data channels.
type SharedTransport struct {
	lock sync.RWMutex

	iceTransport          *ICETransport
	state                 SecurityTransportState
	srtpProtectionProfile srtp.ProtectionProfile

	onStateChangeHandler func(SecurityTransportState)

	srtpConfig                  *srtp.Config
	srtpSession, srtcpSession   atomic.Value
	srtpEndpoint, srtcpEndpoint *mux.Endpoint
	simulcastStreams            []*srtp.ReadStreamSRTP
	srtpReady                   chan struct{}

	api *API
	log logging.LeveledLogger

	irisTransport iris.IrisClient
}

type mlsTransportBootstrap struct {
	secret []byte
}

func (m *mlsTransportBootstrap) ExportKeyingMaterial(label string, context []byte, length int) ([]byte, error) {
	hkdf := hkdf.New(sha256.New, m.secret, []byte(label), context)
	keyingMaterial := make([]byte, length)

	if _, err := io.ReadFull(hkdf, keyingMaterial); err != nil {
		return nil, err
	}

	return keyingMaterial, nil
}

func (api *API) NewSharedTransport(transport *ICETransport, irisClient iris.IrisClient) (*SharedTransport, error) {
	t := &SharedTransport{
		iceTransport:          transport,
		api:                   api,
		state:                 SecurityTransportStateNew,
		srtpProtectionProfile: srtp.ProtectionProfileAes128CmHmacSha1_80,
		srtpReady:             make(chan struct{}),
		log:                   api.settingEngine.LoggerFactory.NewLogger("mlstransport"),
		irisTransport:         irisClient,
	}

	return t, nil
}

// ICETransport returns the currently-configured *ICETransport or nil
// if one has not been configured
func (t *SharedTransport) ICETransport() *ICETransport {
	t.lock.RLock()
	defer t.lock.RUnlock()
	return t.iceTransport
}

// onStateChange requires the caller holds the lock
func (t *SharedTransport) onStateChange(state SecurityTransportState) {
	t.state = state
	handler := t.onStateChangeHandler
	if handler != nil {
		handler(state)
	}
}

// OnStateChange sets a handler that is fired when the Shared connection state changes.
func (t *SharedTransport) OnStateChange(f func(SecurityTransportState)) {
	t.lock.Lock()
	defer t.lock.Unlock()
	t.onStateChangeHandler = f
}

// State returns the current Shared transport state.
func (t *SharedTransport) State() SecurityTransportState {
	t.lock.RLock()
	defer t.lock.RUnlock()
	return t.state
}

// WriteRTCP sends a user provided RTCP packet to the connected peer. If no peer is connected the
// packet is discarded.
func (t *SharedTransport) WriteRTCP(pkts []rtcp.Packet) (int, error) {
	raw, err := rtcp.Marshal(pkts)
	if err != nil {
		return 0, err
	}

	srtcpSession, err := t.getSRTCPSession()
	if err != nil {
		return 0, err
	}

	writeStream, err := srtcpSession.OpenWriteStream()
	if err != nil {
		return 0, fmt.Errorf("%w: %v", errPeerConnWriteRTCPOpenWriteStream, err)
	}

	if n, err := writeStream.Write(raw); err != nil {
		return n, err
	}
	return 0, nil
}

// WriteInsecureRTCP sends a user provided RTCP packet to the connected peer
// without encryption. If no peer is connected the packet is discarded.
func (t *SharedTransport) WriteInsecureRTCP(pkts []rtcp.Packet) (int, error) {
	raw, err := rtcp.Marshal(pkts)
	if err != nil {
		return 0, err
	}

	srtcpSession, err := t.getSRTCPSession()
	if err != nil {
		return 0, err
	}

	writeStream, err := srtcpSession.OpenWriteStream()
	if err != nil {
		return 0, fmt.Errorf("%w: %v", errPeerConnWriteRTCPOpenWriteStream, err)
	}

	if n, err := writeStream.WriteInsecure(raw); err != nil {
		return n, err
	}
	return 0, nil
}

// GetLocalParameters returns the Shared parameters of the local SharedTransport upon construction.
func (t *SharedTransport) GetLocalParameters() (SecurityParameters, error) {
	return SecurityParameters{
		DTLSRole:         DTLSRoleAuto, // always returns the default role
		DTLSFingerprints: []DTLSFingerprint{},
	}, nil
}

// GetRemoteCertificate returns the certificate chain in use by the remote side
// returns an empty list prior to selection of the remote certificate
func (t *SharedTransport) GetRemoteCertificate() []byte {
	return nil
}

func (t *SharedTransport) startSRTP() error {
	srtpConfig := t.srtpConfig

	if srtpConfig == nil {
		srtpConfig = &srtp.Config{Profile: t.srtpProtectionProfile}
		bootstrap := &mlsTransportBootstrap{secret: []byte("hunter2")}
		if err := srtpConfig.ExtractSessionKeysFromShared(bootstrap); err != nil {
			return err
		}
	}

	srtpConfig.BufferFactory = t.api.settingEngine.BufferFactory
	srtpConfig.LoggerFactory = t.api.settingEngine.LoggerFactory

	if t.api.settingEngine.disableSRTPDecrypt {
		srtpConfig.RemoteOptions = append(
			srtpConfig.RemoteOptions,
			srtp.SRTPNoDecrypt(),
		)
	}

	if t.api.settingEngine.disableSRTCPDecrypt {
		srtpConfig.RemoteOptions = append(
			srtpConfig.RemoteOptions,
			srtp.SRTCPNoDecrypt(),
		)
	}

	if t.api.settingEngine.replayProtection.SRTP != nil {
		srtpConfig.RemoteOptions = append(
			srtpConfig.RemoteOptions,
			srtp.SRTPReplayProtection(*t.api.settingEngine.replayProtection.SRTP),
		)
	}

	if t.api.settingEngine.disableSRTPReplayProtection {
		srtpConfig.RemoteOptions = append(
			srtpConfig.RemoteOptions,
			srtp.SRTPNoReplayProtection(),
		)
	}

	if t.api.settingEngine.replayProtection.SRTCP != nil {
		srtpConfig.RemoteOptions = append(
			srtpConfig.RemoteOptions,
			srtp.SRTCPReplayProtection(*t.api.settingEngine.replayProtection.SRTCP),
		)
	}

	if t.api.settingEngine.disableSRTCPReplayProtection {
		srtpConfig.RemoteOptions = append(
			srtpConfig.RemoteOptions,
			srtp.SRTCPNoReplayProtection(),
		)
	}

	srtpSession, err := srtp.NewSessionSRTP(t.srtpEndpoint, srtpConfig)
	if err != nil {
		return fmt.Errorf("%w: %v", errFailedToStartSRTP, err)
	}

	srtcpSession, err := srtp.NewSessionSRTCP(t.srtcpEndpoint, srtpConfig)
	if err != nil {
		return fmt.Errorf("%w: %v", errFailedToStartSRTCP, err)
	}

	t.srtpSession.Store(srtpSession)
	t.srtcpSession.Store(srtcpSession)
	close(t.srtpReady)

	t.irisClient().SetCallback(iris.NewGoCallback(
		receiveAudio(t),
		receiveVideo(t),
		receiveRTCP(t),
	))

	return nil
}

func (t *SharedTransport) getSRTPSession() (*srtp.SessionSRTP, error) {
	if value, ok := t.srtpSession.Load().(*srtp.SessionSRTP); ok {
		return value, nil
	}

	return nil, errDtlsTransportNotStarted
}

func (t *SharedTransport) getSRTCPSession() (*srtp.SessionSRTCP, error) {
	if value, ok := t.srtcpSession.Load().(*srtp.SessionSRTCP); ok {
		return value, nil
	}

	return nil, errDtlsTransportNotStarted
}

func (t *SharedTransport) dtlsRole() DTLSRole {
	return DTLSRoleAuto
}

// Start Shared
func (t *SharedTransport) Start(_ SecurityParameters) error {
	t.lock.Lock()
	defer t.lock.Unlock()

	if err := t.ensureICEConn(); err != nil {
		return err
	}

	t.onStateChange(SecurityTransportStateConnecting)
	t.srtpEndpoint = t.iceTransport.newEndpoint(mux.MatchSRTP)
	t.srtcpEndpoint = t.iceTransport.newEndpoint(mux.MatchSRTCP)
	t.onStateChange(SecurityTransportStateConnected)

	return t.startSRTP()
}

// Stop stops and closes the SharedTransport object.
func (t *SharedTransport) Stop() error {
	t.lock.Lock()
	defer t.lock.Unlock()

	// Try closing everything and collect the errors
	var closeErrs []error

	if srtpSession, err := t.getSRTPSession(); err == nil && srtpSession != nil {
		closeErrs = append(closeErrs, srtpSession.Close())
	}

	if srtcpSession, err := t.getSRTCPSession(); err == nil && srtcpSession != nil {
		closeErrs = append(closeErrs, srtcpSession.Close())
	}

	for i := range t.simulcastStreams {
		closeErrs = append(closeErrs, t.simulcastStreams[i].Close())
	}

	t.onStateChange(SecurityTransportStateClosed)
	return util.FlattenErrs(closeErrs)
}

func (t *SharedTransport) ensureICEConn() error {
	if t.iceTransport == nil {
		return errICEConnectionNotStarted
	}

	return nil
}

func (t *SharedTransport) storeSimulcastStream(s *srtp.ReadStreamSRTP) {
	t.lock.Lock()
	defer t.lock.Unlock()

	t.simulcastStreams = append(t.simulcastStreams, s)
}

func (t *SharedTransport) streamsForSSRC(ssrc SSRC, streamInfo interceptor.StreamInfo) (*srtp.ReadStreamSRTP, interceptor.RTPReader, *srtp.ReadStreamSRTCP, interceptor.RTCPReader, error) {
	srtpSession, err := t.getSRTPSession()
	if err != nil {
		return nil, nil, nil, nil, err
	}

	rtpReadStream, err := srtpSession.OpenReadStream(uint32(ssrc))
	if err != nil {
		return nil, nil, nil, nil, err
	}

	rtpInterceptor := t.api.interceptor.BindRemoteStream(&streamInfo, interceptor.RTPReaderFunc(func(in []byte, a interceptor.Attributes) (n int, attributes interceptor.Attributes, err error) {
		n, err = rtpReadStream.Read(in)
		return n, a, err
	}))

	srtcpSession, err := t.getSRTCPSession()
	if err != nil {
		return nil, nil, nil, nil, err
	}

	rtcpReadStream, err := srtcpSession.OpenReadStream(uint32(ssrc))
	if err != nil {
		return nil, nil, nil, nil, err
	}

	rtcpInterceptor := t.api.interceptor.BindRTCPReader(interceptor.RTPReaderFunc(func(in []byte, a interceptor.Attributes) (n int, attributes interceptor.Attributes, err error) {
		n, err = rtcpReadStream.Read(in)
		return n, a, err
	}))

	return rtpReadStream, rtpInterceptor, rtcpReadStream, rtcpInterceptor, nil
}

func (t *SharedTransport) SRTPReady() <-chan struct{} {
	return t.srtpReady

}

func (t *SharedTransport) UpdateKeys(exporter srtp.KeyingMaterialExporter) error {
	t.srtpConfig = &srtp.Config{Profile: t.srtpProtectionProfile}

	if err := t.srtpConfig.ExtractSessionKeysFromShared(exporter); err != nil {
		return err
	}

	if err := t.updateSessions(); err != nil && err != errDtlsTransportNotStarted {
		return err
	}

	return nil
}

func (t *SharedTransport) updateSessions() error {
	srtpSession, err := t.getSRTPSession()
	if err != nil {
		return err
	}

	srtcpSession, err := t.getSRTCPSession()
	if err != nil {
		return err
	}

	err = srtpSession.UpdateKeys(t.srtpConfig.Keys, t.srtpProtectionProfile)
	if err != nil {
		return err
	}

	err = srtcpSession.UpdateKeys(t.srtpConfig.Keys, t.srtpProtectionProfile)
	if err != nil {
		return err
	}

	return nil
}

func (t *SharedTransport) irisClient() iris.IrisClient {
	return t.irisTransport
}
