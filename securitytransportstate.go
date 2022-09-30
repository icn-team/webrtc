package webrtc

// SecurityTransportState indicates the Security transport establishment state.
type SecurityTransportState int

const (
	// SecurityTransportStateNew indicates that Security has not started negotiating
	// yet.
	SecurityTransportStateNew SecurityTransportState = iota + 1

	// SecurityTransportStateConnecting indicates that Security is in the process of
	// negotiating a secure connection and verifying the remote fingerprint.
	SecurityTransportStateConnecting

	// SecurityTransportStateConnected indicates that Security has completed
	// negotiation of a secure connection and verified the remote fingerprint.
	SecurityTransportStateConnected

	// SecurityTransportStateClosed indicates that the transport has been closed
	// intentionally as the result of receipt of a close_notify alert, or
	// calling close().
	SecurityTransportStateClosed

	// SecurityTransportStateFailed indicates that the transport has failed as
	// the result of an error (such as receipt of an error alert or failure to
	// validate the remote fingerprint).
	SecurityTransportStateFailed
)

// This is done this way because of a linter.
const (
	securityTransportStateNewStr        = "new"
	securityTransportStateConnectingStr = "connecting"
	securityTransportStateConnectedStr  = "connected"
	securityTransportStateClosedStr     = "closed"
	securityTransportStateFailedStr     = "failed"
)

func newSecurityTransportState(raw string) SecurityTransportState {
	switch raw {
	case securityTransportStateNewStr:
		return SecurityTransportStateNew
	case securityTransportStateConnectingStr:
		return SecurityTransportStateConnecting
	case securityTransportStateConnectedStr:
		return SecurityTransportStateConnected
	case securityTransportStateClosedStr:
		return SecurityTransportStateClosed
	case securityTransportStateFailedStr:
		return SecurityTransportStateFailed
	default:
		return SecurityTransportState(Unknown)
	}
}

func (t SecurityTransportState) String() string {
	switch t {
	case SecurityTransportStateNew:
		return securityTransportStateNewStr
	case SecurityTransportStateConnecting:
		return securityTransportStateConnectingStr
	case SecurityTransportStateConnected:
		return securityTransportStateConnectedStr
	case SecurityTransportStateClosed:
		return securityTransportStateClosedStr
	case SecurityTransportStateFailed:
		return securityTransportStateFailedStr
	default:
		return ErrUnknownType.Error()
	}
}
