package webrtc

// SecurityParameters holds information relating to security configuration.
type SecurityParameters struct {
	DTLSRole         DTLSRole          `json:"dtlsRole"`
	DTLSFingerprints []DTLSFingerprint `json:"dtlsFingerprints"`
}
