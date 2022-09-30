package webrtc

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestNewSecurityTransportState(t *testing.T) {
	testCases := []struct {
		stateString   string
		expectedState SecurityTransportState
	}{
		{unknownStr, SecurityTransportState(Unknown)},
		{"new", SecurityTransportStateNew},
		{"connecting", SecurityTransportStateConnecting},
		{"connected", SecurityTransportStateConnected},
		{"closed", SecurityTransportStateClosed},
		{"failed", SecurityTransportStateFailed},
	}

	for i, testCase := range testCases {
		assert.Equal(t,
			testCase.expectedState,
			newSecurityTransportState(testCase.stateString),
			"testCase: %d %v", i, testCase,
		)
	}
}

func TestSecurityTransportState_String(t *testing.T) {
	testCases := []struct {
		state          SecurityTransportState
		expectedString string
	}{
		{SecurityTransportState(Unknown), unknownStr},
		{SecurityTransportStateNew, "new"},
		{SecurityTransportStateConnecting, "connecting"},
		{SecurityTransportStateConnected, "connected"},
		{SecurityTransportStateClosed, "closed"},
		{SecurityTransportStateFailed, "failed"},
	}

	for i, testCase := range testCases {
		assert.Equal(t,
			testCase.expectedString,
			testCase.state.String(),
			"testCase: %d %v", i, testCase,
		)
	}
}
