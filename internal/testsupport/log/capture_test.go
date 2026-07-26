package log_test

import (
	"testing"

	"github.com/MahdiBaghbani/opencloudmesh-go/internal/testsupport/log"
)

func TestLogCapture_Contains(t *testing.T) {
	logger, capture := log.NewLogCapture(t)
	logger.Warn("unused config keys detected")

	if !capture.Contains("unused config keys") {
		t.Error("Contains: expected true for present substring")
	}

	if capture.Contains("absent substring") {
		t.Error("Contains: expected false for absent substring")
	}
}

func TestLogCapture_WarnJSONContainsMessage(t *testing.T) {
	logger, capture := log.NewLogCapture(t)
	logger.Warn("json contract probe")

	if !capture.Contains(`"msg":"json contract probe"`) {
		t.Error("expected JSON handler output with msg field for logged warning")
	}
}

func TestLogCapture_FiltersInfoAndDebug(t *testing.T) {
	logger, capture := log.NewLogCapture(t)
	logger.Info("info should not appear")
	logger.Debug("debug should not appear")

	if capture.Contains("info should not appear") {
		t.Error("Contains: expected false for Info message filtered by warn level")
	}

	if capture.Contains("debug should not appear") {
		t.Error("Contains: expected false for Debug message filtered by warn level")
	}
}
