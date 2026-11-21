package windivert

import (
	"errors"
	"fmt"
	"strings"
	"syscall"
	"testing"
)

func TestOpenErrorPreservesCodesAndExplainsFailure(t *testing.T) {
	for _, code := range []uint32{1058, 1072, 5, 2, 3, 126, 577, 1275, 1753, 1068, 87, 1234} {
		t.Run(fmt.Sprint(code), func(t *testing.T) {
			cause := syscall.Errno(code)
			err := newOpenError(fmt.Errorf("wrapped: %w", cause))
			var open *OpenError
			if !errors.Is(err, cause) || !errors.As(err, &open) || open.Code != code {
				t.Fatal("lost OS error", err)
			}
			if !strings.Contains(err.Error(), fmt.Sprint(code)) || !strings.Contains(err.Error(), "WinDivert") {
				t.Fatal(err)
			}
			if strings.Contains(err.Error(), "wrapped:") {
				t.Fatal("untranslated text escaped")
			}
		})
	}
}
func TestOpenErrorDoesNotExposeUnknownPaths(t *testing.T) {
	cause := errors.New("PRIVATE_PATH")
	err := newOpenError(cause)
	if strings.Contains(err.Error(), "PRIVATE_PATH") || !errors.Is(err, cause) {
		t.Fatal(err)
	}
}
