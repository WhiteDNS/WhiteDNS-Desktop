package security

import (
	"slices"
	"testing"
)

func TestAutoDetectMethodsDoesNotDowngradeEncryptedServerToNone(t *testing.T) {
	for _, configured := range []int{1, 2, 3, 4, 5} {
		methods := AutoDetectMethods(configured)
		if slices.Contains(methods, 0) {
			t.Fatalf("configured method %d unexpectedly enabled method 0: %v", configured, methods)
		}
		if !slices.Contains(methods, configured) {
			t.Fatalf("configured method %d missing from compatibility set: %v", configured, methods)
		}
	}
	if methods := AutoDetectMethods(0); !slices.Contains(methods, 0) {
		t.Fatalf("explicit method 0 configuration must remain compatible: %v", methods)
	}
}
