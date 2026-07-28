package service

import "testing"

func TestDescriptors_MountMetadataOnly(t *testing.T) {
	assertDescriptorsMatchCoreServicesMetadata(t)
}
