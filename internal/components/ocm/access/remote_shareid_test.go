package access

import "testing"

func TestRelativeWebDAVShareID(t *testing.T) {
	tests := []struct {
		name     string
		webdavID string
		want     string
	}{
		{name: "relative id", webdavID: "share-id-789", want: "share-id-789"},
		{
			name:     "absolute uri",
			webdavID: "https://peer.example.com/webdav/ocm/share-id-789",
			want:     "share-id-789",
		},
		{name: "empty", webdavID: "", want: ""},
		{name: "parse error", webdavID: "%zz", want: "%zz"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := relativeWebDAVShareID(tt.webdavID); got != tt.want {
				t.Errorf("relativeWebDAVShareID(%q) = %q, want %q", tt.webdavID, got, tt.want)
			}
		})
	}
}
