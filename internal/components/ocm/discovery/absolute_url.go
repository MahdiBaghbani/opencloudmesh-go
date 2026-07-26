package discovery

import "net/url"

func isAbsoluteURL(raw string) bool {
	u, err := url.Parse(raw)
	if err != nil || u == nil {
		return false
	}

	return u.Scheme != "" && u.Host != ""
}
