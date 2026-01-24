package interceptors

import "fmt"

// GetProfileConfig looks up a named profile from an interceptor's config.
// The interceptorsCfg is typically deps.GetDeps().Config.HTTP.Interceptors.
// Returns the profile config map or an error if not found.
func GetProfileConfig(interceptorsCfg map[string]map[string]any, interceptorName, profileName string) (map[string]any, error) {
	if interceptorsCfg == nil {
		return nil, fmt.Errorf("no interceptors configured, cannot find %s profile %q", interceptorName, profileName)
	}
	interceptorCfg, ok := interceptorsCfg[interceptorName]
	if !ok {
		return nil, fmt.Errorf("no %s interceptor configured, cannot find profile %q", interceptorName, profileName)
	}
	profilesRaw, ok := interceptorCfg["profiles"]
	if !ok {
		return nil, fmt.Errorf("no %s profiles configured, cannot find profile %q", interceptorName, profileName)
	}
	profiles, ok := profilesRaw.(map[string]any)
	if !ok {
		return nil, fmt.Errorf("%s profiles is not a map, cannot find profile %q", interceptorName, profileName)
	}
	profileRaw, ok := profiles[profileName]
	if !ok {
		return nil, fmt.Errorf("%s profile %q not found", interceptorName, profileName)
	}
	profileConfig, ok := profileRaw.(map[string]any)
	if !ok {
		return nil, fmt.Errorf("%s profile %q is not a map", interceptorName, profileName)
	}
	return profileConfig, nil
}
