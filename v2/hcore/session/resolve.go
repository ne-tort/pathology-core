package session

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
)

const (
	mergedConfigName = "_active_merge"
	directConfigName = "_direct"
)

// ResolveStartTarget picks config path/name from session state and working dir.
func ResolveStartTarget(st State, workingDir string) (StartTarget, error) {
	if st.StartTarget != nil && st.StartTarget.Path != "" {
		if _, err := os.Stat(st.StartTarget.Path); err == nil {
			// Honor the cached target only while the session itself is still
			// connectable: direct mode on, or at least one active profile.
			// Otherwise a stale cache (e.g. _direct.json from a past «No VPN»
			// session, or a profile the user has since disabled) would let the
			// QS tile / shortcut connect something the UI would refuse to.
			if st.DirectMode || len(st.ActiveProfileIDs) > 0 {
				return *st.StartTarget, nil
			}
		}
	}
	configs := filepath.Join(workingDir, "configs")
	if st.DirectMode {
		p := filepath.Join(configs, directConfigName+".json")
		if _, err := os.Stat(p); err != nil {
			return StartTarget{}, fmt.Errorf("direct config missing: open UI once to prepare Direct mode")
		}
		return StartTarget{Path: p, Name: "Direct"}, nil
	}
	if len(st.ActiveProfileIDs) == 0 {
		return StartTarget{}, errors.New("no active profile — open UI and select a profile")
	}
	if len(st.ActiveProfileIDs) == 1 {
		p := filepath.Join(configs, st.ActiveProfileIDs[0]+".json")
		if _, err := os.Stat(p); err != nil {
			return StartTarget{}, fmt.Errorf("profile config missing: %s", st.ActiveProfileIDs[0])
		}
		name := st.ActiveProfileIDs[0]
		for _, prof := range st.Profiles {
			if prof.ID == st.ActiveProfileIDs[0] && prof.Name != "" {
				name = prof.Name
				break
			}
		}
		return StartTarget{Path: p, Name: name}, nil
	}
	p := filepath.Join(configs, mergedConfigName+".json")
	if _, err := os.Stat(p); err != nil {
		return StartTarget{}, fmt.Errorf("multi-profile merge missing: connect once from UI or reduce to one profile")
	}
	name := "Merged"
	if len(st.Profiles) > 0 {
		name = st.Profiles[0].Name
		if len(st.Profiles) > 1 {
			name += " +" + fmt.Sprint(len(st.Profiles)-1)
		}
	}
	return StartTarget{Path: p, Name: name}, nil
}
