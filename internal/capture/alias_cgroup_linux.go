package capture

import (
	"encoding/binary"
	"errors"
	"os"
	"path"
	"slices"
	"strconv"
	"strings"

	"golang.org/x/sys/unix"
)

// nft JSON renders a live cgroup ID as a pathname, then as a decimal string
// once the scope disappears. Even nft --numeric keeps that name translation.
// Canonicalize only cgroupv2 matches, retaining every other rule field in the
// digest. Cache IDs solely for the race where the path disappears after nft's
// snapshot. A still-existing path is always re-read to detect replacement.
func (a *aliasRoute) canonicalCgroupMatches(value any) (any, error) {
	switch v := value.(type) {
	case []any:
		out := make([]any, len(v))
		for i, item := range v {
			var err error
			out[i], err = a.canonicalCgroupMatches(item)
			if err != nil {
				return nil, err
			}
		}
		return out, nil
	case map[string]any:
		out := make(map[string]any, len(v))
		for key, item := range v {
			var err error
			out[key], err = a.canonicalCgroupMatches(item)
			if err != nil {
				return nil, err
			}
		}
		left, _ := out["left"].(map[string]any)
		socket, _ := left["socket"].(map[string]any)
		if socket["key"] != "cgroupv2" {
			return out, nil
		}
		right, ok := out["right"].(string)
		if !ok {
			return nil, errors.New("capture: unsupported cgroup rule identity")
		}
		if id, err := strconv.ParseUint(right, 10, 64); err == nil && id != 0 {
			out["right"] = strconv.FormatUint(id, 10)
			return out, nil
		}
		if path.IsAbs(right) || path.Clean(right) != right || strings.HasPrefix(right, "../") || !slices.Contains(a.Groups, right) {
			return nil, errors.New("capture: unexpected cgroup rule path")
		}
		handle, _, err := unix.NameToHandleAt(unix.AT_FDCWD, "/sys/fs/cgroup/"+right, 0)
		id := a.groupIDs[right]
		if err == nil {
			if len(handle.Bytes()) != 8 {
				return nil, errors.New("capture: unsupported cgroup handle")
			}
			id = strconv.FormatUint(binary.NativeEndian.Uint64(handle.Bytes()), 10)
			if a.groupIDs == nil {
				a.groupIDs = make(map[string]string)
			}
			a.groupIDs[right] = id
		} else if !os.IsNotExist(err) || id == "" {
			return nil, err
		}
		out["right"] = id
		return out, nil
	default:
		return value, nil
	}
}
