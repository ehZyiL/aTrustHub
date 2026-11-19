package capture

import (
	"errors"
	"fmt"
	"net"
	"os"
	"strconv"
	"strings"
	"syscall"

	"golang.org/x/sys/unix"
)

type processIdentity struct {
	UID       int
	StartTime uint64
	Group     string
}

func identifyProcess(pid int) (processIdentity, error) {
	var result processIdentity
	if pid <= 0 {
		return result, errors.New("capture: invalid process")
	}
	path := fmt.Sprintf("/proc/%d", pid)
	s, err := os.Stat(path)
	if err != nil {
		return result, err
	}
	stat, ok := s.Sys().(*syscall.Stat_t)
	if !ok {
		return result, errors.New("capture: cannot inspect process owner")
	}
	result.UID = int(stat.Uid)
	status, err := os.ReadFile(path + "/status")
	if err != nil {
		return result, err
	}
	for _, line := range strings.Split(string(status), "\n") {
		if strings.HasPrefix(line, "Uid:") {
			ids := strings.Fields(strings.TrimPrefix(line, "Uid:"))
			if len(ids) != 4 {
				return result, errors.New("capture: incomplete process credentials")
			}
			for _, id := range ids {
				n, err := strconv.Atoi(id)
				if err != nil || n != result.UID {
					return result, errors.New("capture: mixed process credentials are not supported")
				}
			}
		}
	}
	b, err := os.ReadFile(path + "/stat")
	if err != nil {
		return result, err
	}
	// comm can contain spaces and closing parentheses. All remaining fields
	// follow the last ')'; starttime is field 22, state is field 3.
	end := strings.LastIndexByte(string(b), ')')
	if end < 0 {
		return result, errors.New("capture: invalid process metadata")
	}
	fields := strings.Fields(string(b[end+1:]))
	if len(fields) < 20 {
		return result, errors.New("capture: incomplete process metadata")
	}
	result.StartTime, err = strconv.ParseUint(fields[19], 10, 64)
	if err != nil {
		return result, err
	}
	b, err = os.ReadFile(path + "/cgroup")
	if err != nil {
		return result, err
	}
	for _, line := range strings.Split(string(b), "\n") {
		if strings.HasPrefix(line, "0::/") {
			result.Group = strings.TrimPrefix(line, "0::/")
			break
		}
	}
	if result.Group == "" {
		return result, errors.New("capture: cgroup v2 is required")
	}
	return result, nil
}

func validateProcess(uid int, req attachRequest) (processIdentity, error) {
	p, err := identifyProcess(req.PID)
	if err != nil {
		return p, err
	}
	if p.UID != uid || p.StartTime != req.StartTime || !validScope(uid, req.ID, p.Group) {
		return p, errors.New("capture: process owner, start time or launch scope does not match")
	}
	self, err := os.Readlink("/proc/self/ns/net")
	if err != nil {
		return p, err
	}
	ns, err := os.Readlink(fmt.Sprintf("/proc/%d/ns/net", req.PID))
	if err != nil || ns != self {
		return p, errors.New("capture: process uses a different network namespace")
	}
	return p, nil
}

func groupPopulated(group string) (bool, error) {
	b, err := os.ReadFile("/sys/fs/cgroup/" + group + "/cgroup.events")
	if os.IsNotExist(err) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	for _, line := range strings.Split(string(b), "\n") {
		if line == "populated 1" {
			return true, nil
		}
		if line == "populated 0" {
			return false, nil
		}
	}
	return false, errors.New("capture: missing cgroup population state")
}

func peerCredentials(c *net.UnixConn) (*unix.Ucred, error) {
	raw, err := c.SyscallConn()
	if err != nil {
		return nil, err
	}
	var cred *unix.Ucred
	var sockErr error
	err = raw.Control(func(fd uintptr) { cred, sockErr = unix.GetsockoptUcred(int(fd), unix.SOL_SOCKET, unix.SO_PEERCRED) })
	if err != nil {
		return nil, err
	}
	return cred, sockErr
}
