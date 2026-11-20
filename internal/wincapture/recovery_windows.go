package wincapture

import (
	"context"
	"encoding/json"
	"errors"
	"os"

	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/registry"
)

const recoveryRoot = `SOFTWARE\EasyConnectHub\CaptureRecovery`

func journalDNS(id string, state dnsRecovery) error {
	if err := state.validate(); err != nil {
		return err
	}
	if err := journalSession(id); err != nil {
		return err
	}
	data, err := json.Marshal(state)
	if err != nil {
		return err
	}
	key, err := registry.OpenKey(registry.LOCAL_MACHINE, recoveryRoot+`\`+id, registry.SET_VALUE|registry.WOW64_64KEY)
	if err != nil {
		return err
	}
	defer key.Close()
	return key.SetStringValue("DNSState", string(data))
}

func readJournalDNS(id string) (*dnsRecovery, error) {
	if !validID(id) {
		return nil, errors.New("DNS 恢复标识无效")
	}
	key, err := registry.OpenKey(registry.LOCAL_MACHINE, recoveryRoot+`\`+id, registry.QUERY_VALUE|registry.WOW64_64KEY)
	if errors.Is(err, windows.ERROR_FILE_NOT_FOUND) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	defer key.Close()
	data, _, err := key.GetStringValue("DNSState")
	if errors.Is(err, windows.ERROR_FILE_NOT_FOUND) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var state dnsRecovery
	if len(data) > maxFrame || json.Unmarshal([]byte(data), &state) != nil {
		return nil, errors.New("DNS 恢复记录损坏，保留当前策略")
	}
	if err := state.validate(); err != nil {
		return nil, err
	}
	return &state, nil
}

// Journal the helper identity; journalDNS adds the exact before/after DNS
// values for compare-and-remove recovery. No upstream credentials are stored.
// HKLM is writable by the elevated helper, not ordinary desktop applications.
// A journal entry exists before NRPT changes; after a reboot, the next helper
// can remove exactly those orphaned rules without touching another VPN's DNS.
func journalSession(id string) error {
	if !validID(id) {
		return errors.New("恢复标识无效")
	}
	identity, err := processIdentity(windows.CurrentProcess(), uint32(os.Getpid()))
	if err != nil {
		return err
	}
	key, _, err := registry.CreateKey(registry.LOCAL_MACHINE, recoveryRoot+`\`+id, registry.SET_VALUE|registry.WOW64_64KEY)
	if err != nil {
		return err
	}
	defer key.Close()
	if err = key.SetQWordValue("Created", identity.Created); err != nil {
		return err
	}
	return key.SetDWordValue("PID", identity.PID)
}

func clearJournal(id string) error {
	if !validID(id) {
		return errors.New("恢复标识无效")
	}
	root, err := registry.OpenKey(registry.LOCAL_MACHINE, recoveryRoot, registry.ALL_ACCESS|registry.WOW64_64KEY)
	if errors.Is(err, windows.ERROR_FILE_NOT_FOUND) {
		return nil
	}
	if err != nil {
		return err
	}
	defer root.Close()
	err = registry.DeleteKey(root, id)
	if errors.Is(err, windows.ERROR_FILE_NOT_FOUND) {
		return nil
	}
	return err
}

func RecoverOrphanedDNS(ctx context.Context) error {
	root, err := registry.OpenKey(registry.LOCAL_MACHINE, recoveryRoot, registry.ENUMERATE_SUB_KEYS|registry.QUERY_VALUE|registry.WOW64_64KEY)
	if errors.Is(err, windows.ERROR_FILE_NOT_FOUND) {
		return nil
	}
	if err != nil {
		return err
	}
	defer root.Close()
	ids, err := root.ReadSubKeyNames(-1)
	if err != nil {
		return err
	}
	if len(ids) > 256 {
		return errors.New("网络恢复记录过多，请先检查旧会话")
	}
	for _, id := range ids {
		if !validID(id) {
			continue
		}
		if err := ctx.Err(); err != nil {
			return err
		}
		key, err := registry.OpenKey(root, id, registry.QUERY_VALUE)
		if err != nil {
			return err
		}
		pid, _, pidErr := key.GetIntegerValue("PID")
		created, _, createdErr := key.GetIntegerValue("Created")
		key.Close()
		// Incomplete records precede any DNS writes, but their random session
		// tag can still be removed safely and idempotently.
		if pidErr == nil && createdErr == nil && pid > 0 && pid <= 0xffffffff {
			h, err := windows.OpenProcess(windows.SYNCHRONIZE|windows.PROCESS_QUERY_LIMITED_INFORMATION, false, uint32(pid))
			if err == nil {
				identity, idErr := processIdentity(h, uint32(pid))
				state, waitErr := windows.WaitForSingleObject(h, 0)
				windows.CloseHandle(h)
				if idErr != nil || waitErr != nil {
					return errors.Join(idErr, waitErr)
				}
				if identity.Created == created && state == uint32(windows.WAIT_TIMEOUT) {
					continue
				}
			} else if !errors.Is(err, windows.ERROR_INVALID_PARAMETER) {
				return err
			}
		}
		if err := removeNRPT(ctx, id); err != nil {
			return err
		}
		if err := clearJournal(id); err != nil {
			return err
		}
	}
	return nil
}
