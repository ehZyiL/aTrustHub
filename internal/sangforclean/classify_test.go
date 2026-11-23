package sangforclean

import (
	"testing"
)

func TestClassifyDosDevice(t *testing.T) {
	tests := []struct {
		name     string
		letter   string
		target   string
		expected string
	}{
		{
			name:     "Invalid letter (AUX)",
			letter:   "AUX",
			target:   `C:\some\path`,
			expected: "kept",
		},
		{
			name:     "Invalid letter (COM1)",
			letter:   "COM1",
			target:   `C:\some\path`,
			expected: "kept",
		},
		{
			name:     "Raw device prefix",
			letter:   "Z:",
			target:   `\Device\HarddiskVolume1`,
			expected: "manual",
		},
		{
			name:     "Sangfor target suspicious",
			letter:   "X:",
			target:   `C:\Program Files (x86)\Sangfor\aTrust\Workspace`,
			expected: "suspicious",
		},
		{
			name:     "Valid user virtual drive kept",
			letter:   "Y:",
			target:   `D:\MyProjects\Work`,
			expected: "kept",
		},
		{
			name:     "Non-existent or broken non-sangfor drive kept (anti-misclassification)",
			letter:   "W:",
			target:   `E:\DeletedFolder`,
			expected: "kept",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			res := ClassifyDosDevice(tt.letter, tt.target)
			if res != tt.expected {
				t.Errorf("ClassifyDosDevice(%q, %q) = %q, want %q", tt.letter, tt.target, res, tt.expected)
			}
		})
	}
}

func TestClassifyInstalledApp(t *testing.T) {
	tests := []struct {
		name            string
		keyName         string
		displayName     string
		publisher       string
		uninstallString string
		wantMatch       bool
		wantName        string
	}{
		{
			name:            "Standard EasyConnect",
			keyName:         "EasyConnect",
			displayName:     "EasyConnect",
			publisher:       "Sangfor Technologies Inc.",
			uninstallString: `C:\Program Files (x86)\Sangfor\SSL\EasyConnect\Uninstall.exe`,
			wantMatch:       true,
			wantName:        "EasyConnect",
		},
		{
			name:            "Tenant branded DisplayName with Sangfor publisher",
			keyName:         "EasyConnect",
			displayName:     "中原招标采购交易平台",
			publisher:       "Sangfor Technologies Inc.",
			uninstallString: `C:\Program Files (x86)\Sangfor\SSL\EasyConnect\Uninstall.exe`,
			wantMatch:       true,
			wantName:        "中原招标采购交易平台",
		},
		{
			name:            "SangforVNC virtual nic product",
			keyName:         "SangforVNC",
			displayName:     "SangforVNC",
			publisher:       "Sangfor",
			uninstallString: `C:\Program Files (x86)\Sangfor\SSL\CSClient\VNIC\uninstall.exe`,
			wantMatch:       true,
			wantName:        "SangforVNC",
		},
		{
			name:            "aTrust client",
			keyName:         "aTrust",
			displayName:     "aTrust",
			publisher:       "Sangfor",
			uninstallString: `C:\Program Files (x86)\Sangfor\aTrust\uninst.exe`,
			wantMatch:       true,
			wantName:        "aTrust",
		},
		{
			name:            "Unrelated software (7-Zip)",
			keyName:         "7-Zip",
			displayName:     "7-Zip 23.01",
			publisher:       "Igor Pavlov",
			uninstallString: `C:\Program Files\7-Zip\Uninstall.exe`,
			wantMatch:       false,
			wantName:        "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			match, gotName := ClassifyInstalledApp(tt.keyName, tt.displayName, tt.publisher, tt.uninstallString)
			if match != tt.wantMatch {
				t.Fatalf("match = %v, want %v", match, tt.wantMatch)
			}
			if match && gotName != tt.wantName {
				t.Errorf("gotName = %q, want %q", gotName, tt.wantName)
			}
		})
	}
}

func TestClassifyBrowserPolicyValue(t *testing.T) {
	if !ClassifyBrowserPolicyValue("SangforHelper", "https://sangfor.com/update") {
		t.Errorf("Expected true for Sangfor policy value")
	}
	if ClassifyBrowserPolicyValue("StandardPolicy", "https://google.com") {
		t.Errorf("Expected false for non-Sangfor policy value")
	}
}

func TestClassifyWinsockEntry(t *testing.T) {
	if !ClassifyWinsockEntry(`C:\Program Files (x86)\Sangfor\SSL\ClientComponent\1_SangforNsp.dll`) {
		t.Errorf("Expected true for Sangfor NSP dll")
	}
	if !ClassifyWinsockEntry("SangforLSP_def over [MSAFD Tcpip [TCP/IP]]") {
		t.Errorf("Expected true for Sangfor LSP protocol name")
	}
	if ClassifyWinsockEntry(`C:\Windows\System32\mswsock.dll`) {
		t.Errorf("Expected false for standard system mswsock")
	}
}
