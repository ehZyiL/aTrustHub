package model

import "testing"

func TestLocalAppRejectsProxyOverridesAndCredentials(t *testing.T) {
	base := LocalApp{ID: "app", Name: "browser", PointID: "point", Mode: LocalAppBrowser}
	base.Normalize()
	if err := base.Validate(); err != nil {
		t.Fatal(err)
	}
	for _, p := range []LocalApp{
		{ID: "app", Name: "browser", PointID: "point", Mode: LocalAppBrowser, URL: "https://user:password@portal.internal/"},
		{ID: "app", Name: "browser", PointID: "point", Mode: LocalAppBrowser, Args: []string{"--no-proxy-server"}},
		{ID: "app", Name: "browser", PointID: "point", Mode: LocalAppBrowser, URL: "file:///tmp/local"},
		{ID: "app", Name: "db", PointID: "point", Mode: LocalAppTCPForward, RemoteAddress: "db.internal:0"},
		{ID: "app", Name: "db", PointID: "point", Mode: LocalAppTCPForward, RemoteAddress: "db.internal:5432", ListenPort: 65536},
	} {
		if err := p.Validate(); err == nil {
			t.Errorf("invalid profile accepted: mode=%s", p.Mode)
		}
	}
}

func TestConfigCloneSeparatesLocalAppsAndPointSlices(t *testing.T) {
	monitor := true
	base := Config{Points: []AccessPoint{{ID: "point", InternalDomains: []string{"internal"}, Monitor: &monitor}}, LocalApps: []LocalApp{{ID: "app", Args: []string{"value"}}}}
	copy := base.Clone()
	copy.LocalApps[0].Name = "changed"
	copy.LocalApps[0].Args[0] = "changed"
	copy.Points[0].InternalDomains[0] = "changed"
	*copy.Points[0].Monitor = false
	if base.LocalApps[0].Name != "" || base.LocalApps[0].Args[0] != "value" || base.Points[0].InternalDomains[0] != "internal" || !*base.Points[0].Monitor {
		t.Fatal("clone shares mutable storage")
	}
}
