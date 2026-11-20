package capture

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"strconv"
)

type systemRoutes struct {
	routingAllocation
	ID     string
	Source netip.Addr
}

func (r systemRoutes) device() string { return "echt" + r.ID[:10] }

func (r systemRoutes) validate() error {
	if !sessionPattern.MatchString(r.ID) || !r.routingAllocation.valid() ||
		!netip.MustParsePrefix("198.18.0.0/16").Contains(r.Source) {
		return errors.New("capture: invalid system routing lease")
	}
	return nil
}

func linuxRoutePrefix(row map[string]any) (netip.Prefix, bool) {
	raw, _ := row["dst"].(string)
	if prefix, err := netip.ParsePrefix(raw); err == nil && prefix.Addr().Is4() {
		return prefix.Masked(), true
	}
	if addr, err := netip.ParseAddr(raw); err == nil && addr.Is4() {
		return netip.PrefixFrom(addr, 32), true
	}
	if raw == "default" {
		return netip.PrefixFrom(netip.IPv4Unspecified(), 0), true
	}
	return netip.Prefix{}, false
}

func (r systemRoutes) table() string { return strconv.FormatUint(uint64(r.Table), 10) }
func (r systemRoutes) mark() string  { return fmt.Sprintf("0x0/0x%x", r.Mark) }

func (r systemRoutes) ruleArgs(action string) []string {
	// Linux uses iif lo for locally originated traffic. The mark bit is zero
	// on normal sockets and set on the helper's original egress sockets.
	return []string{"-4", "rule", action, "pref", strconv.Itoa(r.Pref), "iif", "lo", "fwmark", r.mark(), "lookup", r.table(), "protocol", routeProtocol}
}

func (r systemRoutes) ownsRule(row map[string]any) bool {
	for key := range row {
		switch key {
		case "priority", "iif", "src", "fwmark", "fwmask", "table", "protocol":
		default:
			return false
		}
	}
	pref, _ := number(row["priority"])
	mark, hasMark := number(row["fwmark"])
	mask, _ := number(row["fwmask"])
	table, _ := number(row["table"])
	proto, _ := number(row["protocol"])
	return row["iif"] == "lo" && row["src"] == "all" && pref == uint32(r.Pref) && table == r.Table &&
		hasMark && mark == 0 && mask == r.Mark && proto == 242
}

func (r systemRoutes) addRule(ctx context.Context, run commandFunc) error {
	if err := r.validate(); err != nil {
		return err
	}
	_, err := run(ctx, "ip", "", r.ruleArgs("add")...)
	return err
}

func (r systemRoutes) removeRule(ctx context.Context, run commandFunc) error {
	if err := r.validate(); err != nil {
		return err
	}
	raw, err := run(ctx, "ip", "", "-j", "-N", "-4", "rule", "show")
	if err != nil {
		return err
	}
	var rows []map[string]any
	if err := decodeJSON(raw, &rows); err != nil {
		return err
	}
	var matches int
	for _, row := range rows {
		if r.ownsRule(row) {
			matches++
		}
	}
	if matches == 0 {
		return nil
	}
	if matches != 1 {
		return errors.New("capture: system routing rule is ambiguous")
	}
	_, err = run(ctx, "ip", "", r.ruleArgs("del")...)
	return err
}

func (r systemRoutes) changeRoute(ctx context.Context, run commandFunc, action string, prefix netip.Prefix) error {
	if !prefix.IsValid() || !prefix.Addr().Is4() || prefix.Bits() < 12 {
		return errors.New("capture: invalid system resource route")
	}
	_, err := run(ctx, "ip", "", "-4", "route", action, prefix.String(), "dev", r.device(), "src", r.Source.String(), "table", r.table(), "proto", routeProtocol)
	return err
}

func (r systemRoutes) ownsRoute(row map[string]any) bool {
	table, _ := number(row["table"])
	proto, _ := number(row["protocol"])
	return table == r.Table && proto == 242 && row["dev"] == r.device() && row["prefsrc"] == r.Source.String()
}

func (r systemRoutes) verify(state kernelState, expected map[netip.Prefix]bool) error {
	found := false
	for _, rule := range state.rules {
		priority, _ := number(rule["priority"])
		if r.ownsRule(rule) && !found {
			found = true
		} else if priority > 0 && priority <= uint32(r.Pref) {
			return errors.New("capture: system routing priority changed")
		} else if priority == 0 {
			table, _ := number(rule["table"])
			if table != 255 && rule["table"] != "local" {
				return errors.New("capture: system routing priority-zero policy changed")
			}
		}
		if !r.ownsRule(rule) {
			if mark, present := number(rule["fwmark"]); present {
				mask, explicit := number(rule["fwmask"])
				if !explicit {
					mask = ^uint32(0)
				}
				if mark&mask == r.Mark&mask {
					return errors.New("capture: another policy changed original-egress marking")
				}
			}
		}
	}
	for _, item := range state.nft {
		if rule, ok := item["rule"].(map[string]any); ok {
			if exprs, ok := rule["expr"].([]any); ok {
				for _, expr := range exprs {
					if hasMark(expr) {
						mask, dynamic := markConstants(expr)
						if dynamic || mask&r.Mark != 0 {
							return errors.New("capture: another nftables rule changed the capture mark")
						}
					}
				}
			}
		}
	}
	if !found {
		return errors.New("capture: system routing policy was removed")
	}
	seen := make(map[netip.Prefix]bool, len(expected))
	for _, row := range state.routes {
		table, _ := number(row["table"])
		if table != r.Table {
			continue
		}
		prefix, valid := linuxRoutePrefix(row)
		if !valid || !expected[prefix] || !r.ownsRoute(row) || seen[prefix] {
			return errors.New("capture: foreign entry in system routing table")
		}
		seen[prefix] = true
	}
	if len(seen) != len(expected) {
		return errors.New("capture: a system resource route was removed")
	}
	return nil
}

func (r systemRoutes) checkOverlap(state kernelState, desired []netip.Prefix) error {
	for _, row := range state.routes {
		if r.ownsRoute(row) {
			continue
		}
		prefix, ok := linuxRoutePrefix(row)
		if !ok {
			continue
		}
		for _, capture := range desired {
			if prefix.Bits() >= capture.Bits() && prefix.Overlaps(capture) {
				return fmt.Errorf("capture: resource %s overlaps existing route %s", capture, prefix)
			}
		}
	}
	return nil
}
