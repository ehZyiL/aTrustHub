package capture

import (
	"errors"
	"net/netip"
	"strings"

	"github.com/ehzyil/connect-hub/internal/dnsmapping"
	"github.com/ehzyil/connect-hub/internal/netpolicy"
	"github.com/ehzyil/connect-hub/internal/resolved"
)

// SystemResource identifies one VPN generation. A guard reserves existing
// resource routes and DNS ownership while its worker is offline.
type SystemResource struct {
	ID             string            `json:"id"`
	Gateway        string            `json:"gateway"`
	Guard          bool              `json:"guard,omitempty"`
	Networks       []netpolicy.Range `json:"networks,omitempty"`
	Domains        []string          `json:"domains,omitempty"`
	RequiredPrefix string            `json:"requiredPrefix,omitempty"`
	Alias          *AliasRef         `json:"alias,omitempty"`
}

type SystemConfig struct {
	Upstream    Upstream          `json:"upstream"`
	DNSAddress  string            `json:"dnsAddress"`
	Resources   []SystemResource  `json:"resources"`
	Reserved    []string          `json:"reserved,omitempty"`
	AliasRanges []netpolicy.Range `json:"aliasRanges,omitempty"`
}

func (c SystemConfig) validate() error {
	if err := c.Upstream.validate(); err != nil {
		return err
	}
	if c.Upstream.DNS != nil || c.Upstream.Alias != nil || len(c.Upstream.Networks) != 0 {
		return errors.New("capture: unexpected software capture options")
	}
	if len(c.Resources) == 0 || len(c.Resources) > maxSessions {
		return errors.New("capture: invalid number of system resources")
	}
	if err := dnsmapping.ValidateReservations(c.Reserved); err != nil {
		return err
	}
	if err := netpolicy.Validate(c.AliasRanges); err != nil {
		return err
	}
	seen := make(map[string]bool, len(c.Resources))
	for _, resource := range c.Resources {
		if !sessionPattern.MatchString(resource.ID) || seen[resource.ID] || resource.Gateway == "" ||
			len(resource.Gateway) > 253 || strings.ContainsAny(resource.Gateway, " /\\\r\n\t\x00@?#") {
			return errors.New("capture: invalid system gateway identity")
		}
		seen[resource.ID] = true
		if resource.Alias != nil && (!sessionPattern.MatchString(resource.Alias.ID) || len(resource.Alias.Token) != 64 || resource.Guard || len(resource.Domains) == 0) {
			return errors.New("capture: invalid shared system DNS reference")
		}
		if resource.RequiredPrefix != "" {
			prefix, err := netip.ParsePrefix(resource.RequiredPrefix)
			if err != nil || !dnsmapping.ValidPrefix(prefix) || resource.Guard || len(resource.Domains) == 0 {
				return errors.New("capture: invalid required worker DNS pool")
			}
		}
		if len(resource.Domains) == 0 && len(resource.Networks) == 0 {
			return errors.New("capture: empty system resource")
		}
		if err := netpolicy.Validate(resource.Networks); err != nil {
			return err
		}
		if len(resource.Domains) > 0 {
			if err := (resolved.Config{Address: c.DNSAddress, Domains: resource.Domains}).Validate(); err != nil {
				return err
			}
		}
	}
	return nil
}

type SystemState struct {
	Prefixes map[string]string `json:"prefixes,omitempty"`
	Original Upstream          `json:"original"`
}
