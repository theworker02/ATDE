package immunize

import (
	"context"
	"fmt"
	"log/slog"
	"net"
	"os"
	"strings"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/wafv2"
	"github.com/aws/aws-sdk-go-v2/service/wafv2/types"
)

// AWSWAFBanProvider updates an owned WAFv2 IPSet (GetIPSet → append CIDR → UpdateIPSet).
type AWSWAFBanProvider struct {
	Client    *wafv2.Client
	IPSetID   string
	IPSetName string
	Scope     types.Scope
	Log       *slog.Logger
	DryRun    bool
	ready     bool
}

// NewAWSWAF constructs a provider when IPSet id/name are configured; otherwise returns a disabled stub.
func NewAWSWAF(ctx context.Context, region, ipSetID, ipSetName string, cloudFront, dryRun bool, log *slog.Logger) *AWSWAFBanProvider {
	id := first(ipSetID, os.Getenv("AWS_WAF_IPSET_ID"))
	name := first(ipSetName, os.Getenv("AWS_WAF_IPSET_NAME"))
	reg := first(region, os.Getenv("AWS_REGION"), os.Getenv("AWS_DEFAULT_REGION"), "us-east-1")
	p := &AWSWAFBanProvider{
		IPSetID:   id,
		IPSetName: name,
		Log:       log,
		DryRun:    dryRun,
		Scope:     types.ScopeRegional,
	}
	if cloudFront || strings.EqualFold(os.Getenv("AWS_WAF_SCOPE"), "CLOUDFRONT") {
		p.Scope = types.ScopeCloudfront
		reg = "us-east-1"
	}
	if id == "" || name == "" {
		return p
	}
	cfg, err := config.LoadDefaultConfig(ctx, config.WithRegion(reg))
	if err != nil {
		if log != nil {
			log.Warn("aws waf config load failed", "err", err)
		}
		return p
	}
	p.Client = wafv2.NewFromConfig(cfg)
	p.ready = true
	return p
}

func (w *AWSWAFBanProvider) Enabled() bool {
	return w != nil && w.ready && w.IPSetID != "" && w.IPSetName != ""
}

func (w *AWSWAFBanProvider) BanIP(ctx context.Context, ipAddress string) error {
	if w == nil {
		return nil
	}
	if net.ParseIP(ipAddress) == nil {
		return fmt.Errorf("invalid ip")
	}
	if isPrivate(ipAddress) {
		return fmt.Errorf("refusing private/local ip")
	}
	if w.DryRun || !w.Enabled() {
		if w.Log != nil {
			w.Log.Info("aws waf ban dry-run/skip", "ip", ipAddress, "configured", w.Enabled())
		}
		return nil
	}

	getResp, err := w.Client.GetIPSet(ctx, &wafv2.GetIPSetInput{
		Id:    aws.String(w.IPSetID),
		Name:  aws.String(w.IPSetName),
		Scope: w.Scope,
	})
	if err != nil {
		return fmt.Errorf("get IPSet: %w", err)
	}

	cidr := ipAddress + "/32"
	if strings.Contains(ipAddress, ":") {
		cidr = ipAddress + "/128"
	}
	addrs := append([]string{}, getResp.IPSet.Addresses...)
	for _, a := range addrs {
		if a == cidr {
			return nil
		}
	}
	addrs = append(addrs, cidr)

	_, err = w.Client.UpdateIPSet(ctx, &wafv2.UpdateIPSetInput{
		Id:          aws.String(w.IPSetID),
		Name:        aws.String(w.IPSetName),
		Scope:       w.Scope,
		LockToken:   getResp.LockToken,
		Addresses:   addrs,
		Description: aws.String("Auto-Updated by ATDE Deception Engine"),
	})
	if err != nil {
		return fmt.Errorf("update IPSet: %w", err)
	}
	return nil
}
