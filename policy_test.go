package main

import (
	"net/netip"
	"testing"
	"time"
)

func TestPolicySignatureAndTamper(t *testing.T) {
	p := distributedPolicy{Version: 3, GeneratedAt: time.Now().Unix(), ExpiresAt: time.Now().Add(time.Minute).Unix(), Mode: "observe", Action: "redirect", Allow: []string{"39.96.203.191/32"}}
	p.Signature = policySign(p, "token")
	if !policyVerify(p, "token") {
		t.Fatal("valid policy signature rejected")
	}
	p.Action = "drop"
	if policyVerify(p, "token") {
		t.Fatal("tampered policy signature accepted")
	}
}

func TestInfrastructureAllowlistWins(t *testing.T) {
	p := distributedPolicy{
		Version: 1, ExpiresAt: time.Now().Add(time.Minute).Unix(), Mode: "observe", Action: "redirect",
		Allow: []string{"39.96.203.191/32", "120.55.94.106/32", "103.118.42.217/32", "103.118.42.224/32"},
		Rules: []policyRule{{IP: "39.96.203.191", ExpiresAt: time.Now().Add(time.Hour).Unix()}},
	}
	compiled, err := compilePolicy(p)
	if err != nil {
		t.Fatal(err)
	}
	for _, ip := range []string{"39.96.203.191", "120.55.94.106", "103.118.42.217", "103.118.42.224"} {
		if d := compiled.decide(ip); d.Matched {
			t.Fatalf("infrastructure address %s matched block rule", ip)
		}
	}
}

func TestObserveCandidateMatchesWithoutEnforcement(t *testing.T) {
	p := distributedPolicy{
		Version: 7, ExpiresAt: time.Now().Add(time.Minute).Unix(), Mode: "observe", Action: "redirect",
		Rules: []policyRule{{IP: "203.0.113.77", ExpiresAt: time.Now().Add(time.Hour).Unix()}},
	}
	compiled, err := compilePolicy(p)
	if err != nil {
		t.Fatal(err)
	}
	d := compiled.decide("203.0.113.77")
	if !d.Matched || d.Mode != "observe" || d.Action != "redirect" || d.Version != 7 {
		t.Fatalf("unexpected decision: %+v", d)
	}
}

func TestExpiredPolicyDoesNotMatch(t *testing.T) {
	p := &compiledPolicy{Policy: distributedPolicy{ExpiresAt: time.Now().Add(-time.Second).Unix()}, Rules: map[netip.Addr]policyRule{}}
	if d := p.decide("203.0.113.77"); d.Matched {
		t.Fatal("expired policy matched")
	}
}
