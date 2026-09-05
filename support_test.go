package main

import (
	"strings"
	"testing"
)

func TestSupportPageIncludesStaticFallbackAndScript(t *testing.T) {
	gateSupportEnabled = true
	gateSupportURL = "https://support.example/ticket"
	gateSupportText = "联系客服"
	gateSupportScriptURL = "https://plugin.example/chat.js"
	gateSupportHTML = ""
	page := renderGatePage()
	for _, want := range []string{"https://support.example/ticket", "联系客服", "https://plugin.example/chat.js", "HG-VERIFY-01"} {
		if !strings.Contains(page, want) {
			t.Fatalf("rendered page missing %q", want)
		}
	}
}

func TestInvalidSupportScriptSchemeRejected(t *testing.T) {
	if got := validHTTPURL("javascript:alert(1)"); got != "" {
		t.Fatalf("unsafe script URL accepted: %q", got)
	}
}
