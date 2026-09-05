package main

import (
	"encoding/base64"
	"html"
	"log"
	"net/url"
	"os"
	"strings"
)

func initSupport() {
	gateSupportURL = strings.TrimSpace(os.Getenv("GATE_SUPPORT_URL"))
	gateSupportText = envDefault("GATE_SUPPORT_TEXT", "验证遇到问题？联系客服")
	gateSupportScriptURL = validHTTPURL(os.Getenv("GATE_SUPPORT_SCRIPT_URL"))

	if path := strings.TrimSpace(os.Getenv("GATE_SUPPORT_HTML_FILE")); path != "" {
		if b, err := os.ReadFile(path); err == nil {
			gateSupportHTML = string(b)
		} else {
			log.Printf("support html file error: %v", err)
		}
	} else if raw := strings.TrimSpace(os.Getenv("GATE_SUPPORT_HTML_B64")); raw != "" {
		if b, err := base64.StdEncoding.DecodeString(raw); err == nil {
			gateSupportHTML = string(b)
		} else {
			log.Printf("support html base64 error: %v", err)
		}
	}

	enableRaw := strings.TrimSpace(os.Getenv("GATE_SUPPORT_ENABLE"))
	gateSupportEnabled = !strings.EqualFold(enableRaw, "off") &&
		(enableRaw != "" || gateSupportURL != "" || gateSupportScriptURL != "" || gateSupportHTML != "")
	if gateSupportEnabled {
		log.Printf("gate support enabled: static=%v script=%v custom=%v", gateSupportURL != "", gateSupportScriptURL != "", gateSupportHTML != "")
	}
}

func validHTTPURL(raw string) string {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return ""
	}
	u, err := url.Parse(raw)
	if err != nil || (u.Scheme != "https" && u.Scheme != "http") || u.Host == "" {
		log.Printf("ignore invalid support URL: %q", raw)
		return ""
	}
	return raw
}

func supportMarkup() string {
	if !gateSupportEnabled {
		return `<div class="support"><div>验证无法完成？</div><a href="javascript:location.reload()">重新加载验证</a><small>故障码 HG-VERIFY-01</small></div>`
	}
	contact := ""
	if gateSupportURL != "" {
		contact = `<a class="support-primary" href="` + html.EscapeString(gateSupportURL) + `" target="_blank" rel="noopener noreferrer">` + html.EscapeString(gateSupportText) + `</a>`
	} else if gateSupportScriptURL != "" || gateSupportHTML != "" {
		contact = `<span class="support-note">` + html.EscapeString(gateSupportText) + `（右下角客服图标）</span>`
	}
	return `<div class="support">` + contact + `<a href="javascript:location.reload()">重新加载验证</a><small>如客服组件未加载，请截图故障码 HG-VERIFY-01</small></div>`
}

func supportEmbedMarkup() string {
	if !gateSupportEnabled {
		return ""
	}
	out := gateSupportHTML
	if gateSupportScriptURL != "" {
		out += `<script src="` + html.EscapeString(gateSupportScriptURL) + `" async></script>`
	}
	return out
}
