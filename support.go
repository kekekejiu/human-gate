package main

import (
	"encoding/base64"
	"encoding/json"
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
	gateChatwootBaseURL = strings.TrimRight(validHTTPURL(os.Getenv("GATE_CHATWOOT_BASE_URL")), "/")
	gateChatwootToken = strings.TrimSpace(os.Getenv("GATE_CHATWOOT_TOKEN"))

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

	chatwootReady := gateChatwootBaseURL != "" && gateChatwootToken != ""
	enableRaw := strings.TrimSpace(os.Getenv("GATE_SUPPORT_ENABLE"))
	gateSupportEnabled = !strings.EqualFold(enableRaw, "off") &&
		(enableRaw != "" || gateSupportURL != "" || gateSupportScriptURL != "" || gateSupportHTML != "" || chatwootReady)
	if gateSupportEnabled {
		log.Printf("gate support enabled: chatwoot=%v static=%v script=%v custom=%v",
			chatwootReady, gateSupportURL != "", gateSupportScriptURL != "", gateSupportHTML != "")
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

// chatwootEmbedMarkup 生成 Chatwoot 挂件代码。
// 地址与 token 来自环境变量，便于各节点统一配置、无需重新编译：
//   GATE_CHATWOOT_BASE_URL   例如 https://103.118.41.128:11186
//   GATE_CHATWOOT_TOKEN      Chatwoot 网站入口 websiteToken
// 两者任一为空则返回空串（视为未启用 Chatwoot）。
func chatwootEmbedMarkup() string {
	if gateChatwootBaseURL == "" || gateChatwootToken == "" {
		return ""
	}
	base, _ := json.Marshal(gateChatwootBaseURL)
	token, _ := json.Marshal(gateChatwootToken)
	return `<script>window.chatwootSettings={locale:"zh_CN",position:"right",type:"standard",hideMessageBubble:false};(function(d,t){var BASE_URL=` +
		string(base) + `;var g=d.createElement(t),s=d.getElementsByTagName(t)[0];g.src=BASE_URL+"/packs/js/sdk.js";g.async=true;s.parentNode.insertBefore(g,s);g.onload=function(){window.chatwootSDK.run({websiteToken:` +
		string(token) + `,baseUrl:BASE_URL});};})(document,"script");window.addEventListener("chatwoot:ready",function(){var query=new URLSearchParams(window.location.search);window.$chatwoot.setCustomAttributes({current_page_url:window.location.href,current_page_title:document.title,landing_referrer:document.referrer||"直接访问",user_agent:navigator.userAgent,utm_source:query.get("utm_source")||"",utm_medium:query.get("utm_medium")||"",utm_campaign:query.get("utm_campaign")||""});});</script>`
}

func supportEmbedMarkup() string {
	if !gateSupportEnabled {
		return ""
	}
	// Chatwoot 为统一客服入口，配置齐全时优先使用，不再叠加其它客服脚本，
	// 避免多个挂件同时出现在右下角。
	if embed := chatwootEmbedMarkup(); embed != "" {
		return embed
	}
	out := gateSupportHTML
	if gateSupportScriptURL != "" {
		// 严格保持客服平台提供的同步脚本形式。部分加载器依赖 document.currentScript，
		// 添加 async/defer 会导致二级组件无法找到自身来源而初始化失败。
		out += `<script src="` + html.EscapeString(gateSupportScriptURL) + `"></script>`
	}
	return out
}
