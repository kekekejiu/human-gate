package main

import (
	"strings"
	"sync"
	"time"
)

// botUAKeywords 爬虫/自动化工具的 UA 特征
var botUAKeywords = []string{
	"python", "curl", "wget", "go-http-client", "java/", "okhttp",
	"scrapy", "httpx", "aiohttp", "libwww", "httpclient", "node-fetch",
	"axios", "headlesschrome", "phantomjs", "bot", "spider", "crawler",
	"masscan", "zgrab", "nmap", "censys", "fscan", "xray",
}

// freqCounter 统计单位时间内各 IP 的访问次数
type freqCounter struct {
	mu     sync.Mutex
	counts map[string][]int64 // ip -> 时间戳列表(秒)
	window int64              // 窗口秒数
}

func newFreqCounter(windowSec int64) *freqCounter {
	f := &freqCounter{counts: make(map[string][]int64), window: windowSec}
	go f.gc()
	return f
}

// hit 记录一次访问并返回窗口内该 IP 的访问次数
func (f *freqCounter) hit(ip string) int {
	now := time.Now().Unix()
	f.mu.Lock()
	defer f.mu.Unlock()
	arr := f.counts[ip]
	cutoff := now - f.window
	kept := arr[:0]
	for _, t := range arr {
		if t >= cutoff {
			kept = append(kept, t)
		}
	}
	kept = append(kept, now)
	f.counts[ip] = kept
	return len(kept)
}

func (f *freqCounter) gc() {
	ticker := time.NewTicker(5 * time.Minute)
	defer ticker.Stop()
	for range ticker.C {
		now := time.Now().Unix()
		cutoff := now - f.window
		f.mu.Lock()
		for ip, arr := range f.counts {
			kept := arr[:0]
			for _, t := range arr {
				if t >= cutoff {
					kept = append(kept, t)
				}
			}
			if len(kept) == 0 {
				delete(f.counts, ip)
			} else {
				f.counts[ip] = kept
			}
		}
		f.mu.Unlock()
	}
}

// assessRisk 综合 UA / IP画像 / 频率 打分，返回等级与标签
// 只做标记，不做任何封禁
func assessRisk(ua string, p IPProfile, freq int) (level string, tags []string) {
	uaLower := strings.ToLower(strings.TrimSpace(ua))

	if uaLower == "" {
		tags = append(tags, "空UA")
	} else {
		for _, kw := range botUAKeywords {
			if strings.Contains(uaLower, kw) {
				tags = append(tags, "爬虫UA:"+kw)
				break
			}
		}
	}

	if p.IPType == "idc" {
		tags = append(tags, "机房IP")
	}
	if freq >= 60 {
		tags = append(tags, "高频访问")
	} else if freq >= 20 {
		tags = append(tags, "较高频率")
	}

	// 等级判定
	hasBot := false
	hasIDC := false
	hasHighFreq := false
	for _, t := range tags {
		if strings.HasPrefix(t, "爬虫UA") || t == "空UA" {
			hasBot = true
		}
		if t == "机房IP" {
			hasIDC = true
		}
		if t == "高频访问" {
			hasHighFreq = true
		}
	}

	switch {
	case hasBot && (hasIDC || hasHighFreq):
		level = "danger"
	case hasBot || (hasIDC && hasHighFreq):
		level = "danger"
	case hasIDC || hasHighFreq:
		level = "suspect"
	default:
		level = "ok"
	}
	return level, tags
}
