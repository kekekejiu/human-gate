package main

import (
	"crypto/subtle"
	"encoding/json"
	"net/http"
	"time"
)

// handleIngest 接收远程节点批量上报的原始事件(中心侧)。
// 认证：X-Gate-Token 头与 GATE_INGEST_TOKEN 常数时间比较。
func handleIngest(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method", http.StatusMethodNotAllowed)
		return
	}
	tok := r.Header.Get("X-Gate-Token")
	if subtle.ConstantTimeCompare([]byte(tok), []byte(ingestToken)) != 1 {
		w.WriteHeader(http.StatusUnauthorized)
		return
	}
	var events []rawEvent
	// 限制请求体大小，单批最多约 1MB
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<20)).Decode(&events); err != nil {
		http.Error(w, "bad json", http.StatusBadRequest)
		return
	}
	for _, e := range events {
		if e.IP == "" {
			continue
		}
		if e.TS == 0 {
			e.TS = time.Now().Unix()
		}
		processEvent(e)
	}
	w.WriteHeader(http.StatusNoContent)
}
