package main

import (
	"bytes"
	"crypto/tls"
	"encoding/json"
	"log"
	"net/http"
	"time"
)

// rawEvent 是一次未经画像的原始访问事件，由远程节点上报给中心。
// 真实客户端 IP 已在远程节点侧通过 nginx real_ip 还原，中心信任该值。
type rawEvent struct {
	TS     int64  `json:"ts"`
	IP     string `json:"ip"`
	UA     string `json:"ua"`
	Site   string `json:"site"`
	URI    string `json:"uri"`
	Passed int    `json:"passed"`
}

// reporter 把本地访问事件异步、批量地推送到中心 ingest 端点。
// 采集是尽力而为：缓冲满或推送失败均直接丢弃，绝不阻塞闸门主流程。
type reporter struct {
	url    string
	token  string
	ch     chan rawEvent
	client *http.Client
}

func newReporter(url, token string, insecure bool) *reporter {
	client := &http.Client{Timeout: 5 * time.Second}
	if insecure {
		// 中心用自签证书时跳过校验：TLS 仅负责加密，防伪造由 X-Gate-Token 保证
		client.Transport = &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		}
	}
	r := &reporter{
		url:    url,
		token:  token,
		ch:     make(chan rawEvent, 2000),
		client: client,
	}
	go r.loop()
	return r
}

// send 入队一个事件；缓冲满时直接丢弃，保证非阻塞
func (r *reporter) send(e rawEvent) {
	select {
	case r.ch <- e:
	default:
	}
}

func (r *reporter) loop() {
	batch := make([]rawEvent, 0, 64)
	ticker := time.NewTicker(2 * time.Second)
	defer ticker.Stop()
	flush := func() {
		if len(batch) == 0 {
			return
		}
		r.post(batch)
		batch = batch[:0]
	}
	for {
		select {
		case e := <-r.ch:
			batch = append(batch, e)
			if len(batch) >= 64 {
				flush()
			}
		case <-ticker.C:
			flush()
		}
	}
}

func (r *reporter) post(events []rawEvent) {
	body, err := json.Marshal(events)
	if err != nil {
		return
	}
	req, err := http.NewRequest(http.MethodPost, r.url, bytes.NewReader(body))
	if err != nil {
		return
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Gate-Token", r.token)
	resp, err := r.client.Do(req)
	if err != nil {
		log.Printf("reporter post error: %v", err)
		return
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 300 {
		log.Printf("reporter post rejected: status=%d", resp.StatusCode)
	}
}
