package main

import (
	"errors"
	"sync"
	"time"

	"github.com/wenlng/go-captcha-assets/resources/imagesv2"
	"github.com/wenlng/go-captcha-assets/resources/tiles"
	"github.com/wenlng/go-captcha/v2/slide"
)

// challenge 保存一次滑块验证的正确答案
type challenge struct {
	x       int
	y       int
	expires time.Time
}

// captchaManager 负责生成滑块挑战与在内存中暂存答案
type captchaManager struct {
	capt slide.Captcha

	mu    sync.Mutex
	store map[string]challenge
	ttl   time.Duration
}

func newCaptchaManager(ttl time.Duration) (*captchaManager, error) {
	bgs, err := imagesv2.GetImages()
	if err != nil {
		return nil, err
	}
	graphs, err := tiles.GetTiles()
	if err != nil {
		return nil, err
	}

	slideGraphs := make([]*slide.GraphImage, 0, len(graphs))
	for _, g := range graphs {
		slideGraphs = append(slideGraphs, &slide.GraphImage{
			OverlayImage: g.OverlayImage,
			ShadowImage:  g.ShadowImage,
			MaskImage:    g.MaskImage,
		})
	}

	builder := slide.NewBuilder()
	builder.SetResources(
		slide.WithGraphImages(slideGraphs),
		slide.WithBackgrounds(bgs),
	)

	m := &captchaManager{
		capt:  builder.Make(),
		store: make(map[string]challenge),
		ttl:   ttl,
	}
	go m.gc()
	return m, nil
}

// generate 生成一张滑块图，返回挑战 id、主图与滑块图(base64)以及滑块初始 y
func (m *captchaManager) generate(id string) (masterB64, tileB64 string, tileY, tileWidth, tileHeight int, err error) {
	data, err := m.capt.Generate()
	if err != nil {
		return "", "", 0, 0, 0, err
	}
	block := data.GetData()
	if block == nil {
		return "", "", 0, 0, 0, errors.New("generate failed")
	}
	masterB64, err = data.GetMasterImage().ToBase64()
	if err != nil {
		return "", "", 0, 0, 0, err
	}
	tileB64, err = data.GetTileImage().ToBase64()
	if err != nil {
		return "", "", 0, 0, 0, err
	}

	m.mu.Lock()
	m.store[id] = challenge{x: block.X, y: block.Y, expires: time.Now().Add(m.ttl)}
	m.mu.Unlock()

	return masterB64, tileB64, block.DY, block.Width, block.Height, nil
}

// verify 校验用户滑到的 x 坐标是否命中(y 方向滑块不动)，一次性消费
func (m *captchaManager) verify(id string, userX, userY int) bool {
	m.mu.Lock()
	ch, ok := m.store[id]
	if ok {
		delete(m.store, id)
	}
	m.mu.Unlock()

	if !ok || time.Now().After(ch.expires) {
		return false
	}
	// 滑块仅水平移动，Y 为常量不作安全判据，仅校验 X 命中缺口(带容差)
	_ = userY
	const padding = 8
	if userX < ch.x-padding || userX > ch.x+padding {
		return false
	}
	return true
}

func (m *captchaManager) gc() {
	ticker := time.NewTicker(time.Minute)
	defer ticker.Stop()
	for range ticker.C {
		now := time.Now()
		m.mu.Lock()
		for k, v := range m.store {
			if now.After(v.expires) {
				delete(m.store, k)
			}
		}
		m.mu.Unlock()
	}
}
