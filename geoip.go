package main

import (
	"net"
	"strings"

	"github.com/lionsoul2014/ip2region/binding/golang/xdb"
	"github.com/oschwald/geoip2-golang"
)

// IPProfile 是一次 IP 画像结果
type IPProfile struct {
	Country  string `json:"country"`  // 国家代码，如 CN/US
	Province string `json:"province"` // 省份(中文)
	City     string `json:"city"`     // 城市(中文)
	ASN      uint   `json:"asn"`      // 自治域号
	ASNOrg   string `json:"asn_org"`  // 自治域组织名
	IPType   string `json:"ip_type"`  // idc / carrier / unknown
	ISP      string `json:"isp"`      // telecom/unicom/mobile/其他/unknown
}

type geoResolver struct {
	city *geoip2.Reader
	asn  *geoip2.Reader
	// ip2region：国内地市级 + 运营商兜底(可选，加载失败则为 nil)
	region4 *xdb.Searcher
	region6 *xdb.Searcher
}

func newGeoResolver(cityPath, asnPath string) (*geoResolver, error) {
	c, err := geoip2.Open(cityPath)
	if err != nil {
		return nil, err
	}
	a, err := geoip2.Open(asnPath)
	if err != nil {
		c.Close()
		return nil, err
	}
	return &geoResolver{city: c, asn: a}, nil
}

// loadIP2Region 加载国内 IP 库(v4/v6)，用于地市级与运营商兜底。
// 任一失败都不影响主流程，仅记录为空。
func (g *geoResolver) loadIP2Region(v4Path, v6Path string) {
	if v4Path != "" {
		if buf, err := xdb.LoadContentFromFile(v4Path); err == nil {
			if s, err := xdb.NewWithBuffer(xdb.IPv4, buf); err == nil {
				g.region4 = s
			}
		}
	}
	if v6Path != "" {
		if buf, err := xdb.LoadContentFromFile(v6Path); err == nil {
			if s, err := xdb.NewWithBuffer(xdb.IPv6, buf); err == nil {
				g.region6 = s
			}
		}
	}
}

func (g *geoResolver) Close() {
	if g.city != nil {
		g.city.Close()
	}
	if g.asn != nil {
		g.asn.Close()
	}
	if g.region4 != nil {
		g.region4.Close()
	}
	if g.region6 != nil {
		g.region6.Close()
	}
}

// Lookup 对给定 IP 做画像
func (g *geoResolver) Lookup(ipStr string) IPProfile {
	p := IPProfile{IPType: "unknown", ISP: "unknown"}
	ip := net.ParseIP(ipStr)
	if ip == nil {
		return p
	}

	if c, err := g.city.City(ip); err == nil {
		p.Country = c.Country.IsoCode
		if len(c.Subdivisions) > 0 {
			p.Province = firstNonEmpty(c.Subdivisions[0].Names["zh-CN"], c.Subdivisions[0].Names["en"])
		}
		p.City = firstNonEmpty(c.City.Names["zh-CN"], c.City.Names["en"])
	}

	if a, err := g.asn.ASN(ip); err == nil {
		p.ASN = a.AutonomousSystemNumber
		p.ASNOrg = a.AutonomousSystemOrganization
	}

	p.ISP = classifyISP(p.ASNOrg, p.ASN, p.Country)
	p.IPType = classifyIPType(p.ASNOrg, p.ISP)

	// 国内 IP 用 ip2region 补齐地市级与运营商(GeoLite2 免费库对移动省市常缺失)
	g.enrichWithRegion(ip, &p)
	return p
}

// enrichWithRegion 用 ip2region 覆盖国内 IP 的省/市/运营商。
// 格式：国家|区域|省份|城市|ISP，如 "中国|北京市|北京市|移动|CN"。
func (g *geoResolver) enrichWithRegion(ip net.IP, p *IPProfile) {
	var s *xdb.Searcher
	if ip.To4() != nil {
		s = g.region4
	} else {
		s = g.region6
	}
	if s == nil {
		return
	}
	raw, err := s.Search(ip.String())
	if err != nil || raw == "" {
		return
	}
	f := strings.Split(raw, "|")
	if len(f) < 5 {
		return
	}
	country, province, city, isp := f[0], f[1], f[2], f[3]
	// 仅对中国大陆 IP 采用 ip2region 结果(境外仍以 GeoLite2 为准)
	if country != "中国" {
		return
	}
	if p.Country == "" {
		p.Country = "CN"
	}
	if v := cleanRegion(province); v != "" {
		p.Province = v
	}
	if v := cleanRegion(city); v != "" {
		p.City = v
	}
	if mapped := mapRegionISP(isp); mapped != "" {
		p.ISP = mapped
		if p.IPType == "unknown" {
			p.IPType = "carrier"
		}
	}
}

// cleanRegion 过滤 ip2region 的占位符("0"/空)
func cleanRegion(v string) string {
	v = strings.TrimSpace(v)
	if v == "" || v == "0" {
		return ""
	}
	return v
}

// mapRegionISP 把 ip2region 的 ISP 字段映射到统一口径
func mapRegionISP(isp string) string {
	switch {
	case strings.Contains(isp, "移动") || strings.Contains(isp, "铁通"):
		return "移动"
	case strings.Contains(isp, "联通") || strings.Contains(isp, "网通"):
		return "联通"
	case strings.Contains(isp, "电信"):
		return "电信"
	case strings.Contains(isp, "教育"):
		return "教育网"
	default:
		return ""
	}
}

func firstNonEmpty(vals ...string) string {
	for _, v := range vals {
		if strings.TrimSpace(v) != "" {
			return v
		}
	}
	return ""
}

// 三大运营商已知 ASN(含省级子公司)。ASN 命中最可靠，作为首选判据。
var (
	telecomASN = map[uint]bool{4134: true, 4809: true, 4811: true, 4812: true, 4813: true, 23724: true, 24138: true, 63838: true, 131285: true, 131325: true, 132118: true, 137687: true, 137689: true, 137693: true, 137694: true, 138948: true, 139018: true, 140330: true, 140726: true}
	unicomASN  = map[uint]bool{4837: true, 9929: true, 10099: true, 17621: true, 17622: true, 17816: true, 17964: true, 131486: true, 132633: true, 136958: true, 137688: true, 137692: true, 137695: true, 138421: true, 139007: true}
	mobileASN  = map[uint]bool{9808: true, 24400: true, 24444: true, 24445: true, 24547: true, 56040: true, 56041: true, 56042: true, 56044: true, 56046: true, 56047: true, 56048: true, 132510: true, 132525: true, 137872: true, 137876: true, 141425: true, 9231: true, 58453: true, 38019: true}
)

// classifyISP 依据 ASN 号 + 组织名判断运营商。
// 优先用 ASN 号(最准，覆盖省级子公司)，再用组织名关键词兜底。
func classifyISP(org string, asn uint, country string) string {
	switch {
	case telecomASN[asn]:
		return "电信"
	case mobileASN[asn]:
		return "移动"
	case unicomASN[asn]:
		return "联通"
	}
	o := strings.ToLower(org)
	isCN := country == "" || country == "CN"
	switch {
	case strings.Contains(o, "chinanet") || strings.Contains(o, "china telecom") || strings.Contains(o, "telecom"):
		return "电信"
	case strings.Contains(o, "unicom") || strings.Contains(o, "china169") || strings.Contains(o, "cnc"):
		return "联通"
	case strings.Contains(o, "china mobile") || strings.Contains(o, "cmnet") || strings.Contains(o, "tietong"):
		return "移动"
	// 省级子公司常见格式："Shandong Mobile"、"Zhejiang Telecom"，仅在国内 IP 下宽松匹配
	case isCN && strings.Contains(o, "mobile"):
		return "移动"
	case isCN && strings.Contains(o, "cernet") || strings.Contains(o, "education"):
		return "教育网"
	default:
		return "其他"
	}
}

// idcKeywords 云厂商/IDC 关键词，命中则判为机房 IP
var idcKeywords = []string{
	"alibaba", "aliyun", "tencent", "huawei", "amazon", "aws", "google",
	"microsoft", "azure", "cloudflare", "zenlayer", "ucloud", "kingsoft",
	"baidu", "digitalocean", "linode", "vultr", "ovh", "hetzner", "gcore",
	"leaseweb", "choopa", "hostwinds", "contabo", "oracle", "idc", "data center",
	"datacenter", "hosting", "cloud", "server", "vps",
}

// classifyIPType 判断 IDC 还是运营商住宅/商宽
func classifyIPType(org, isp string) string {
	o := strings.ToLower(org)
	for _, kw := range idcKeywords {
		if strings.Contains(o, kw) {
			return "idc"
		}
	}
	// 命中三大运营商基础网络，视为宽带接入(家宽/商宽，免费库无法进一步细分)
	if isp == "电信" || isp == "联通" || isp == "移动" {
		return "carrier"
	}
	return "unknown"
}
