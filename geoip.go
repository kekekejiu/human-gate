package main

import (
	"net"
	"strings"

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

func (g *geoResolver) Close() {
	if g.city != nil {
		g.city.Close()
	}
	if g.asn != nil {
		g.asn.Close()
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
	return p
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
