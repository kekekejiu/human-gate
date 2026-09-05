package main

import (
	"database/sql"
	"log"
	"time"

	_ "modernc.org/sqlite"
)

// visitStore 负责访问记录的持久化
type visitStore struct {
	db         *sql.DB
	retainDays int
}

// visitRow 一条访问记录
type visitRow struct {
	ID        int64  `json:"id"`
	TS        int64  `json:"ts"`
	IP        string `json:"ip"`
	UA        string `json:"ua"`
	Site      string `json:"site"`
	URI       string `json:"uri"`
	Passed    int    `json:"passed"` // 1=已持通行证 0=未通过(被拦到闸门)
	Country   string `json:"country"`
	Province  string `json:"province"`
	City      string `json:"city"`
	ASN       uint   `json:"asn"`
	ASNOrg    string `json:"asn_org"`
	IPType    string `json:"ip_type"`
	ISP       string `json:"isp"`
	RiskLevel string `json:"risk_level"` // ok/suspect/danger
	RiskTags  string `json:"risk_tags"`
}

func newVisitStore(path string, retainDays int) (*visitStore, error) {
	db, err := sql.Open("sqlite", path)
	if err != nil {
		return nil, err
	}
	db.SetMaxOpenConns(1) // sqlite 单写，避免锁竞争
	s := &visitStore{db: db, retainDays: retainDays}
	if err := s.init(); err != nil {
		db.Close()
		return nil, err
	}
	if err := s.initPolicy(); err != nil {
		db.Close()
		return nil, err
	}
	go s.gcLoop()
	return s, nil
}

func (s *visitStore) init() error {
	_, err := s.db.Exec(`
CREATE TABLE IF NOT EXISTS visits (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  ts INTEGER NOT NULL,
  ip TEXT, ua TEXT, site TEXT, uri TEXT, passed INTEGER,
  country TEXT, province TEXT, city TEXT,
  asn INTEGER, asn_org TEXT, ip_type TEXT, isp TEXT,
  risk_level TEXT, risk_tags TEXT
);
CREATE INDEX IF NOT EXISTS idx_visits_ts ON visits(ts);
CREATE INDEX IF NOT EXISTS idx_visits_ip ON visits(ip);
CREATE INDEX IF NOT EXISTS idx_visits_risk ON visits(risk_level);
`)
	return err
}

func (s *visitStore) insert(v visitRow) {
	_, err := s.db.Exec(
		`INSERT INTO visits(ts,ip,ua,site,uri,passed,country,province,city,asn,asn_org,ip_type,isp,risk_level,risk_tags)
		 VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)`,
		v.TS, v.IP, v.UA, v.Site, v.URI, v.Passed,
		v.Country, v.Province, v.City, v.ASN, v.ASNOrg, v.IPType, v.ISP,
		v.RiskLevel, v.RiskTags,
	)
	if err != nil {
		log.Printf("visit insert error: %v", err)
	}
}

func (s *visitStore) gcLoop() {
	ticker := time.NewTicker(time.Hour)
	defer ticker.Stop()
	for range ticker.C {
		cutoff := time.Now().Add(-time.Duration(s.retainDays) * 24 * time.Hour).Unix()
		if _, err := s.db.Exec(`DELETE FROM visits WHERE ts < ?`, cutoff); err != nil {
			log.Printf("visit gc error: %v", err)
		}
	}
}

// recent 返回最近的访问记录，可按风险等级过滤
func (s *visitStore) recent(limit int, riskFilter string) ([]visitRow, error) {
	q := `SELECT id,ts,ip,ua,site,uri,passed,country,province,city,asn,asn_org,ip_type,isp,risk_level,risk_tags FROM visits`
	args := []interface{}{}
	if riskFilter == "suspect" || riskFilter == "danger" {
		q += ` WHERE risk_level = ?`
		args = append(args, riskFilter)
	}
	q += ` ORDER BY id DESC LIMIT ?`
	args = append(args, limit)

	rows, err := s.db.Query(q, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []visitRow
	for rows.Next() {
		var v visitRow
		if err := rows.Scan(&v.ID, &v.TS, &v.IP, &v.UA, &v.Site, &v.URI, &v.Passed,
			&v.Country, &v.Province, &v.City, &v.ASN, &v.ASNOrg, &v.IPType, &v.ISP,
			&v.RiskLevel, &v.RiskTags); err != nil {
			return nil, err
		}
		out = append(out, v)
	}
	return out, nil
}

// kv 通用统计返回
type kv struct {
	Key   string `json:"key"`
	Count int    `json:"count"`
}

func (s *visitStore) groupBy(col string, sinceHours, limit int) ([]kv, error) {
	since := time.Now().Add(-time.Duration(sinceHours) * time.Hour).Unix()
	// col 由内部固定传入，非用户输入，避免注入
	q := `SELECT ` + col + ` AS k, COUNT(*) AS c FROM visits WHERE ts >= ? GROUP BY ` + col + ` ORDER BY c DESC LIMIT ?`
	rows, err := s.db.Query(q, since, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []kv
	for rows.Next() {
		var e kv
		if err := rows.Scan(&e.Key, &e.Count); err != nil {
			return nil, err
		}
		out = append(out, e)
	}
	return out, nil
}

// summary 返回总体统计
func (s *visitStore) summary(sinceHours int) map[string]interface{} {
	since := time.Now().Add(-time.Duration(sinceHours) * time.Hour).Unix()
	var total, uniqIP, danger, suspect, idc int
	s.db.QueryRow(`SELECT COUNT(*) FROM visits WHERE ts>=?`, since).Scan(&total)
	s.db.QueryRow(`SELECT COUNT(DISTINCT ip) FROM visits WHERE ts>=?`, since).Scan(&uniqIP)
	s.db.QueryRow(`SELECT COUNT(*) FROM visits WHERE ts>=? AND risk_level='danger'`, since).Scan(&danger)
	s.db.QueryRow(`SELECT COUNT(*) FROM visits WHERE ts>=? AND risk_level='suspect'`, since).Scan(&suspect)
	s.db.QueryRow(`SELECT COUNT(*) FROM visits WHERE ts>=? AND ip_type='idc'`, since).Scan(&idc)
	return map[string]interface{}{
		"total": total, "unique_ip": uniqIP,
		"danger": danger, "suspect": suspect, "idc": idc,
		"since_hours": sinceHours,
	}
}
