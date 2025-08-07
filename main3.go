package main

import (
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"sort"
	"strings"
	"time"
)

type CVE struct {
	ID          string   `json:"id"`
	Summary     string   `json:"summary"`
	Published   string   `json:"Published"`
	Modified    string   `json:"Modified"`
	CVSS        float64  `json:"cvss"`
	CWE         string   `json:"cwe"`
	References  []string `json:"references"`
}

const (
	cveURL   = "https://cve.circl.lu/api/last"
	cveIDURL = "https://cve.circl.lu/api/cve/"
)

var (
	flagCVEID     = flag.String("cve", "", "Fetch specific CVE (e.g. CVE-2024-12345)")
	flagAuto      = flag.Bool("auto", false, "Fetch latest CVEs automatically")
	flagTags      = flag.String("tags", "", "Filter exploits by tags (e.g. RCE,XSS)")
	flagVerbose   = flag.Bool("verbose", false, "Verbose output")
	flagOutput    = flag.String("output", "", "Save results to file (e.g. results.json)")
	flagToken     = flag.String("token", "", "GitHub token to bypass rate limits")
	flagSince     = flag.String("since", "", "Filter CVEs published since date (YYYY-MM-DD)")
	flagIgnore    = flag.String("ignore", "", "Ignore CVEs with specific keywords")
	flagSort      = flag.String("sort", "", "Sort by latest or stars")
	flagLang      = flag.String("lang", "", "Filter PoCs by language (e.g. go,python)")
	flagSilent    = flag.Bool("silent", false, "Silent mode (no stdout, just output file)")
	flagLimit     = flag.Int("limit", 0, "Limit number of CVEs shown")
	flagSeverity  = flag.String("severity", "", "Filter by severity (e.g. high,critical)")
)

func log(msg string, args ...any) {
	if *flagVerbose && !*flagSilent {
		fmt.Printf(msg+"\n", args...)
	}
}

func fetchCVEByID(id string) (*CVE, error) {
	resp, err := http.Get(cveIDURL + id)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode == 404 {
		return nil, errors.New("CVE not found")
	}
	var cve CVE
	if err := json.NewDecoder(resp.Body).Decode(&cve); err != nil {
		return nil, err
	}
	return &cve, nil
}

func fetchLatestCVEs() ([]CVE, error) {
	resp, err := http.Get(cveURL)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	var cves []CVE
	if err := json.NewDecoder(resp.Body).Decode(&cves); err != nil {
		return nil, err
	}
	return cves, nil
}

func filterCVEs(cves []CVE) []CVE {
	var results []CVE
	ignoreList := strings.Split(strings.ToLower(*flagIgnore), ",")
	tags := strings.Split(strings.ToLower(*flagTags), ",")
	severityMap := map[string]float64{
		"low": 3.9, "medium": 6.9, "high": 8.9, "critical": 10.0,
	}
	sinceDate := time.Time{}
	if *flagSince != "" {
		parsed, _ := time.Parse("2006-01-02", *flagSince)
		sinceDate = parsed
	}
	
	for _, cve := range cves {
		if *flagSince != "" {
			pubTime, _ := time.Parse("2006-01-02T15:04:05", cve.Published)
			if pubTime.Before(sinceDate) {
				continue
			}
		}

		if *flagSeverity != "" {
			allowed := false
			for _, s := range strings.Split(*flagSeverity, ",") {
				if cve.CVSS >= severityMap[strings.ToLower(strings.TrimSpace(s))] {
					allowed = true
					break
				}
			}
			if !allowed {
				continue
			}
		}

		skip := false
		for _, ign := range ignoreList {
			if strings.Contains(strings.ToLower(cve.Summary), ign) {
				skip = true
				break
			}
		}
		if skip {
			continue
		}

		if *flagTags != "" {
			found := false
			for _, tag := range tags {
				if strings.Contains(strings.ToLower(cve.Summary), tag) {
					found = true
					break
				}
			}
			if !found {
				continue
			}
		}
		results = append(results, cve)
	}

	if *flagSort == "latest" {
		sort.Slice(results, func(i, j int) bool {
			return results[i].Published > results[j].Published
		})
	}
	if *flagLimit > 0 && len(results) > *flagLimit {
		results = results[:*flagLimit]
	}
	return results
}

func outputResults(cves []CVE) {
	if *flagSilent {
		return
	}
	for _, cve := range cves {
		fmt.Printf("ID: %s\nPublished: %s\nCVSS: %.1f\nSummary: %s\n\n", cve.ID, cve.Published, cve.CVSS, cve.Summary)
	}
}

func saveToFile(cves []CVE) error {
	if *flagOutput == "" {
		return nil
	}
	data, err := json.MarshalIndent(cves, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(*flagOutput, data, 0644)
}

func main() {
	flag.Parse()

	if *flagCVEID != "" {
		cve, err := fetchCVEByID(*flagCVEID)
		if err != nil {
			fmt.Println("[!]", err)
			os.Exit(1)
		}
		outputResults([]CVE{*cve})
		saveToFile([]CVE{*cve})
		return
	}

	if *flagAuto || *flagTags != "" || *flagSince != "" || *flagSeverity != "" {
		log("[+] Fetching latest CVEs...")
		cves, err := fetchLatestCVEs()
		if err != nil {
			fmt.Println("[!]", err)
			os.Exit(1)
		}
		filtered := filterCVEs(cves)
		outputResults(filtered)
		saveToFile(filtered)
		return
	}

	flag.Usage()
}
