package main

import (
	"encoding/json"
	"encoding/xml"
	"flag"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"golang.org/x/net/html"
)

// RDF structure for NVD RSS feed
type RDF struct {
	Items []Item `xml:"item"`
}

type Item struct {
	Title       string `xml:"title"`
	Link        string `xml:"link"`
	Description string `xml:"description"`
	PubDate     string `xml:"dc:date"`
}

// NVD JSON CVSS structure
type NVDResponse struct {
	Vulnerabilities []struct {
		Cve struct {
			Metrics struct {
				CvssV3_1 struct {
					BaseScore     float64 `json:"baseScore"`
					BaseSeverity  string  `json:"baseSeverity"`
				} `json:"cvssMetricV31"`
				CvssV3 struct {
					BaseScore     float64 `json:"baseScore"`
					BaseSeverity  string  `json:"baseSeverity"`
				} `json:"cvssMetricV30"`
			} `json:"metrics"`
		} `json:"cve"`
	} `json:"vulnerabilities"`
}

func main() {
	limit := flag.Int("n", 10, "Number of latest CVEs to fetch (default 10)")
	flag.Parse()

	fmt.Println("🔎 Fetching latest CVEs...\n")

	cves, err := fetchLatestCVEs()
	if err != nil {
		fmt.Println("❌ Error:", err)
		return
	}

	count := 0
	for _, cve := range cves {
		if !strings.HasPrefix(cve.Title, "CVE") {
			continue
		}

		if count >= *limit {
			break
		}

		// Fetch CVSS
		cvss, _ := fetchCVSS(cve.Title)

		// Get GitHub PoCs
		pocs := fetchPoCs(cve.Title)

		// Check for Nuclei template
		nucleiURL := fetchNucleiTemplate(cve.Title)

		// Output
		fmt.Printf("🧨 %s\n", cve.Title)
		fmt.Printf("🗓️  Published: %s\n", formatDate(cve.PubDate))
		fmt.Printf("📊 CVSS: %s\n", cvss)
		fmt.Printf("🏷️  Tags: %s\n", extractTags(cve.Description))
		fmt.Printf("📄 Description: %s\n", cve.Description)
		fmt.Printf("🔗 NVD Link: %s\n", cve.Link)

		if len(pocs) > 0 {
			fmt.Println("🧪 GitHub PoCs:")
			for _, url := range pocs {
				fmt.Printf("  - %s\n", url)
			}
		} else {
			fmt.Println("🧪 GitHub PoCs: Not found")
		}

		if nucleiURL != "" {
			fmt.Printf("🧬 Nuclei Template:\n  - %s\n", nucleiURL)
		} else {
			fmt.Println("🧬 Nuclei Template: Not available")
		}

		fmt.Println(strings.Repeat("-", 90))
		count++
	}
}

// Fetch latest CVEs from NVD RSS feed
func fetchLatestCVEs() ([]Item, error) {
	url := "https://nvd.nist.gov/feeds/xml/cve/misc/nvd-rss.xml"
	resp, err := http.Get(url)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	data, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	var rdf RDF
	if err := xml.Unmarshal(data, &rdf); err != nil {
		return nil, err
	}

	return rdf.Items, nil
}

// Format date nicely
func formatDate(raw string) string {
	t, err := time.Parse(time.RFC3339, raw)
	if err != nil {
		return raw
	}
	return t.Format("2006-01-02 15:04 MST")
}

// Extract basic tags from description
func extractTags(desc string) string {
	desc = strings.ToLower(desc)
	keywords := []string{"rce", "xss", "bypass", "csrf", "overflow", "windows", "linux", "apache", "mysql", "privilege"}
	var tags []string
	for _, word := range keywords {
		if strings.Contains(desc, word) {
			tags = append(tags, word)
		}
	}
	if len(tags) == 0 {
		return "None"
	}
	return strings.Join(tags, ", ")
}

// Fetch CVSS info from NVD JSON
func fetchCVSS(cveID string) (string, error) {
	url := fmt.Sprintf("https://services.nvd.nist.gov/rest/json/cve/1.0/%s", cveID)
	resp, err := http.Get(url)
	if err != nil {
		return "N/A", err
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		return "N/A", nil
	}

	body, _ := io.ReadAll(resp.Body)
	var nvd NVDResponse
	if err := json.Unmarshal(body, &nvd); err != nil {
		return "N/A", nil
	}

	if len(nvd.Vulnerabilities) == 0 {
		return "N/A", nil
	}

	metrics := nvd.Vulnerabilities[0].Cve.Metrics
	if metrics.CvssV3_1.BaseScore != 0 {
		return fmt.Sprintf("%.1f (%s)", metrics.CvssV3_1.BaseScore, metrics.CvssV3_1.BaseSeverity), nil
	}
	if metrics.CvssV3.BaseScore != 0 {
		return fmt.Sprintf("%.1f (%s)", metrics.CvssV3.BaseScore, metrics.CvssV3.BaseSeverity), nil
	}
	return "N/A", nil
}

// Scrape GitHub for PoCs
func fetchPoCs(cveID string) []string {
	url := fmt.Sprintf("https://github.com/search?q=%s&type=repositories", cveID)
	resp, err := http.Get(url)
	if err != nil {
		return nil
	}
	defer resp.Body.Close()

	var pocLinks []string
	z := html.NewTokenizer(resp.Body)
	seen := make(map[string]bool)

	for {
		tt := z.Next()
		if tt == html.ErrorToken {
			break
		}
		t := z.Token()
		if t.Type == html.StartTagToken && t.Data == "a" {
			href := ""
			for _, attr := range t.Attr {
				if attr.Key == "href" && strings.HasPrefix(attr.Val, "/") && !strings.Contains(attr.Val, "/topics/") {
					href = attr.Val
					break
				}
			}
			if href != "" && strings.Count(href, "/") == 2 {
				full := "https://github.com" + href
				if !seen[full] {
					pocLinks = append(pocLinks, full)
					seen[full] = true
				}
			}
			if len(pocLinks) >= 3 {
				break
			}
		}
	}
	return pocLinks
}

// Check if Nuclei template exists
func fetchNucleiTemplate(cveID string) string {
	yearPart := strings.Split(cveID, "-")
	if len(yearPart) != 3 {
		return ""
	}
	url := fmt.Sprintf("https://raw.githubusercontent.com/projectdiscovery/nuclei-templates/main/cves/%s/%s.yaml", yearPart[1], cveID)
	resp, err := http.Head(url)
	if err != nil || resp.StatusCode != 200 {
		return ""
	}
	return url
}
