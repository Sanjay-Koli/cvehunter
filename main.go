package main

import (
	"encoding/xml"
	"fmt"
	"io/ioutil"
	"net/http"
	"strings"
)

// RDF format (NVD uses RDF, not standard RSS)
type RDF struct {
	Items []Item `xml:"item"`
}

type Item struct {
	Title       string `xml:"title"`       // e.g., CVE-2025-12345
	Link        string `xml:"link"`        // NVD page
	Description string `xml:"description"` // Short summary
	PubDate     string `xml:"dc:date"`     // Publish date
}

func fetchLatestCVEs() ([]Item, error) {
	url := "https://nvd.nist.gov/feeds/xml/cve/misc/nvd-rss.xml"
	resp, err := http.Get(url)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch CVEs: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		return nil, fmt.Errorf("received non-200 response: %d", resp.StatusCode)
	}

	data, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read response body: %v", err)
	}

	var rdf RDF
	if err := xml.Unmarshal(data, &rdf); err != nil {
		return nil, fmt.Errorf("failed to parse RDF/XML: %v", err)
	}

	return rdf.Items, nil
}

func main() {
	fmt.Println("🔎 Fetching latest CVEs...\n")

	cves, err := fetchLatestCVEs()
	if err != nil {
		fmt.Println("❌ Error:", err)
		return
	}

	if len(cves) == 0 {
		fmt.Println("⚠️ No CVEs found in the feed.")
		return
	}

	fmt.Printf("✅ Total CVEs fetched: %d\n\n", len(cves))

	for _, cve := range cves {
		if !strings.HasPrefix(cve.Title, "CVE") {
			continue
		}

		fmt.Printf("🧨 %s\n", cve.Title)
		fmt.Printf("🗓️  Published: %s\n", cve.PubDate)
		fmt.Printf("📄 Description: %s\n", cve.Description)
		fmt.Printf("🔗 NVD Link: %s\n", cve.Link)
		fmt.Println(strings.Repeat("-", 80))
	}
}

