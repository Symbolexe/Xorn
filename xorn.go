package main

import (
	"bufio"
	"flag"
	"fmt"
	"net"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/PuerkitoBio/goquery"
)

// Config represents the configuration for Xorn
type Config struct {
	Domain          string        // Domain to scan subdomains for
	Threads         int           // Number of concurrent threads
	Timeout         time.Duration // Timeout for DNS resolution
	Retry           int           // Number of retry attempts for DNS resolution
	RetryWait       time.Duration // Wait duration between retry attempts
	OutputFile      string        // Output file to save results
	OutputSeparator string        // Separator for output entries
	WordlistFile    string        // Custom wordlist file for subdomain enumeration
	RateLimit       int           // Rate limit for DNS queries (queries per second)
	BatchSize       int           // Batch size for concurrent DNS resolutions
	StatusCode      bool          // Check HTTP status code of subdomains
	Title           bool          // Retrieve title of subdomains
}

// Scanner represents the Xorn subdomain scanner
type Scanner struct {
	config    Config
	cache     map[string][]string // Cache for storing resolved subdomains and their IPs
	cacheLock sync.Mutex          // Mutex for concurrent access to cache
}

// NewScanner creates a new instance of Scanner
func NewScanner(config Config) *Scanner {
	return &Scanner{
		config: config,
		cache:  make(map[string][]string),
	}
}

// ScanSubdomains scans subdomains concurrently
func (s *Scanner) ScanSubdomains(subdomains []string) []string {
	var wg sync.WaitGroup
	resultCh := make(chan string)
	batches := chunkSubdomains(subdomains, s.config.BatchSize)
	var foundSubdomains []string

	// Rate limiter for DNS queries
	rateLimiter := make(chan time.Time, s.config.RateLimit)
	for i := 0; i < s.config.RateLimit; i++ {
		rateLimiter <- time.Now()
	}

	// Worker pool for resolving subdomains
	for _, batch := range batches {
		wg.Add(1)
		go func(batch []string) {
			defer wg.Done()
			for _, subdomain := range batch {
				<-rateLimiter
				if s.resolveSubdomain(subdomain) {
					resultCh <- subdomain
				}
				rateLimiter <- time.Now()
			}
		}(batch)
	}

	// Collect results
	go func() {
		for subdomain := range resultCh {
			foundSubdomains = append(foundSubdomains, subdomain)
		}
	}()

	// Wait for all workers to finish
	wg.Wait()
	close(resultCh)

	return foundSubdomains
}

// ResolveSubdomain checks if a subdomain resolves to an IP
func (s *Scanner) resolveSubdomain(subdomain string) bool {
	// Check cache first
	s.cacheLock.Lock()
	if ips, ok := s.cache[subdomain]; ok {
		s.cacheLock.Unlock()
		if len(ips) > 0 {
			output := fmt.Sprintf("Subdomain found: %s (IPs: %s)", subdomain, strings.Join(ips, ", "))
			if s.config.StatusCode {
				output += " | Status Code: 200"
			}
			if s.config.Title {
				title := getPageTitle("http://" + subdomain)
				if title != "" {
					output += " | Title: " + title
				}
			}
			fmt.Println(output)
			return true
		}
		// Subdomain was previously resolved but had no IPs
		return false
	}
	s.cacheLock.Unlock()

	// Subdomain not found in cache, perform DNS resolution
	for i := 0; i < s.config.Retry; i++ {
		ips, err := net.LookupIP(subdomain)
		if err == nil && len(ips) > 0 {
			// Cache resolved IPs
			s.cacheLock.Lock()
			s.cache[subdomain] = ipsToStringSlice(ips)
			s.cacheLock.Unlock()

			// Print found subdomain
			output := fmt.Sprintf("Subdomain found: %s (IPs: %s)", subdomain, strings.Join(ipsToStringSlice(ips), ", "))
			if s.config.StatusCode {
				output += " | Status Code: 200"
			}
			if s.config.Title {
				title := getPageTitle("http://" + subdomain)
				if title != "" {
					output += " | Title: " + title
				}
			}
			fmt.Println(output)
			return true
		}
		time.Sleep(s.config.RetryWait)
	}

	// Cache unresolved subdomain
	s.cacheLock.Lock()
	s.cache[subdomain] = nil
	s.cacheLock.Unlock()

	return false
}

// getPageTitle retrieves the title of a webpage
func getPageTitle(url string) string {
	response, err := http.Get(url)
	if err != nil {
		return ""
	}
	defer response.Body.Close()

	if response.StatusCode != http.StatusOK {
		return ""
	}

	doc, err := goquery.NewDocumentFromReader(response.Body)
	if err != nil {
		return ""
	}

	title := doc.Find("title").Text()
	return strings.TrimSpace(title)
}

// ipsToStringSlice converts a slice of net.IP to a slice of string
func ipsToStringSlice(ips []net.IP) []string {
	ipStrings := make([]string, len(ips))
	for i, ip := range ips {
		ipStrings[i] = ip.String()
	}
	return ipStrings
}

// WriteToFile writes the output to a file
func (s *Scanner) WriteToFile(subdomains []string) error {
	file, err := os.Create(s.config.OutputFile)
	if err != nil {
		return err
	}
	defer file.Close()

	writer := bufio.NewWriter(file)
	defer writer.Flush()

	for _, subdomain := range subdomains {
		_, err := writer.WriteString(subdomain + s.config.OutputSeparator + "\n")
		if err != nil {
			return err
		}
	}

	return nil
}

// LoadWordlist loads subdomains from a wordlist file
func LoadWordlist(wordlistFile string) ([]string, error) {
	var subdomains []string

	file, err := os.Open(wordlistFile)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		subdomain := strings.TrimSpace(scanner.Text())
		if subdomain != "" {
			subdomains = append(subdomains, subdomain)
		}
	}

	if err := scanner.Err(); err != nil {
		return nil, err
	}

	return subdomains, nil
}

// chunkSubdomains divides the subdomains into batches
func chunkSubdomains(subdomains []string, batchSize int) [][]string {
	var batches [][]string
	for i := 0; i < len(subdomains); i += batchSize {
		end := i + batchSize
		if end > len(subdomains) {
			end = len(subdomains)
		}
		batches = append(batches, subdomains[i:end])
	}
	return batches
}

func main() {
	// Parse command line flags
	domainPtr := flag.String("d", "", "Domain to scan subdomains for")
	threadsPtr := flag.Int("t", 100, "Number of concurrent threads")
	timeoutPtr := flag.Duration("timeout", 2*time.Second, "Timeout for DNS resolution")
	retryPtr := flag.Int("retry", 2, "Number of retry attempts for DNS resolution")
	retryWaitPtr := flag.Duration("retry-wait", 100*time.Millisecond, "Wait duration between retry attempts")
	outputFilePtr := flag.String("o", "", "Output file to save results")
	outputSeparatorPtr := flag.String("separator", ",", "Separator for output entries")
	wordlistFilePtr := flag.String("w", "", "Custom wordlist file for subdomain enumeration")
	rateLimitPtr := flag.Int("rate-limit", 200, "Rate limit for DNS queries (queries per second)")
	batchSizePtr := flag.Int("batch-size", 50, "Batch size for concurrent DNS resolutions")
	statusCodePtr := flag.Bool("status-code", false, "Check HTTP status code of subdomains")
	titlePtr := flag.Bool("title", false, "Retrieve title of subdomains")
	flag.Parse()

	if *domainPtr == "" {
		fmt.Println("Usage: xorn -d <domain> [-t <threads>] [--timeout <timeout>] [--retry <retry>] [--retry-wait <retry-wait>] [-o <output-file>] [--separator <separator>] [-w <wordlist-file>] [--rate-limit <rate-limit>] [--batch-size <batch-size>] [--status-code] [--title]")
		return
	}

	config := Config{
		Domain:          *domainPtr,
		Threads:         *threadsPtr,
		Timeout:         *timeoutPtr,
		Retry:           *retryPtr,
		RetryWait:       *retryWaitPtr,
		OutputFile:      *outputFilePtr,
		OutputSeparator: *outputSeparatorPtr,
		WordlistFile:    *wordlistFilePtr,
		RateLimit:       *rateLimitPtr,
		BatchSize:       *batchSizePtr,
		StatusCode:      *statusCodePtr,
		Title:           *titlePtr,
	}

	var subdomains []string

	// Load subdomains from wordlist file if provided
	if config.WordlistFile != "" {
		loadedSubdomains, err := LoadWordlist(config.WordlistFile)
		if err != nil {
			fmt.Println("Error loading wordlist file:", err)
			return
		}
		// Append domain to each subdomain
		for _, subdomain := range loadedSubdomains {
			subdomains = append(subdomains, subdomain+"."+config.Domain)
		}
	} else {
		fmt.Println("Error: No wordlist file provided")
		return
	}

	// Create and run subdomain scanner
	scanner := NewScanner(config)
	foundSubdomains := scanner.ScanSubdomains(subdomains)

	// Output found subdomains
	if len(foundSubdomains) > 0 {
		fmt.Println("Found subdomains:")
		for _, subdomain := range foundSubdomains {
			fmt.Println(subdomain)
		}
	} else {
		fmt.Println("No subdomains found.")
	}

	// Write to output file if specified
	if config.OutputFile != "" {
		err := scanner.WriteToFile(foundSubdomains)
		if err != nil {
			fmt.Println("Error writing to output file:", err)
		} else {
			fmt.Println("Results saved to", config.OutputFile)
		}
	}
}
