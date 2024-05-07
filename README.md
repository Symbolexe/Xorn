# xorn
![Xorn Tool](https://github.com/Symbolexe/xorn/assets/140549630/c965deb0-6116-4249-8033-a4e5bd055e3f)
Xorn is a versatile subdomain scanner tool written in Go. It enables you to discover subdomains of a given domain by performing DNS resolution, and optionally checking HTTP status codes and retrieving titles of web pages associated with the subdomains.
## Features
### Subdomain Enumeration
Xorn efficiently enumerates subdomains by performing DNS resolution for a given domain. It can handle large wordlists and parallelize the scanning process to improve performance.
### DNS Resolution
The tool resolves subdomains to their corresponding IP addresses using the DNS lookup mechanism. It provides configurable options for timeout, retry attempts, and retry wait duration to fine-tune the resolution process.
### HTTP Status Code Checking
Xorn optionally checks the HTTP status codes of the discovered subdomains. This feature allows you to identify active subdomains and determine their accessibility.
### Title Retrieval
Additionally, Xorn can retrieve the titles of web pages associated with the discovered subdomains. This information provides insights into the content hosted on each subdomain.
### Rate Limiting
To avoid overwhelming the DNS servers, Xorn implements rate limiting for DNS queries. You can configure the rate limit to control the number of queries per second.
### Custom Wordlist
You can supply a custom wordlist file containing potential subdomains to scan. Xorn appends the domain name to each entry in the wordlist for enumeration.
### Output Options
Xorn provides flexible options for outputting the scan results. You can save the results to a file, specifying the output format and separator.
## Installation
### From Source
1. Ensure you have Go installed. Download it from [here](https://golang.org/dl/).
2. Clone the repository:

   ```git clone https://github.com/symbolexe/Xorn.git```
3. Navigate to the cloned directory:

   ```cd Xorn```
4. Build the tool:

   ```go build```
5. Optionally, move the binary to a directory in your PATH:

   ```sudo mv xorn /usr/local/bin/```
## From Releases
Download precompiled binaries from the Releases section of this repository. Choose the appropriate binary for your operating system and architecture and download it. Then, move the binary to a directory in your PATH.
## Usage
Xorn provides a wide range of options to customize the scanning process. Here's how you can use it

```xorn -d <domain> [options]```
## Options
1. -d <domain>: Specifies the domain to scan subdomains for.
2. -t <threads>: Number of concurrent threads (default is 100).
3. --timeout <timeout>: Timeout for DNS resolution (default is 2 seconds).
4. --retry <retry>: Number of retry attempts for DNS resolution (default is 2).
5. --retry-wait <retry-wait>: Wait duration between retry attempts (default is 100 milliseconds).
6. -o <output-file>: Output file to save results.
7. --separator <separator>: Separator for output entries (default is ,).
8. -w <wordlist-file>: Custom wordlist file for subdomain enumeration.
9. --rate-limit <rate-limit>: Rate limit for DNS queries (queries per second, default is 200).
10. --batch-size <batch-size>: Batch size for concurrent DNS resolutions (default is 50).
11. --status-code: Check HTTP status code of subdomains.
12. --title: Retrieve title of subdomains.
## Example
```xorn -d example.com -w wordlist.txt -o subdomains.txt --status-code --title```

This command scans subdomains of example.com using the wordlist wordlist.txt, saves the results to subdomains.txt, and checks HTTP status codes and retrieves titles of web pages associated with the subdomains.
