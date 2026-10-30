// gotls: one HTTPS GET per host with Go's standard library, so the result
// shows what crypto/x509 in the Go version that built it accepts. On Linux,
// Go reads SSL_CERT_FILE / SSL_CERT_DIR for its roots.
package main

import (
	"fmt"
	"net/http"
	"os"
	"runtime"
	"time"
)

func main() {
	ua := "emudhra-trust-store-check/1.0 (+https://github.com/The-DevOps-Daily/emudhra-trust-store-check)"
	c := &http.Client{Timeout: 20 * time.Second}
	for _, h := range os.Args[1:] {
		req, _ := http.NewRequest("GET", "https://"+h+"/", nil)
		req.Header.Set("User-Agent", ua)
		r, err := c.Do(req)
		if err != nil {
			fmt.Printf("%s\t%s\treject\t%v\n", runtime.Version(), h, err)
			continue
		}
		r.Body.Close()
		fmt.Printf("%s\t%s\tACCEPT\tHTTP %d\n", runtime.Version(), h, r.StatusCode)
	}
}
