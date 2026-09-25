package main

import (
	"io"
	"log"
	"net"
	"net/http"

	"github.com/cnuss/libtunnel"
)

func main() {
	lis, err := net.Listen("tcp", ":0")
	if err != nil {
		log.Fatalf("Error creating listener: %v", err)
	}

	var hello = "Hello, World!"

	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(hello))
	})
	go http.Serve(lis, mux)

	tun1 := libtunnel.New(libtunnel.Cloudflare().WithProvider("api.trycloudflare.com")).WithListener(lis)
	url1 := tun1.URL().String()
	log.Printf("tun1 url: %s", url1)

	resp1 := fetch(url1)
	if resp1 != hello {
		log.Fatalf("Unexpected response: got %q, want %q", resp1, hello)
	}
	// Wait for Done, not just Cancel: the edge has then been told tun1 is
	// gone, and tun2 registers on a clean tunnel.
	tun1.Cancel()
	<-tun1.Done()

	spec := tun1.Serialize()
	log.Printf("tun1 spec: %+v", spec)

	tun2 := libtunnel.From(spec).WithListener(lis)
	url2 := tun2.URL().String()
	log.Printf("tun2 url: %s", url2)

	if url2 != url1 {
		log.Fatalf("Unexpected URL: got %q, want %q", url2, url1)
	}
	resp2 := fetch(url2)
	if resp2 != hello {
		log.Fatalf("Unexpected response: got %q, want %q", resp2, hello)
	}
	tun2.Cancel()
	<-tun2.Done()
}

func fetch(url string) string {
	r, err := http.Get(url)
	if err != nil {
		log.Printf("Error fetching URL %q: %v", url, err)
		return ""
	}
	defer r.Body.Close()
	b, err := io.ReadAll(r.Body)
	if err != nil {
		log.Printf("Error reading response body from URL %q: %v", url, err)
		return ""
	}
	return string(b)
}
