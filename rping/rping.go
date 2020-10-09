package main

import (
	"flag"
	"fmt"
)

var (
	payload = flag.String("payload", "[ProtaX", "ICMP payload")
	ip      = flag.String("ip", "127.0.0.1", "Destination ip address")
	count   = flag.Int("c", 1, "Number of ICMP requests")
)

func main() {
	flag.Parse()

	err := Ping(*ip, *count, []byte(*payload))
	if err != nil {
		fmt.Println(err)
	}
}
