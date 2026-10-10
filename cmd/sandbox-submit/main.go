// Command sandbox-submit sends one job frame to a running
// sandbox-executord and prints its response. It is the operator's
// submission path: peer-uid authentication is handled by the kernel,
// the shared token proves this process, and -envelope supplies the
// authority-signed contract produced by sandbox-job-sign.
//
// Usage:
//
//	sandbox-submit -socket /run/sx/executor.sock -token T -envelope env.json
//	sandbox-submit -socket /run/sx/executor.sock -token T -job unsigned.json
package main

import (
	"bufio"
	"encoding/json"
	"flag"
	"fmt"
	"net"
	"os"
	"time"
)

func main() {
	socket := flag.String("socket", os.Getenv("SANDBOX_EXECUTOR_SOCKET"), "executor.sock path (or SANDBOX_EXECUTOR_SOCKET)")
	token := flag.String("token", os.Getenv("SANDBOX_EXECUTOR_TOKEN"), "shared submission token (or SANDBOX_EXECUTOR_TOKEN)")
	envelope := flag.String("envelope", "", "JSON file containing {\"signed_job\":{contract,signature}}")
	job := flag.String("job", "", "JSON file containing an unsigned job object")
	timeout := flag.Duration("timeout", 35*time.Second, "response wait bound")
	flag.Parse()

	if (*envelope == "") == (*job == "") {
		fmt.Fprintln(os.Stderr, "sandbox-submit: exactly one of -envelope or -job is required")
		os.Exit(2)
	}
	req := map[string]any{"version": 1, "type": "submit"}
	if *token != "" {
		req["token"] = *token
	}
	var file string
	var field string
	if *envelope != "" {
		file, field = *envelope, "signed_job"
	} else {
		file, field = *job, "job"
	}
	data, err := os.ReadFile(file)
	if err != nil {
		fmt.Fprintf(os.Stderr, "sandbox-submit: %v\n", err)
		os.Exit(1)
	}
	var payload map[string]json.RawMessage
	if err := json.Unmarshal(data, &payload); err != nil {
		fmt.Fprintf(os.Stderr, "sandbox-submit: parse %s: %v\n", file, err)
		os.Exit(1)
	}
	inner, ok := payload[field]
	if !ok {
		// Allow the file to be the bare object too.
		inner = json.RawMessage(data)
	}
	req[field] = inner

	conn, err := net.DialTimeout("unix", *socket, 5*time.Second)
	if err != nil {
		fmt.Fprintf(os.Stderr, "sandbox-submit: dial %s: %v\n", *socket, err)
		os.Exit(1)
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(*timeout))
	frame, err := json.Marshal(req)
	if err != nil {
		fmt.Fprintf(os.Stderr, "sandbox-submit: %v\n", err)
		os.Exit(1)
	}
	if _, err := conn.Write(append(frame, '\n')); err != nil {
		fmt.Fprintf(os.Stderr, "sandbox-submit: write: %v\n", err)
		os.Exit(1)
	}
	line, err := bufio.NewReader(conn).ReadBytes('\n')
	if err != nil {
		fmt.Fprintf(os.Stderr, "sandbox-submit: read response: %v\n", err)
		os.Exit(1)
	}
	fmt.Print(string(line))
}
