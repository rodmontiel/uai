package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"os"
	"os/signal"
	"strings"
	"syscall"

	"github.com/rodmontiel/uai/internal/keyfile"
	uai "github.com/rodmontiel/uai/sdk/go"
)

// serverInfo identifies this implementation to the client.
var serverInfo = map[string]any{
	"name": "uai-mcp", "title": "Universal Agent Identity", "version": "0.1.0",
}

func main() {
	var (
		endpoint = flag.String("endpoint", envOr("UAI_ENDPOINT", "http://127.0.0.1:8080"),
			"base URL of the UAI gateway")
		uaiID = flag.String("uai-id", os.Getenv("UAI_AGENT_ID"),
			"the UAI-ID this server signs as")
		keyPath = flag.String("key", envOr("UAI_AGENT_KEY", ".keys/agent.jwk"),
			"path to the agent's signing key")
		ownerDID = flag.String("owner-did", os.Getenv("UAI_OWNER_DID"),
			"DID of the owner recorded in attestations")
		ca = flag.String("ca", envOr("UAI_API_CA", ""),
			"PEM CA bundle to verify an https gateway with")
	)
	flag.Parse()

	// Logs go to stderr, always. stdout is the JSON-RPC channel: one stray line
	// there and every message after it is unparseable to the client.
	logger := log.New(os.Stderr, "uai-mcp ", log.LstdFlags|log.LUTC)

	if *uaiID == "" {
		logger.Fatal("no identity: set UAI_AGENT_ID or pass -uai-id. " +
			"This server signs as exactly one agent and will not guess which.")
	}
	signer, err := keyfile.Load(*keyPath, didOf(*uaiID)+"#key-1")
	if err != nil {
		// Refusing to start beats starting without a key: a server that came up
		// unable to sign would fail at the first tool call, inside whatever task
		// the agent was doing, instead of here where an operator is looking.
		logger.Fatalf("no signing key at %s: %v", *keyPath, err)
	}
	opts := []uai.Option{uai.WithOwnerDID(*ownerDID)}
	if *ca != "" {
		opts = append(opts, uai.WithCA(*ca))
	}
	client, err := uai.New(*endpoint, *uaiID, signer, opts...)
	if err != nil {
		logger.Fatalf("client: %v", err)
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	logger.Printf("serving %d tools as %s against %s", len(tools()), *uaiID, *endpoint)
	if err := serve(ctx, newConn(os.Stdin, os.Stdout), client, logger); err != nil &&
		!errors.Is(err, io.EOF) && !errors.Is(err, context.Canceled) {
		logger.Fatalf("serve: %v", err)
	}
}

// server holds per-session state.
type server struct {
	client      *uai.Client
	logger      *log.Logger
	byName      map[string]Tool
	initialized bool
}

// serve runs the JSON-RPC loop.
func serve(ctx context.Context, c *conn, client *uai.Client, logger *log.Logger) error {
	s := &server{client: client, logger: logger, byName: map[string]Tool{}}
	for _, t := range tools() {
		s.byName[t.Name] = t
	}
	for {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		req, err := c.read()
		if errors.Is(err, io.EOF) {
			return nil
		}
		if err != nil {
			if errors.Is(err, errParse) {
				// No id to answer with, so the error cannot be correlated. It is
				// logged rather than answered, per JSON-RPC.
				logger.Printf("dropping unparseable message: %v", err)
				continue
			}
			return err
		}
		if req.JSONRPC != "2.0" {
			if !req.isNotification() {
				_ = c.replyError(req.ID, codeInvalidRequest, "jsonrpc must be \"2.0\"", nil)
			}
			continue
		}
		s.dispatch(ctx, c, req)
	}
}

func (s *server) dispatch(ctx context.Context, c *conn, req request) {
	switch req.Method {
	case "initialize":
		s.initialize(c, req)
	case "notifications/initialized":
		s.initialized = true
	case "ping":
		_ = c.reply(req.ID, map[string]any{})
	case "tools/list":
		_ = c.reply(req.ID, map[string]any{"tools": s.list()})
	case "tools/call":
		s.call(ctx, c, req)
	default:
		if req.isNotification() {
			return
		}
		_ = c.replyError(req.ID, codeMethodNotFound, "unknown method: "+req.Method, nil)
	}
}

func (s *server) initialize(c *conn, req request) {
	var params struct {
		ProtocolVersion string `json:"protocolVersion"`
	}
	_ = json.Unmarshal(req.Params, &params)

	version := protocolVersions[0]
	for _, v := range protocolVersions {
		if v == params.ProtocolVersion {
			version = v
			break
		}
	}
	_ = c.reply(req.ID, map[string]any{
		"protocolVersion": version,
		"capabilities":    map[string]any{"tools": map[string]any{"listChanged": false}},
		"serverInfo":      serverInfo,
		// Read by the model, so it says the one thing a model must not get
		// wrong about this server.
		"instructions": "Every tool call here runs under one agent identity and is subject to the " +
			"same guardrail as any other action. No tool grants capabilities: " +
			"uai_request_capability creates a request that a human owner decides out of band. " +
			"A DENY from uai_check_policy is a refusal, not a suggestion.",
	})
}

// list renders the tool table for tools/list.
func (s *server) list() []map[string]any {
	out := make([]map[string]any, 0, len(s.byName))
	for _, t := range tools() {
		out = append(out, map[string]any{
			"name": t.Name, "title": t.Title, "description": t.Description,
			"inputSchema": t.Schema,
			"annotations": map[string]any{
				"readOnlyHint":    t.ReadOnly,
				"destructiveHint": false,
				"openWorldHint":   true,
			},
		})
	}
	return out
}

func (s *server) call(ctx context.Context, c *conn, req request) {
	var params struct {
		Name      string          `json:"name"`
		Arguments json.RawMessage `json:"arguments"`
	}
	if err := json.Unmarshal(req.Params, &params); err != nil {
		_ = c.replyError(req.ID, codeInvalidParams, "params must be an object with name and arguments", nil)
		return
	}
	tool, found := s.byName[params.Name]
	if !found {
		_ = c.replyError(req.ID, codeMethodNotFound, "unknown tool: "+params.Name, nil)
		return
	}
	if len(params.Arguments) == 0 {
		params.Arguments = json.RawMessage("{}")
	}

	result, err := tool.Handle(ctx, s.client, params.Arguments)
	if err != nil {
		// A tool failure is a tool result with isError, not a protocol error.
		// The distinction matters: the model must see what went wrong and be
		// able to act on it, and a JSON-RPC error would reach the framework
		// instead of the model.
		_ = c.reply(req.ID, toolResult(map[string]any{
			"error": err.Error(),
			"note":  "This is a refusal or a failure from UAI, not a transport problem.",
		}, true))
		return
	}
	_ = c.reply(req.ID, toolResult(result, false))
}

// toolResult renders an MCP tool result.
//
// The payload is returned as text AND as structuredContent: a framework that
// understands the second gets typed data, and one that does not still shows the
// model something it can read.
func toolResult(v any, isError bool) map[string]any {
	raw, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		raw = []byte(fmt.Sprintf("%v", v))
	}
	out := map[string]any{
		"content": []map[string]any{{"type": "text", "text": string(raw)}},
		"isError": isError,
	}
	if m, ok := v.(map[string]any); ok {
		out["structuredContent"] = m
	}
	return out
}

// didOf turns a UAI-ID into its DID.
func didOf(uaiID string) string {
	if strings.HasPrefix(uaiID, "did:") {
		return uaiID
	}
	return "did:" + uaiID
}

func envOr(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}
