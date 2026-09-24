// Command uai-mcp exposes UAI to an agent framework as an MCP server.
//
// It speaks JSON-RPC 2.0 over stdio, newline-delimited, with no dependencies:
// this process holds the agent's signing key and stands between a model and a
// registry of record, so every library linked into it is a library that could
// sign on the agent's behalf (T-07).
//
// # The rule this server exists to respect
//
// §22.9: no MCP tool grants capabilities. An MCP server runs under the calling
// agent's identity, so a tool that could widen that identity's privileges would
// be a confused-deputy generator — the model asks for more, the server has the
// key, and the boundary the owner set is gone (T-11/T-13). uai_request_capability
// therefore creates a pending request and nothing else. The constraint is kept in
// three places that would each have to fail together: there is no tool that
// grants, there is no API route that grants, and the database refuses a grant
// signed by the agent itself.
package main

import (
	"bufio"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"sync"
)

// protocolVersions are the MCP revisions this server implements, newest first.
//
// The negotiated version is echoed back when the client asks for one we
// implement, and the newest one otherwise. Agreeing to a version we do not
// implement would produce a session that fails later, at a call, instead of now.
var protocolVersions = []string{"2025-06-18", "2025-03-26", "2024-11-05"}

// request is a JSON-RPC 2.0 request or notification.
//
// ID is a json.RawMessage because the spec allows a string or a number and the
// response must echo the exact value: normalising it would break a client that
// correlates on the literal.
type request struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      json.RawMessage `json:"id,omitempty"`
	Method  string          `json:"method"`
	Params  json.RawMessage `json:"params,omitempty"`
}

// isNotification reports whether no response may be sent.
func (r request) isNotification() bool { return len(r.ID) == 0 || string(r.ID) == "null" }

type response struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      json.RawMessage `json:"id"`
	Result  any             `json:"result,omitempty"`
	Error   *rpcError       `json:"error,omitempty"`
}

type rpcError struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
	Data    any    `json:"data,omitempty"`
}

// JSON-RPC 2.0 error codes.
const (
	codeParse          = -32700
	codeInvalidRequest = -32600
	codeMethodNotFound = -32601
	codeInvalidParams  = -32602
	codeInternal       = -32603
)

// conn is a JSON-RPC connection over a byte stream.
type conn struct {
	in  *bufio.Scanner
	out io.Writer
	mu  sync.Mutex
}

// maxLine caps one JSON-RPC message. A framework that sent an unbounded line
// would otherwise exhaust this process, which holds a signing key.
const maxLine = 8 << 20

func newConn(r io.Reader, w io.Writer) *conn {
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 0, 64<<10), maxLine)
	return &conn{in: sc, out: w}
}

// read returns the next message, or io.EOF.
func (c *conn) read() (request, error) {
	for c.in.Scan() {
		line := c.in.Bytes()
		if len(line) == 0 {
			continue
		}
		var req request
		if err := json.Unmarshal(line, &req); err != nil {
			return request{}, fmt.Errorf("%w: %v", errParse, err)
		}
		return req, nil
	}
	if err := c.in.Err(); err != nil {
		return request{}, err
	}
	return request{}, io.EOF
}

var errParse = errors.New("mcp: message is not JSON")

// write sends one message. Writes are serialized because a tool handler may
// answer while another is still streaming, and interleaved JSON is unparseable.
func (c *conn) write(v any) error {
	raw, err := json.Marshal(v)
	if err != nil {
		return err
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if _, err := c.out.Write(append(raw, '\n')); err != nil {
		return err
	}
	return nil
}

func (c *conn) reply(id json.RawMessage, result any) error {
	return c.write(response{JSONRPC: "2.0", ID: id, Result: result})
}

func (c *conn) replyError(id json.RawMessage, code int, msg string, data any) error {
	return c.write(response{JSONRPC: "2.0", ID: id, Error: &rpcError{Code: code, Message: msg, Data: data}})
}
