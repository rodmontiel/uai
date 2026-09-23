package chain

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"net/http"
	"strings"
	"time"
)

// Errors a caller distinguishes.
var (
	// ErrReverted means the transaction executed and the contract refused it.
	// It is separated from a transport failure on purpose: a revert is the
	// ledger doing its job, and retrying it forever would turn a correct
	// refusal into an outage.
	ErrReverted = errors.New("chain: transaction reverted")
	// ErrUnavailable means the endpoint could not be reached.
	ErrUnavailable = errors.New("chain: endpoint unavailable")
)

// Client is a minimal JSON-RPC client.
//
// It signs nothing. UAI's consortium deployment uses an account the node
// already holds — a permissioned validator set with an unlocked writer key —
// so transaction signing belongs to the node's keystore or an HSM rather than
// to this process. A service that held a chain private key would be a service
// worth stealing.
type Client struct {
	url     string
	from    string
	http    *http.Client
	chainID uint64
}

// New builds a client.
func New(url, from string, chainID uint64) *Client {
	return &Client{
		url: url, from: from, chainID: chainID,
		http: &http.Client{Timeout: 20 * time.Second},
	}
}

// ChainID is the network this client writes to, recorded on every anchor so a
// reader can tell which ledger an event came from.
func (c *Client) ChainID() uint64 { return c.chainID }

type rpcRequest struct {
	JSONRPC string `json:"jsonrpc"`
	ID      int    `json:"id"`
	Method  string `json:"method"`
	Params  []any  `json:"params"`
}

type rpcError struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
	Data    any    `json:"data,omitempty"`
}

type rpcResponse struct {
	Result json.RawMessage `json:"result"`
	Error  *rpcError       `json:"error"`
}

func (c *Client) call(ctx context.Context, method string, params ...any) (json.RawMessage, error) {
	if params == nil {
		params = []any{}
	}
	body, err := json.Marshal(rpcRequest{JSONRPC: "2.0", ID: 1, Method: method, Params: params})
	if err != nil {
		return nil, err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.url, bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := c.http.Do(req)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrUnavailable, err)
	}
	defer resp.Body.Close()
	var out rpcResponse
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		return nil, fmt.Errorf("%w: %v", ErrUnavailable, err)
	}
	if out.Error != nil {
		// A revert arrives as an ordinary JSON-RPC error. Telling it apart from
		// a transport failure is what lets the writer retry one and record the
		// other.
		if strings.Contains(strings.ToLower(out.Error.Message), "revert") ||
			strings.Contains(strings.ToLower(out.Error.Message), "execution reverted") {
			return nil, fmt.Errorf("%w: %s", ErrReverted, out.Error.Message)
		}
		return nil, fmt.Errorf("chain: %s: %s", method, out.Error.Message)
	}
	return out.Result, nil
}

// Send submits a transaction carrying call data and waits for its receipt.
func (c *Client) Send(ctx context.Context, to string, data []byte) (Receipt, error) {
	var txHash string
	raw, err := c.call(ctx, "eth_sendTransaction", map[string]string{
		"from": c.from, "to": to, "data": Hex(data),
	})
	if err != nil {
		return Receipt{}, err
	}
	if err := json.Unmarshal(raw, &txHash); err != nil {
		return Receipt{}, err
	}
	return c.waitForReceipt(ctx, txHash)
}

// Receipt is what a transaction produced.
type Receipt struct {
	TxHash      string
	BlockNumber uint64
	Success     bool
}

func (c *Client) waitForReceipt(ctx context.Context, txHash string) (Receipt, error) {
	deadline := time.Now().Add(30 * time.Second)
	for {
		raw, err := c.call(ctx, "eth_getTransactionReceipt", txHash)
		if err != nil {
			return Receipt{}, err
		}
		var got struct {
			BlockNumber string `json:"blockNumber"`
			Status      string `json:"status"`
		}
		if len(raw) > 0 && string(raw) != "null" {
			if err := json.Unmarshal(raw, &got); err != nil {
				return Receipt{}, err
			}
			block, err := parseQuantity(got.BlockNumber)
			if err != nil {
				return Receipt{}, err
			}
			r := Receipt{TxHash: txHash, BlockNumber: block, Success: got.Status == "0x1"}
			if !r.Success {
				// Mined and refused. The contract said no, and that is a fact
				// to record rather than an operation to retry.
				return r, fmt.Errorf("%w: %s", ErrReverted, txHash)
			}
			return r, nil
		}
		if time.Now().After(deadline) {
			return Receipt{}, fmt.Errorf("chain: %s was not mined within the deadline", txHash)
		}
		select {
		case <-ctx.Done():
			return Receipt{}, ctx.Err()
		case <-time.After(200 * time.Millisecond):
		}
	}
}

// Deploy publishes a contract and returns its address.
func (c *Client) Deploy(ctx context.Context, bytecode []byte, args ...Word) (string, error) {
	data := append([]byte(nil), bytecode...)
	for _, a := range args {
		data = append(data, a[:]...)
	}
	var txHash string
	// No explicit gas: the node estimates it. A hardcoded limit is either too
	// low for a large contract or above the block limit, and both fail in ways
	// that read as a chain problem rather than a configuration one.
	raw, err := c.call(ctx, "eth_sendTransaction", map[string]string{
		"from": c.from, "data": Hex(data),
	})
	if err != nil {
		return "", err
	}
	if err := json.Unmarshal(raw, &txHash); err != nil {
		return "", err
	}
	if _, err := c.waitForReceipt(ctx, txHash); err != nil {
		return "", err
	}
	raw, err = c.call(ctx, "eth_getTransactionReceipt", txHash)
	if err != nil {
		return "", err
	}
	var got struct {
		ContractAddress string `json:"contractAddress"`
	}
	if err := json.Unmarshal(raw, &got); err != nil {
		return "", err
	}
	if got.ContractAddress == "" {
		return "", errors.New("chain: deployment produced no contract address")
	}
	return got.ContractAddress, nil
}

// CallView performs a read-only call.
func (c *Client) CallView(ctx context.Context, to string, data []byte) ([]byte, error) {
	raw, err := c.call(ctx, "eth_call", map[string]string{"to": to, "data": Hex(data)}, "latest")
	if err != nil {
		return nil, err
	}
	var out string
	if err := json.Unmarshal(raw, &out); err != nil {
		return nil, err
	}
	return hex.DecodeString(strings.TrimPrefix(out, "0x"))
}

// Accounts lists the accounts the node holds.
func (c *Client) Accounts(ctx context.Context) ([]string, error) {
	raw, err := c.call(ctx, "eth_accounts")
	if err != nil {
		return nil, err
	}
	var out []string
	return out, json.Unmarshal(raw, &out)
}

func parseQuantity(s string) (uint64, error) {
	s = strings.TrimPrefix(s, "0x")
	if s == "" {
		return 0, nil
	}
	n, ok := new(big.Int).SetString(s, 16)
	if !ok {
		return 0, fmt.Errorf("chain: %q is not a hex quantity", s)
	}
	if !n.IsUint64() {
		return 0, fmt.Errorf("chain: quantity %s does not fit in uint64", n)
	}
	return n.Uint64(), nil
}
