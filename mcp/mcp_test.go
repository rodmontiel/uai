package main

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"log"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"

	"github.com/rodmontiel/uai/pkg/uaicrypto"
	uai "github.com/rodmontiel/uai/sdk/go"
)

// TestTheEightToolsOfSection229 pins the surface. §22.9 lists eight tools; a
// ninth that appeared without a spec change would be a capability nobody
// reviewed, and a missing one would be a documented feature that is not there.
func TestTheEightToolsOfSection229(t *testing.T) {
	want := []string{
		"uai_attest_action", "uai_check_policy", "uai_register", "uai_report_incident",
		"uai_request_capability", "uai_get_status", "uai_verify_identity", "uai_verify_passport",
	}
	sort.Strings(want)
	var got []string
	for _, tool := range tools() {
		got = append(got, tool.Name)
	}
	sort.Strings(got)
	if strings.Join(got, ",") != strings.Join(want, ",") {
		t.Fatalf("tool surface drifted\n got: %v\nwant: %v", got, want)
	}
}

// TestNoToolGrantsCapabilities is the §22.9 hard rule as a build gate.
//
// An MCP server runs under the calling agent's identity. A tool that could
// widen that identity's privileges would be a confused-deputy generator
// (T-11/T-13): the model asks for more, the server holds the key, and the
// boundary the owner set is gone.
func TestNoToolGrantsCapabilities(t *testing.T) {
	for _, tool := range tools() {
		if tool.Grants {
			t.Errorf("%s declares that it grants capabilities. §22.9 forbids it: approval is an "+
				"act by the human owner, out of band.", tool.Name)
		}
	}
}

// TestNoGrantPathIsReachableFromHere is the same rule one level down: the tool
// table can only be trusted if nothing under it can write a grant either.
//
// It reads the sources of this package and of the SDK it calls. A handler that
// reached a grant-writing path would have to name it, and naming it fails here
// before any reviewer has to notice.
func TestNoGrantPathIsReachableFromHere(t *testing.T) {
	forbidden := []string{"capability_grants", "GrantCapability"}
	for _, dir := range []string{".", "../sdk/go"} {
		entries, err := os.ReadDir(dir)
		if err != nil {
			t.Fatal(err)
		}
		for _, e := range entries {
			if e.IsDir() || !strings.HasSuffix(e.Name(), ".go") || strings.HasSuffix(e.Name(), "_test.go") {
				continue
			}
			body, err := os.ReadFile(filepath.Join(dir, e.Name()))
			if err != nil {
				t.Fatal(err)
			}
			for _, needle := range forbidden {
				if bytes.Contains(body, []byte(needle)) {
					t.Errorf("%s/%s references %q. Nothing an agent can reach may write a capability grant.",
						dir, e.Name(), needle)
				}
			}
		}
	}
}

// TestRequestCapabilityAnswersWithARequest exercises the tool end to end
// against a gateway that answers as the real one does, and asserts the model
// cannot read the answer as a grant.
func TestRequestCapabilityAnswersWithARequest(t *testing.T) {
	var gotPath string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotPath = r.URL.Path
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusAccepted)
		_, _ = io.WriteString(w, `{"request_id":"capreq-01J","capability":"payments.transfer",
			"state":"PENDING","granted":false,"requested_at":"2026-09-23T00:00:00Z",
			"expires_at":"2026-10-23T00:00:00Z",
			"note":"This is a request, not a grant."}`)
	}))
	defer srv.Close()

	out := callTool(t, srv.URL, "uai_request_capability",
		`{"capability":"payments.transfer","justification":"refund a customer"}`)

	if gotPath != "/v1/capability-requests" {
		t.Fatalf("the tool called %q, want /v1/capability-requests", gotPath)
	}
	if strings.Contains(out, `"granted": true`) {
		t.Fatal("the tool reported a grant")
	}
	for _, want := range []string{`"state": "PENDING"`, `"granted": false`, "not a grant"} {
		if !strings.Contains(out, want) {
			t.Errorf("the answer does not contain %q:\n%s", want, out)
		}
	}
}

// TestADeniedActionIsNotAttestedAsSuccess: the attest tool evaluates policy
// first, and a refusal must reach the model as a refusal.
func TestADeniedActionIsNotAttestedAsSuccess(t *testing.T) {
	var attested bool
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case "/v1/policy/evaluate":
			_, _ = io.WriteString(w, `{"decision_id":"01JD","decision":"DENY",
				"reason":"capability_not_granted","policy":{"version":"GASC-2027.4","bundle_hash":"sha256:aa"},
				"rules_fired":["capability_envelope"]}`)
		case "/v1/agents/uai:agent:01JY8R9ZAF392N7QX2T81JH6KM/events":
			_, _ = io.WriteString(w, `{"events":[],"head":{"hash":"sha256:bb","sequence":1}}`)
		case "/v1/actions/attest":
			attested = true
			_, _ = io.WriteString(w, `{"event_id":"evt-1","event_hash":"sha256:cc","sequence":2,
				"transparency":"LOGGED"}`)
		default:
			t.Errorf("unexpected path %s", r.URL.Path)
		}
	}))
	defer srv.Close()

	out := callTool(t, srv.URL, "uai_attest_action",
		`{"capability":"payments.transfer","purpose":"refund","outcome":"SUCCESS","origin":"AR"}`)

	if strings.Contains(out, `"outcome": "SUCCESS"`) {
		t.Fatalf("a denied action was attested as SUCCESS:\n%s", out)
	}
	if !strings.Contains(out, "ABORTED_BY_POLICY") {
		t.Errorf("the refusal was not recorded as ABORTED_BY_POLICY:\n%s", out)
	}
	if !strings.Contains(out, `"refused": true`) {
		t.Errorf("the model is not told the action was refused:\n%s", out)
	}
	// The refusal itself IS attested: a refusal nobody wrote down is
	// indistinguishable from a request nobody made.
	if !attested {
		t.Error("the refusal was never recorded in the agent's own chain")
	}
}

// TestSaltsComeBackToTheCaller: UAI never holds them, so if the SDK did not
// return them the commitments would be openable by nobody -- which is the same
// as not having recorded anything.
func TestSaltsComeBackToTheCaller(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case "/v1/policy/evaluate":
			_, _ = io.WriteString(w, `{"decision_id":"01JD","decision":"ALLOW","reason":"within_envelope",
				"policy":{"version":"GASC-2027.4","bundle_hash":"sha256:aa"}}`)
		case "/v1/actions/attest":
			// The commitment must be a digest, never the content.
			body, _ := io.ReadAll(r.Body)
			if bytes.Contains(body, []byte("the customer email")) {
				t.Error("the input text was sent to the gateway; only a commitment may leave the process")
			}
			_, _ = io.WriteString(w, `{"event_id":"evt-1","event_hash":"sha256:cc","sequence":2,
				"transparency":"LOGGED"}`)
		default:
			_, _ = io.WriteString(w, `{"events":[],"head":{"hash":"sha256:bb","sequence":1}}`)
		}
	}))
	defer srv.Close()

	out := callTool(t, srv.URL, "uai_attest_action",
		`{"capability":"crm.customer.read","purpose":"support","outcome":"SUCCESS",`+
			`"origin":"AR","input_summary":"the customer email","output_summary":"one record"}`)

	for _, want := range []string{"input_salt_hex", "output_salt_hex", "Keep these salts"} {
		if !strings.Contains(out, want) {
			t.Errorf("the answer is missing %q:\n%s", want, out)
		}
	}
}

// TestProtocolHandshake exercises the JSON-RPC surface: initialize, tools/list
// and an unknown method, over a real pipe.
func TestProtocolHandshake(t *testing.T) {
	in := strings.NewReader(strings.Join([]string{
		`{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-03-26"}}`,
		`{"jsonrpc":"2.0","method":"notifications/initialized"}`,
		`{"jsonrpc":"2.0","id":2,"method":"tools/list"}`,
		`{"jsonrpc":"2.0","id":3,"method":"nope/nope"}`,
		`not json at all`,
		`{"jsonrpc":"2.0","id":4,"method":"ping"}`,
	}, "\n") + "\n")
	var out bytes.Buffer

	client := testClient(t, "http://127.0.0.1:1")
	if err := serve(context.Background(), newConn(in, &out), client,
		log.New(io.Discard, "", 0)); err != nil {
		t.Fatal(err)
	}

	lines := strings.Split(strings.TrimSpace(out.String()), "\n")
	if len(lines) != 4 {
		t.Fatalf("got %d responses, want 4 (the notification and the garbage line get none)\n%s",
			len(lines), out.String())
	}

	var initResp struct {
		Result struct {
			ProtocolVersion string `json:"protocolVersion"`
			Instructions    string `json:"instructions"`
		} `json:"result"`
	}
	if err := json.Unmarshal([]byte(lines[0]), &initResp); err != nil {
		t.Fatal(err)
	}
	// A version the client asked for and we implement is echoed back. Agreeing
	// to one we do not implement would fail later, at a call.
	if initResp.Result.ProtocolVersion != "2025-03-26" {
		t.Errorf("negotiated %q, want the version the client asked for", initResp.Result.ProtocolVersion)
	}
	// The instructions are read by the model, so the rule that matters most has
	// to be in them.
	if !strings.Contains(initResp.Result.Instructions, "No tool grants capabilities") {
		t.Errorf("the instructions do not state the rule:\n%s", initResp.Result.Instructions)
	}

	var listResp struct {
		Result struct {
			Tools []struct {
				Name        string         `json:"name"`
				InputSchema map[string]any `json:"inputSchema"`
			} `json:"tools"`
		} `json:"result"`
	}
	if err := json.Unmarshal([]byte(lines[1]), &listResp); err != nil {
		t.Fatal(err)
	}
	if len(listResp.Result.Tools) != 8 {
		t.Fatalf("tools/list returned %d tools, want 8", len(listResp.Result.Tools))
	}
	for _, tool := range listResp.Result.Tools {
		if tool.InputSchema["additionalProperties"] != false {
			t.Errorf("%s accepts unknown properties; a model that invents a parameter "+
				"misunderstood the tool, and dropping it silently hides that", tool.Name)
		}
	}

	var errResp struct {
		Error *struct {
			Code int `json:"code"`
		} `json:"error"`
	}
	if err := json.Unmarshal([]byte(lines[2]), &errResp); err != nil {
		t.Fatal(err)
	}
	if errResp.Error == nil || errResp.Error.Code != codeMethodNotFound {
		t.Errorf("an unknown method did not produce -32601: %s", lines[2])
	}
}

// TestAFailureReachesTheModelNotTheFramework: a refusal from UAI must arrive as
// a tool result with isError, so the model can act on it. A JSON-RPC error
// would go to the framework and the model would never see why.
func TestAFailureReachesTheModelNotTheFramework(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/problem+json")
		w.WriteHeader(http.StatusForbidden)
		_, _ = io.WriteString(w, `{"title":"UAI_IDENTITY_QUARANTINED","status":403,
			"detail":"Identity is under a preventive, reversible quarantine."}`)
	}))
	defer srv.Close()

	raw := callToolRaw(t, srv.URL, "uai_get_status", `{}`)
	var resp struct {
		Result struct {
			IsError bool `json:"isError"`
			Content []struct {
				Text string `json:"text"`
			} `json:"content"`
		} `json:"result"`
		Error any `json:"error"`
	}
	if err := json.Unmarshal([]byte(raw), &resp); err != nil {
		t.Fatal(err)
	}
	if resp.Error != nil {
		t.Fatalf("a UAI refusal became a JSON-RPC error: %s", raw)
	}
	if !resp.Result.IsError {
		t.Error("a refusal was not marked isError")
	}
	if !strings.Contains(resp.Result.Content[0].Text, "UAI_IDENTITY_QUARANTINED") {
		t.Errorf("the model is not told why:\n%s", resp.Result.Content[0].Text)
	}
}

// ── helpers ─────────────────────────────────────────────────────────────────

func testClient(t *testing.T, endpoint string) *uai.Client {
	t.Helper()
	const uaiID = "uai:agent:01JY8R9ZAF392N7QX2T81JH6KM"
	signer, _, err := uaicrypto.GenerateEd25519Signer("did:" + uaiID + "#key-1")
	if err != nil {
		t.Fatal(err)
	}
	c, err := uai.New(endpoint, uaiID, signer, uai.WithOwnerDID("did:uai:owner:01JY8R9ZB0"))
	if err != nil {
		t.Fatal(err)
	}
	return c
}

// callToolRaw runs one tools/call through the full JSON-RPC loop.
func callToolRaw(t *testing.T, endpoint, name, args string) string {
	t.Helper()
	// One message, one line: the stdio transport is newline-delimited, and a
	// test whose arguments contained a newline would silently be testing the
	// framing instead of the tool.
	if strings.ContainsAny(args, "\n\r") {
		t.Fatalf("tool arguments must be a single line: %q", args)
	}
	in := strings.NewReader(`{"jsonrpc":"2.0","id":1,"method":"tools/call","params":` +
		`{"name":"` + name + `","arguments":` + args + `}}` + "\n")
	var out bytes.Buffer
	if err := serve(context.Background(), newConn(in, &out), testClient(t, endpoint),
		log.New(io.Discard, "", 0)); err != nil {
		t.Fatal(err)
	}
	return strings.TrimSpace(out.String())
}

// callTool returns the text the model would see.
func callTool(t *testing.T, endpoint, name, args string) string {
	t.Helper()
	var resp struct {
		Result struct {
			Content []struct {
				Text string `json:"text"`
			} `json:"content"`
		} `json:"result"`
	}
	raw := callToolRaw(t, endpoint, name, args)
	if err := json.Unmarshal([]byte(raw), &resp); err != nil {
		t.Fatalf("%v\n%s", err, raw)
	}
	if len(resp.Result.Content) == 0 {
		t.Fatalf("no content in %s", raw)
	}
	return resp.Result.Content[0].Text
}
