package guard

import (
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"time"
)

type Client struct {
	Protocol int
	URL      string
	Audience string
	HTTP     *http.Client
}

func NewClient(address, audience, caFile string) (*Client, error) {
	u, e := url.Parse(address)
	if e != nil || u.Host == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" || u.Path != "" {
		return nil, errors.New("use an origin URL without path or credentials")
	}
	host := u.Hostname()
	ip := net.ParseIP(host)
	if u.Scheme != "https" && !(u.Scheme == "http" && (host == "localhost" || (ip != nil && ip.IsLoopback()))) {
		return nil, errors.New("TLS required except loopback")
	}
	t := &http.Transport{TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS13}}
	if caFile != "" {
		b, e := os.ReadFile(caFile)
		if e != nil {
			return nil, e
		}
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM(b) {
			return nil, errors.New("invalid CA")
		}
		t.TLSClientConfig.RootCAs = pool
	}
	return &Client{Protocol: 2, URL: address, Audience: audience, HTTP: &http.Client{Transport: t, Timeout: 15 * time.Second, CheckRedirect: func(r *http.Request, v []*http.Request) error { return errors.New("redirects forbidden") }}}, nil
}
func (c *Client) call(method, path string, in, out any, token string) error {
	var body io.Reader
	if in != nil {
		b, e := json.Marshal(in)
		if e != nil {
			return e
		}
		body = bytes.NewReader(b)
	}
	r, e := http.NewRequest(method, c.URL+path, body)
	if e != nil {
		return e
	}
	if in != nil {
		r.Header.Set("Content-Type", "application/json")
	}
	if token != "" {
		r.Header.Set("Authorization", "Bearer "+token)
	}
	res, e := c.HTTP.Do(r)
	if e != nil {
		return e
	}
	defer res.Body.Close()
	limit := int64(64 << 20)
	b, e := io.ReadAll(io.LimitReader(res.Body, limit+1))
	if e != nil {
		return e
	}
	if int64(len(b)) > limit {
		return errors.New("response size limit")
	}
	if res.StatusCode != 200 {
		var f Fault
		if StrictJSON(b, &f) == nil && f.Code != "" {
			return &f
		}
		return fmt.Errorf("HTTP %d", res.StatusCode)
	}
	return StrictJSON(b, out)
}
func (c *Client) Prepare(k KeyFile, action, resource string, version int64, body []byte) (Request, error) {
	op, e := RandomID()
	if e != nil {
		return Request{}, e
	}
	return c.PrepareOperation(k, action, resource, version, body, op)
}
func (c *Client) PrepareOperation(k KeyFile, action, resource string, version int64, body []byte, op string) (Request, error) {
	if c.Protocol != 1 && c.Protocol != 2 {
		return Request{}, errors.New("unsupported client protocol")
	}
	env := Envelope{Version: c.Protocol, Audience: c.Audience, Action: action, Resource: resource, ResourceVersion: version, Operation: op, Expires: time.Now().Unix() + 60}
	req, e := SignRequest(k, env, body, SignatureContext("challenge", c.Protocol))
	if e != nil {
		return req, e
	}
	var reply ChallengeReply
	if e = c.call("POST", "/v1/challenges", req, &reply, ""); e != nil {
		return req, e
	}
	env.Challenge = reply.Challenge
	return SignRequest(k, env, body, SignatureContext("action", c.Protocol))
}
func (c *Client) Execute(req Request) (Result, error) {
	var r Result
	e := c.call("POST", "/v1/actions", req, &r, "")
	return r, e
}
func (c *Client) Act(k KeyFile, action, resource string, version int64, body any) (Result, error) {
	b, e := json.Marshal(body)
	if e != nil {
		return Result{}, e
	}
	r, e := c.Prepare(k, action, resource, version, b)
	if e != nil {
		return Result{}, e
	}
	return c.Execute(r)
}
func (c *Client) Session(k KeyFile) (string, error) {
	token, e := RandomID()
	if e != nil {
		return "", e
	}
	_, e = c.Act(k, "session.create", k.Subject, 0, map[string]string{"token_hash": Digest(c.Protocol, []byte(token))})
	return token, e
}
func (c *Client) State(token string) (map[string]any, error) {
	var s map[string]any
	e := c.call("GET", "/v1/state", nil, &s, token)
	return s, e
}
func (c *Client) Evidence(token string) (Bundle, error) {
	var b Bundle
	e := c.call("GET", "/v1/evidence", nil, &b, token)
	return b, e
}

func (c *Client) Ready() error {
	var status map[string]string
	return c.call("GET", "/readyz", nil, &status, "")
}
