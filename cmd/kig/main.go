package main

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"errors"
	"flag"
	"fmt"
	"log"
	"math/big"
	"net"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"devforge/keyguard/internal/guard"
)

func main() {
	if e := run(os.Args[1:]); e != nil {
		fmt.Fprintln(os.Stderr, "kig:", e)
		os.Exit(1)
	}
}
func output(v any) error { e := json.NewEncoder(os.Stdout); e.SetIndent("", "  "); return e.Encode(v) }
func run(args []string) error {
	if len(args) == 0 {
		return errors.New("commands: init, keygen, migrate, bootstrap, serve, prepare, submit, act, session, ready, state, export, verify, witness, upgrade-body, recovery-body, enrollment-body, crypto-sign, crypto-verify")
	}
	if os.Getenv("DATABASE_URL") == "" && os.Getenv("DATABASE_URL_FILE") != "" {
		b, e := os.ReadFile(os.Getenv("DATABASE_URL_FILE"))
		if e != nil {
			return e
		}
		if e = os.Setenv("DATABASE_URL", strings.TrimSpace(string(b))); e != nil {
			return e
		}
	}
	cmd := args[0]
	f := flag.NewFlagSet(cmd, flag.ContinueOnError)
	dir := f.String("dir", ".local", "initialization output directory")
	subject := f.String("subject", "writer", "subject for key generation")
	role := f.String("role", "writer", "enrollment role")
	keyPath := f.String("key", "", "client signing key")
	out := f.String("out", "", "output JSON file (no overwrite)")
	dsn := f.String("db", os.Getenv("DATABASE_URL"), "PostgreSQL DSN; prefer DATABASE_URL")
	audience := f.String("audience", "keyguard", "pinned deployment audience")
	auditPath := f.String("audit-key", "", "audit private key")
	genesisPath := f.String("genesis", "", "genesis identity manifest")
	anchorPath := f.String("anchor", "", "externally retained checkpoint or witness receipt")
	listen := f.String("listen", "127.0.0.1:8080", "HTTP listen address")
	cert := f.String("tls-cert", "", "TLS certificate PEM")
	tlsKey := f.String("tls-key", "", "TLS private key PEM")
	address := f.String("url", "http://127.0.0.1:8080", "server origin")
	ca := f.String("ca", "", "trusted TLS CA PEM")
	action := f.String("action", "", "signed action")
	resource := f.String("resource", "", "target resource or subject")
	version := f.Int64("version", 0, "expected source resource version")
	protocol := f.Int("protocol", 2, "request/enrollment/genesis protocol; explicit 1 only for legacy operation")
	minProtocol := f.Int("min-protocol", 2, "external minimum protocol for serving/verifying; use 1 only during legacy migration")
	body := f.String("body", "{}", "body JSON or @file")
	requestPath := f.String("request", "", "signed request JSON")
	token := f.String("token", os.Getenv("KIG_TOKEN"), "read token (prefer KIG_TOKEN)")
	bundlePath := f.String("bundle", "", "evidence bundle JSON")
	trustPath := f.String("trust", "", "externally trusted audit public key")
	witnessPath := f.String("witness-key", "", "independent witness private key")
	witnessTrust := f.String("witness-trust", "", "independent witness public key")
	statePath := f.String("state", "", "retained witness state file")
	recoveryID := f.String("recovery-id", "", "shared recovery proposal ID")
	expires := f.Int64("expires", 0, "recovery expiry Unix seconds (same for both approvers)")
	messagePath := f.String("message", "", "exact message bytes file")
	signaturePath := f.String("signature", "", "raw signature bytes file")
	signatureContext := f.String("context", guard.SignatureContext("action", 2), "ML-DSA context string")
	if e := f.Parse(args[1:]); e != nil {
		return e
	}
	if f.NArg() != 0 {
		return errors.New("unexpected positional arguments")
	}
	if (*protocol != 1 && *protocol != 2) || (*minProtocol != 1 && *minProtocol != 2) {
		return errors.New("unsupported protocol version")
	}
	save := func(v any) error {
		if *out != "" {
			return guard.WriteJSON(*out, v, false)
		}
		return output(v)
	}
	switch cmd {
	case "crypto-sign", "crypto-verify":
		k, e := guard.ReadKey(*keyPath)
		if e != nil {
			return e
		}
		msg, e := guard.ReadFile(*messagePath, guard.MaxBody)
		if e != nil {
			return e
		}
		if len(msg) > guard.MaxBody || len(*signatureContext) > 255 {
			return errors.New("message/context limit")
		}
		if cmd == "crypto-sign" {
			if *out == "" {
				return errors.New("--out required")
			}
			sig, e := k.Sign(msg, *signatureContext)
			if e != nil {
				return e
			}
			return guard.WriteFile(*out, sig, false)
		}
		sig, e := guard.ReadFile(*signaturePath, 8192)
		if e != nil {
			return e
		}
		if !guard.Verify(k.Public, msg, sig, *signatureContext) {
			return errors.New("invalid signature")
		}
		return output(map[string]any{"verified": true, "algorithm": guard.Algorithm})
	case "init":
		return initialize(*dir, *audience, *protocol)
	case "keygen":
		k, e := guard.NewKey(*subject)
		if e != nil {
			return e
		}
		if *out == "" {
			return errors.New("--out required for private keys")
		}
		return save(k)
	case "enrollment-body", "recovery-body":
		k, e := guard.ReadKey(*keyPath)
		if e != nil {
			return e
		}
		en := guard.Enrollment{Subject: k.Subject, Role: *role, Public: k.Public}
		if *protocol == 2 {
			en.Version = 2
		}
		en.Proof, e = k.Sign(guard.EnrollmentBytes(en), guard.SignatureContext("enroll", *protocol))
		if e != nil {
			return e
		}
		if cmd == "enrollment-body" {
			return save(en)
		}
		if *recoveryID == "" || *expires <= time.Now().Unix() {
			return errors.New("--recovery-id and future --expires required")
		}
		return save(guard.RecoveryBody{ID: *recoveryID, Expires: *expires, Enrollment: en})
	case "migrate", "bootstrap", "serve":
		if *dsn == "" {
			return errors.New("DATABASE_URL or --db required")
		}
		store := &guard.Store{DSN: *dsn, Audience: *audience, MinVersion: *minProtocol}
		ctx, cancel := guard.Deadline()
		defer cancel()
		if cmd == "migrate" {
			return store.Migrate(ctx)
		}
		k, e := guard.ReadKey(*auditPath)
		if e != nil {
			return e
		}
		if len(k.Private) == 0 {
			return errors.New("audit private key required")
		}
		store.Audit = k
		if *anchorPath != "" {
			cp, e := readAnchor(*anchorPath, *witnessTrust)
			if e != nil {
				return e
			}
			store.Anchor = &cp
		}
		if cmd == "bootstrap" {
			var g guard.Genesis
			if e = guard.ReadJSON(*genesisPath, &g); e != nil {
				return e
			}
			return store.Init(ctx, g)
		}
		if e = store.Check(ctx); e != nil {
			return e
		}
		host, _, e := net.SplitHostPort(*listen)
		if e != nil {
			return e
		}
		ip := net.ParseIP(host)
		if *cert == "" || *tlsKey == "" {
			if *cert != "" || *tlsKey != "" {
				return errors.New("both TLS files required")
			}
			if host != "localhost" && (ip == nil || !ip.IsLoopback()) {
				return errors.New("TLS required for non-loopback listener")
			}
		}
		server := &http.Server{Addr: *listen, Handler: guard.Handler(store), ReadHeaderTimeout: 5 * time.Second, ReadTimeout: 15 * time.Second, WriteTimeout: 30 * time.Second, IdleTimeout: 30 * time.Second, MaxHeaderBytes: 16 << 10, TLSConfig: &tls.Config{MinVersion: tls.VersionTLS13}}
		stop, done := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
		defer done()
		go func() {
			<-stop.Done()
			ctx, c := context.WithTimeout(context.Background(), 10*time.Second)
			defer c()
			_ = server.Shutdown(ctx)
		}()
		log.Printf("Key Identity Guard listening on %s; audience=%s", *listen, *audience)
		if *cert != "" {
			e = server.ListenAndServeTLS(*cert, *tlsKey)
		} else {
			e = server.ListenAndServe()
		}
		if errors.Is(e, http.ErrServerClosed) {
			return nil
		}
		return e
	case "verify", "witness", "upgrade-body":
		var b guard.Bundle
		if e := guard.ReadJSON(*bundlePath, &b); e != nil {
			return e
		}
		pub, e := guard.ReadKey(*trustPath)
		if e != nil {
			return e
		}
		if cmd == "upgrade-body" {
			var cp *guard.Checkpoint
			if *anchorPath != "" {
				v, err := readAnchor(*anchorPath, *witnessTrust)
				if err != nil {
					return err
				}
				cp = &v
			}
			u, err := guard.PrepareUpgrade(b, pub.Public, *audience, cp)
			if err != nil {
				return err
			}
			return save(u)
		}
		if cmd == "verify" {
			var cp *guard.Checkpoint
			if *anchorPath != "" {
				v, e := readAnchor(*anchorPath, *witnessTrust)
				if e != nil {
					return e
				}
				cp = &v
			}
			st, e := guard.VerifyBundle(b, pub.Public, *audience, cp)
			if e != nil {
				return e
			}
			if st.Version() < *minProtocol {
				return errors.New("history below minimum protocol")
			}
			return save(map[string]any{"verified": true, "size": b.Checkpoint.Size, "root": b.Checkpoint.Root, "state": st.Summary(), "claim": "signed executor history and replayed authorization, not proof of executor honesty"})
		}
		if *statePath == "" {
			return errors.New("--state required")
		}
		wk, e := guard.ReadKey(*witnessPath)
		if e != nil {
			return e
		}
		// Exclusive lock prevents two witness invocations from accepting different extensions concurrently.
		lock, e := os.OpenFile(*statePath+".lock", os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
		if e != nil {
			return fmt.Errorf("witness lock: %w (investigate stale locks before removal)", e)
		}
		lock.Close()
		defer os.Remove(*statePath + ".lock")
		var previous *guard.WitnessReceipt
		var receipt guard.WitnessReceipt
		if _, e = os.Stat(*statePath); e == nil {
			if e = guard.ReadJSON(*statePath, &receipt); e != nil {
				return e
			}
			previous = &receipt
		} else if !os.IsNotExist(e) {
			return e
		}
		receipt, e = guard.Attest(b, pub.Public, *audience, previous, wk)
		if e != nil {
			return e
		}
		if b.Checkpoint.Version != 2 && *minProtocol == 2 {
			return errors.New("history below minimum protocol")
		}
		if e = guard.WriteJSON(*statePath, receipt, previous != nil); e != nil {
			return e
		}
		return output(receipt)
	}
	c, e := guard.NewClient(*address, *audience, *ca)
	if e != nil {
		return e
	}
	c.Protocol = *protocol
	switch cmd {
	case "ready":
		return c.Ready()
	case "state":
		v, e := c.State(*token)
		if e != nil {
			return e
		}
		return save(v)
	case "export":
		v, e := c.Evidence(*token)
		if e != nil {
			return e
		}
		return save(v)
	case "submit":
		var r guard.Request
		if e = guard.ReadJSON(*requestPath, &r); e != nil {
			return e
		}
		v, e := c.Execute(r)
		if e != nil {
			return e
		}
		return save(v)
	case "session", "prepare", "act":
		k, e := guard.ReadKey(*keyPath)
		if e != nil {
			return e
		}
		if cmd == "session" {
			t, e := c.Session(k)
			if e != nil {
				return e
			}
			fmt.Println(t)
			return nil
		}
		raw := []byte(*body)
		if strings.HasPrefix(*body, "@") {
			raw, e = guard.ReadFile(strings.TrimPrefix(*body, "@"), guard.MaxBody)
			if e != nil {
				return e
			}
		}
		req, e := c.Prepare(k, *action, *resource, *version, raw)
		if e != nil {
			return e
		}
		if cmd == "prepare" {
			if *out == "" {
				return errors.New("--out required; persist exact request for retries")
			}
			return save(req)
		}
		// Persist before transmission, so a timeout can be resolved by submitting the exact request.
		if *out == "" {
			return errors.New("act requires --out for durable retry request; use submit to resolve uncertain outcomes")
		}
		if e = guard.WriteJSON(*out, req, false); e != nil {
			return e
		}
		res, e := c.Execute(req)
		if e != nil {
			return e
		}
		return output(res)
	default:
		return fmt.Errorf("unknown command %q", cmd)
	}
}
func readAnchor(path, witnessTrust string) (guard.Checkpoint, error) {
	var receipt guard.WitnessReceipt
	if e := guard.ReadJSON(path, &receipt); e == nil && receipt.Checkpoint.Size > 0 {
		if witnessTrust == "" {
			return guard.Checkpoint{}, errors.New("witness receipt needs --witness-trust")
		}
		k, e := guard.ReadKey(witnessTrust)
		if e != nil {
			return guard.Checkpoint{}, e
		}
		if !guard.Verify(k.Public, receipt.Checkpoint.Bytes(), receipt.Signature, receipt.Checkpoint.WitnessContext()) {
			return guard.Checkpoint{}, errors.New("invalid witness signature")
		}
		return receipt.Checkpoint, nil
	}
	var cp guard.Checkpoint
	e := guard.ReadJSON(path, &cp)
	return cp, e
}
func initialize(dir, audience string, protocol int) error {
	if e := os.Mkdir(dir, 0700); e != nil {
		return e
	}
	g := guard.Genesis{Audience: audience}
	if protocol == 2 {
		g.Version = 2
		g.Suite = guard.Suite384
	}
	for _, name := range []string{"admin", "recovery1", "recovery2", "writer", "observer", "audit", "witness"} {
		k, e := guard.NewKey(name)
		if e != nil {
			return e
		}
		if e = guard.WriteJSON(filepath.Join(dir, name+".json"), k, false); e != nil {
			return e
		}
		pub := k
		pub.Private = nil
		if e = guard.WriteJSON(filepath.Join(dir, name+"-public.json"), pub, false); e != nil {
			return e
		}
		role := name
		if strings.HasPrefix(name, "recovery") {
			role = "recovery"
		}
		if name == "observer" {
			role = "auditor"
		}
		if name != "audit" && name != "witness" {
			g.Identities = append(g.Identities, guard.Identity{Subject: name, Role: role, Public: k.Public})
		}
	}
	if e := guard.WriteJSON(filepath.Join(dir, "genesis.json"), g, false); e != nil {
		return e
	}
	owner, e := guard.RandomID()
	if e != nil {
		return e
	}
	app, e := guard.RandomID()
	if e != nil {
		return e
	}
	for name, value := range map[string]string{"postgres-password": owner, "app-password": app, "owner-dsn": "postgres://kig_owner:" + owner + "@db:5432/keyguard?sslmode=disable", "app-dsn": "postgres://kig_app:" + app + "@db:5432/keyguard?sslmode=disable"} {
		if e = guard.WriteFile(filepath.Join(dir, name), []byte(value+"\n"), false); e != nil {
			return e
		}
	}
	return certificate(dir)
}
func certificate(dir string) error {
	key, e := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if e != nil {
		return e
	}
	serial, e := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if e != nil {
		return e
	}
	cert := &x509.Certificate{SerialNumber: serial, Subject: pkix.Name{CommonName: "Keyguard local"}, NotBefore: time.Now().Add(-time.Minute), NotAfter: time.Now().AddDate(1, 0, 0), KeyUsage: x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}, IsCA: true, BasicConstraintsValid: true, DNSNames: []string{"localhost"}, IPAddresses: []net.IP{net.ParseIP("127.0.0.1"), net.ParseIP("::1")}}
	der, e := x509.CreateCertificate(rand.Reader, cert, cert, &key.PublicKey, key)
	if e != nil {
		return e
	}
	private, e := x509.MarshalPKCS8PrivateKey(key)
	if e != nil {
		return e
	}
	if e = guard.WriteFile(filepath.Join(dir, "tls-cert.pem"), pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), false); e != nil {
		return e
	}
	return guard.WriteFile(filepath.Join(dir, "tls-key.pem"), pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: private}), false)
}
