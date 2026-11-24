// Package natsauth holds the operator-mode account layout: the keys, the
// account JWTs, and the runtime material that the application needs.
//
// Accounts:
//   - SYS: system account.
//   - AUTH: holds the auth callout user and the public bearer sentinel.
//   - SVC: application services. JetStream is enabled here only. It exports
//     the API service subjects and the user event stream.
//   - USERS: browser and per-session users. It imports the API and events.
package natsauth

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"

	"github.com/nats-io/jwt/v2"
	"github.com/nats-io/nkeys"
)

const (
	APISubjects    = "app.api.>"
	EventsSubjects = "app.events.>"
	CalloutSubject = "$SYS.REQ.USER.AUTH"
)

// Keys are the root seeds. Development keeps them in the data directory.
// For a deployment, keep them offline and give the application only Runtime.
type Keys struct {
	Operator     string `json:"operator"`
	System       string `json:"system"`
	Auth         string `json:"auth"`
	AuthSigning  string `json:"auth_signing"`
	Service      string `json:"service"`
	Users        string `json:"users"`
	UsersSigning string `json:"users_signing"`
	XKey         string `json:"xkey"`
	CalloutUser  string `json:"callout_user"`
	ServiceUser  string `json:"service_user"`
	TokenKey     string `json:"token_key"`
}

// Runtime is what the application process needs and nothing more.
type Runtime struct {
	CalloutCreds string `json:"callout_creds"`
	ServiceCreds string `json:"service_creds"`
	Sentinel     string `json:"sentinel"`
	AuthAccount  string `json:"auth_account"`
	AuthSigning  string `json:"auth_signing_seed"`
	UsersAccount string `json:"users_account"`
	UsersSigning string `json:"users_signing_seed"`
	XKey         string `json:"xkey_seed"`
	TokenKey     string `json:"token_key"`
}

// Server is the trust configuration of a NATS server for these accounts.
type Server struct {
	Operator      string
	SystemAccount string
	Accounts      map[string]string
}

func GenerateKeys() (Keys, error) {
	var k Keys
	var err error
	gen := func(f func() (nkeys.KeyPair, error), dst *string) {
		if err != nil {
			return
		}
		var kp nkeys.KeyPair
		if kp, err = f(); err == nil {
			var seed []byte
			seed, err = kp.Seed()
			*dst = string(seed)
		}
	}
	gen(nkeys.CreateOperator, &k.Operator)
	gen(nkeys.CreateAccount, &k.System)
	gen(nkeys.CreateAccount, &k.Auth)
	gen(nkeys.CreateAccount, &k.AuthSigning)
	gen(nkeys.CreateAccount, &k.Service)
	gen(nkeys.CreateAccount, &k.Users)
	gen(nkeys.CreateAccount, &k.UsersSigning)
	gen(nkeys.CreateCurveKeys, &k.XKey)
	gen(nkeys.CreateUser, &k.CalloutUser)
	gen(nkeys.CreateUser, &k.ServiceUser)
	if err != nil {
		return Keys{}, err
	}
	k.TokenKey = base64.StdEncoding.EncodeToString(randomBytes(32))
	return k, nil
}

// LoadOrCreateKeys reads the keys file, or makes one with mode 0600. A
// restart with the same file keeps sessions and connect tokens valid.
func LoadOrCreateKeys(path string) (Keys, error) {
	var k Keys
	b, err := os.ReadFile(path)
	if err == nil {
		return k, json.Unmarshal(b, &k)
	}
	if !errors.Is(err, os.ErrNotExist) {
		return k, err
	}
	if k, err = GenerateKeys(); err != nil {
		return k, err
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return k, err
	}
	b, _ = json.MarshalIndent(k, "", "  ")
	return k, os.WriteFile(path, b, 0o600)
}

func LoadRuntime(path string) (Runtime, error) {
	var rt Runtime
	b, err := os.ReadFile(path)
	if err != nil {
		return rt, err
	}
	if err := json.Unmarshal(b, &rt); err != nil {
		return rt, err
	}
	return rt, rt.validate()
}

func (rt Runtime) validate() error {
	if rt.CalloutCreds == "" || rt.ServiceCreds == "" || rt.Sentinel == "" || rt.AuthSigning == "" ||
		rt.UsersSigning == "" || rt.XKey == "" || rt.UsersAccount == "" || rt.AuthAccount == "" {
		return errors.New("NATS runtime file is incomplete")
	}
	if len(rt.TokenBytes()) < 32 {
		return errors.New("NATS runtime token_key must be at least 32 bytes of base64")
	}
	return nil
}

func (rt Runtime) TokenBytes() []byte {
	b, _ := base64.StdEncoding.DecodeString(rt.TokenKey)
	return b
}

func (rt Runtime) UsersSigningKey() (nkeys.KeyPair, error) {
	return nkeys.FromSeed([]byte(rt.UsersSigning))
}

func (rt Runtime) AuthSigningKey() (nkeys.KeyPair, error) {
	return nkeys.FromSeed([]byte(rt.AuthSigning))
}

func (rt Runtime) XKeyPair() (nkeys.KeyPair, error) {
	return nkeys.FromCurveSeed([]byte(rt.XKey))
}

func pub(seed string) string {
	p, _ := kp(seed).PublicKey()
	return p
}

func kp(seed string) nkeys.KeyPair {
	k, err := nkeys.FromSeed([]byte(seed))
	if err != nil {
		panic(fmt.Sprintf("invalid seed: %v", err))
	}
	return k
}

// Build makes the operator and account JWTs and the runtime material.
func (k Keys) Build() (Server, Runtime, error) {
	xk, err := nkeys.FromCurveSeed([]byte(k.XKey))
	if err != nil {
		return Server{}, Runtime{}, err
	}
	xpub, _ := xk.PublicKey()
	sys, auth, svc, usr := pub(k.System), pub(k.Auth), pub(k.Service), pub(k.Users)

	op := jwt.NewOperatorClaims(pub(k.Operator))
	op.Name = "app-operator"
	op.SystemAccount = sys
	opJWT, err := op.Encode(kp(k.Operator))
	if err != nil {
		return Server{}, Runtime{}, err
	}

	accounts := map[string]string{}
	sign := func(ac *jwt.AccountClaims) {
		if err != nil {
			return
		}
		var t string
		t, err = ac.Encode(kp(k.Operator))
		accounts[ac.Subject] = t
	}

	sa := jwt.NewAccountClaims(sys)
	sa.Name = "SYS"
	sign(sa)

	aa := jwt.NewAccountClaims(auth)
	aa.Name = "AUTH"
	aa.SigningKeys.Add(pub(k.AuthSigning))
	aa.Authorization.AuthUsers.Add(pub(k.CalloutUser))
	aa.Authorization.AllowedAccounts.Add(usr)
	aa.Authorization.XKey = xpub
	sign(aa)

	va := jwt.NewAccountClaims(svc)
	va.Name = "SVC"
	va.Limits.JetStreamLimits = jwt.JetStreamLimits{MemoryStorage: -1, DiskStorage: -1, Streams: -1, Consumer: -1}
	va.Exports.Add(
		&jwt.Export{Name: "api", Subject: APISubjects, Type: jwt.Service, ResponseType: jwt.ResponseTypeSingleton},
		&jwt.Export{Name: "events", Subject: EventsSubjects, Type: jwt.Stream},
	)
	sign(va)

	ua := jwt.NewAccountClaims(usr)
	ua.Name = "USERS"
	ua.SigningKeys.Add(pub(k.UsersSigning))
	ua.Imports.Add(
		&jwt.Import{Name: "api", Subject: APISubjects, Account: svc, Type: jwt.Service, Share: true},
		&jwt.Import{Name: "events", Subject: EventsSubjects, Account: svc, Type: jwt.Stream},
	)
	sign(ua)
	if err != nil {
		return Server{}, Runtime{}, err
	}

	callout := jwt.NewUserClaims(pub(k.CalloutUser))
	callout.Name = "callout"
	callout.IssuerAccount = auth
	callout.Pub.Allow.Add("$SYS._INBOX.>")
	callout.Sub.Allow.Add(CalloutSubject)
	calloutCreds, err := creds(callout, kp(k.Auth), k.CalloutUser)
	if err != nil {
		return Server{}, Runtime{}, err
	}

	service := jwt.NewUserClaims(pub(k.ServiceUser))
	service.Name = "service"
	serviceCreds, err := creds(service, kp(k.Service), k.ServiceUser)
	if err != nil {
		return Server{}, Runtime{}, err
	}

	sentinelKey, _ := nkeys.CreateUser()
	sentinelPub, _ := sentinelKey.PublicKey()
	sentinel := jwt.NewUserClaims(sentinelPub)
	sentinel.Name = "sentinel"
	sentinel.BearerToken = true
	sentinel.Pub.Deny.Add(">")
	sentinel.Sub.Deny.Add(">")
	sentinelJWT, err := sentinel.Encode(kp(k.Auth))
	if err != nil {
		return Server{}, Runtime{}, err
	}

	return Server{Operator: opJWT, SystemAccount: sys, Accounts: accounts}, Runtime{
		CalloutCreds: calloutCreds,
		ServiceCreds: serviceCreds,
		Sentinel:     sentinelJWT,
		AuthAccount:  auth,
		AuthSigning:  k.AuthSigning,
		UsersAccount: usr,
		UsersSigning: k.UsersSigning,
		XKey:         k.XKey,
		TokenKey:     k.TokenKey,
	}, nil
}

func creds(uc *jwt.UserClaims, signer nkeys.KeyPair, seed string) (string, error) {
	t, err := uc.Encode(signer)
	if err != nil {
		return "", err
	}
	b, err := jwt.FormatUserConfig(t, []byte(seed))
	return string(b), err
}

// ResolverConfig is a server configuration fragment with the operator and
// a preloaded memory resolver.
func (s Server) ResolverConfig() string {
	out := fmt.Sprintf("operator: %q\nsystem_account: %s\nresolver: MEMORY\nresolver_preload: {\n", s.Operator, s.SystemAccount)
	for pub, t := range s.Accounts {
		out += fmt.Sprintf("  %s: %q\n", pub, t)
	}
	return out + "}\n"
}

func randomBytes(n int) []byte {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		panic(err)
	}
	return b
}
