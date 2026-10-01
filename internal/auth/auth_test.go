package auth

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/nats-io/jwt/v2"
	"github.com/nats-io/nats.go"
	"github.com/nats-io/nats.go/micro"
	"github.com/nats-io/nkeys"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type fakeRequest struct {
	data    []byte
	headers micro.Headers

	resp    []byte
	errCode string
	respErr error
}

func (r *fakeRequest) Respond(b []byte, _ ...micro.RespondOpt) error { r.resp = b; return r.respErr }
func (r *fakeRequest) RespondJSON(any, ...micro.RespondOpt) error    { return nil }
func (r *fakeRequest) Error(code, _ string, _ []byte, _ ...micro.RespondOpt) error {
	r.errCode = code
	return nil
}
func (r *fakeRequest) Data() []byte           { return r.data }
func (r *fakeRequest) Headers() micro.Headers { return r.headers }
func (r *fakeRequest) Subject() string        { return "$SYS.REQ.USER.AUTH" }
func (r *fakeRequest) Reply() string          { return "_INBOX.x" }

type fakeAuthz struct {
	account string
	err     error
}

func (f fakeAuthz) Authorize(_ context.Context, rc *jwt.AuthorizationRequestClaims) (*jwt.UserClaims, error) {
	if f.err != nil {
		return nil, f.err
	}
	uc := jwt.NewUserClaims(rc.UserNkey)
	uc.Audience = f.account
	return uc, nil
}

type keys struct {
	issuer, xkey, server, serverX nkeys.KeyPair
}

func newKeys(t *testing.T) keys {
	t.Helper()
	var k keys
	var err error
	k.issuer, err = nkeys.CreateAccount()
	require.NoError(t, err)
	k.xkey, err = nkeys.CreateCurveKeys()
	require.NoError(t, err)
	k.server, err = nkeys.CreateServer()
	require.NoError(t, err)
	k.serverX, err = nkeys.CreateCurveKeys()
	require.NoError(t, err)
	return k
}

func seed(t *testing.T, kp nkeys.KeyPair) []byte {
	t.Helper()
	s, err := kp.Seed()
	require.NoError(t, err)
	return s
}

// request builds a server-signed auth request like nats-server sends it.
func (k keys) request(t *testing.T) (string, string) {
	t.Helper()
	ukp, _ := nkeys.CreateUser()
	upub, _ := ukp.PublicKey()
	spub, _ := k.server.PublicKey()
	rc := jwt.NewAuthorizationRequestClaims(upub)
	rc.UserNkey = upub
	rc.Server.ID = spub
	rc.ConnectOptions.Token = "tok"
	enc, err := rc.Encode(k.server)
	require.NoError(t, err)
	return enc, upub
}

type observed struct{ results []Result }

func (o *observed) observe(_ context.Context, r Result, _ time.Duration) {
	o.results = append(o.results, r)
}

func decodeResponse(t *testing.T, raw []byte) *jwt.AuthorizationResponseClaims {
	t.Helper()
	rc, err := jwt.DecodeAuthorizationResponseClaims(string(raw))
	require.NoError(t, err)
	return rc
}

func TestHandlePlain(t *testing.T) {
	k := newKeys(t)
	var obs observed
	svc, err := NewService(seed(t, k.issuer), nil, fakeAuthz{account: "$G"}, obs.observe)
	require.NoError(t, err)
	ipub, _ := k.issuer.PublicKey()
	assert.Equal(t, ipub, svc.IssuerPublicKey())

	data, upub := k.request(t)
	req := &fakeRequest{data: []byte(data), headers: micro.Headers{}}
	svc.Handle(req)

	resp := decodeResponse(t, req.resp)
	assert.Empty(t, resp.Error)
	assert.Equal(t, upub, resp.Subject)
	assert.Equal(t, ipub, resp.Issuer)
	uc, err := jwt.DecodeUserClaims(resp.Jwt)
	require.NoError(t, err)
	assert.Equal(t, "$G", uc.Audience)
	assert.Equal(t, []Result{ResultAllowed}, obs.results)
}

func TestHandleEncrypted(t *testing.T) {
	k := newKeys(t)
	var obs observed
	svc, err := NewService(seed(t, k.issuer), seed(t, k.xkey), fakeAuthz{account: "$G"}, obs.observe)
	require.NoError(t, err)

	data, _ := k.request(t)
	xpub, _ := k.xkey.PublicKey()
	sxpub, _ := k.serverX.PublicKey()
	sealed, err := k.serverX.Seal([]byte(data), xpub)
	require.NoError(t, err)

	req := &fakeRequest{data: sealed, headers: micro.Headers(nats.Header{serverXKeyHeader: {sxpub}})}
	svc.Handle(req)

	plain, err := k.serverX.Open(req.resp, xpub)
	require.NoError(t, err)
	assert.Empty(t, decodeResponse(t, plain).Error)
	assert.Equal(t, []Result{ResultAllowed}, obs.results)
}

func TestHandleDenied(t *testing.T) {
	k := newKeys(t)
	var obs observed
	svc, err := NewService(seed(t, k.issuer), nil, fakeAuthz{err: errors.New("bad token")}, obs.observe)
	require.NoError(t, err)

	data, _ := k.request(t)
	req := &fakeRequest{data: []byte(data), headers: micro.Headers{}}
	svc.Handle(req)

	resp := decodeResponse(t, req.resp)
	assert.Equal(t, "not authorized", resp.Error)
	assert.Empty(t, resp.Jwt)
	assert.Equal(t, []Result{ResultDenied}, obs.results)
}

func TestHandleInvalidUserClaims(t *testing.T) {
	k := newKeys(t)
	// An empty account fails user JWT validation and must be denied, not signed.
	svc, err := NewService(seed(t, k.issuer), nil, fakeAuthz{account: ""}, nil)
	require.NoError(t, err)
	data, _ := k.request(t)
	req := &fakeRequest{data: []byte(data), headers: micro.Headers{}}
	svc.Handle(req)
	resp := decodeResponse(t, req.resp)
	assert.NotEmpty(t, resp.Error)
}

func TestHandleErrors(t *testing.T) {
	k := newKeys(t)
	sxpub, _ := k.serverX.PublicKey()
	data, _ := k.request(t)

	for name, tc := range map[string]struct {
		xkey []byte
		req  *fakeRequest
		code string
	}{
		"garbage request": {req: &fakeRequest{data: []byte("garbage"), headers: micro.Headers{}}, code: "400"},
		"encrypted without xkey": {
			req:  &fakeRequest{data: []byte("x"), headers: micro.Headers(nats.Header{serverXKeyHeader: {sxpub}})},
			code: "500",
		},
		"undecryptable": {
			xkey: seed(t, k.xkey),
			req:  &fakeRequest{data: []byte("x"), headers: micro.Headers(nats.Header{serverXKeyHeader: {sxpub}})},
			code: "400",
		},
		"respond fails": {
			req: &fakeRequest{data: []byte(data), headers: micro.Headers{}, respErr: errors.New("closed")},
		},
	} {
		t.Run(name, func(t *testing.T) {
			var obs observed
			svc, err := NewService(seed(t, k.issuer), tc.xkey, fakeAuthz{account: "$G"}, obs.observe)
			require.NoError(t, err)
			svc.Handle(tc.req)
			assert.Equal(t, tc.code, tc.req.errCode)
			assert.Equal(t, []Result{ResultError}, obs.results)
		})
	}
}

func TestNewServiceValidatesKeys(t *testing.T) {
	k := newKeys(t)
	ukp, _ := nkeys.CreateUser()

	_, err := NewService([]byte("nope"), nil, fakeAuthz{}, nil)
	assert.ErrorContains(t, err, "issuer seed")
	_, err = NewService(seed(t, ukp), nil, fakeAuthz{}, nil)
	assert.ErrorContains(t, err, "account key")
	_, err = NewService(seed(t, k.issuer), seed(t, ukp), fakeAuthz{}, nil)
	assert.ErrorContains(t, err, "xkey seed")
}
