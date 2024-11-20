package auth

import (
	"errors"
	"log"

	"github.com/nats-io/jwt/v2"
	"github.com/nats-io/nats.go/micro"
	"github.com/nats-io/nkeys"
)

type Service struct {
	issuerKeyPair nkeys.KeyPair
	handler       NatsAuthHandler
	audience      string
}

type NatsAuthHandler func(req *jwt.AuthorizationRequestClaims) (*jwt.UserClaims, error)

func (a *Service) Handle(r micro.Request) {
	rc, err := jwt.DecodeAuthorizationRequestClaims(string(r.Data()))
	if err != nil {
		log.Println("Error", err)
		r.Error("500", err.Error(), nil)
	}

	userNkey := rc.UserNkey
	serverId := rc.Server.ID
	claims := jwt.NewUserClaims(rc.UserNkey)
	claims.Audience = a.audience

	claims, err = a.handler(rc)
	if err != nil {
		a.Respond(r, userNkey, serverId, "", err)
		return
	}

	token, err := ValidateAndSign(claims, a.issuerKeyPair)
	a.Respond(r, userNkey, serverId, token, err)
}

func (a *Service) Respond(req micro.Request, userNKey, serverId, userJWT string, err error) {
	rc := jwt.NewAuthorizationResponseClaims(userNKey)
	rc.Audience = serverId
	rc.Jwt = userJWT
	if err != nil {
		rc.Error = err.Error()
	}

	token, err := rc.Encode(a.issuerKeyPair)
	if err != nil {
		log.Println("error encoding response jwt:", err)
	}

	req.Respond([]byte(token))
}

func ValidateAndSign(claims *jwt.UserClaims, kp nkeys.KeyPair) (string, error) {
	vr := jwt.CreateValidationResults()

	claims.Validate(vr)
	if len(vr.Errors()) > 0 {
		return "", errors.Join(vr.Errors()...)
	}

	return claims.Encode(kp)
}
