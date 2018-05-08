package jwtauth

import (
	"crypto/ecdsa"
	"crypto/rsa"
	"errors"
	"fmt"
	"strings"

	jwt "github.com/dgrijalva/jwt-go"
	"github.com/mitchellh/mapstructure"
	"github.com/nats-io/gnatsd/server"
)

// JWTAuth implements server.Authentication interface
type JWTAuth struct {
	PublicKeys []KeyProvider
	UserField  string
	NatsField  string
	logger     Logger
}

// static assert
var _ server.Authentication = (*JWTAuth)(nil)

// Token is accept model token should match
type Token struct {
	Subject     string              `mapstructure:"sub"`
	ExpiresAt   *int64              `mapstructure:"exp"`
	User        string              `mapstructure:"user"`
	Name        string              `mapstructure:"name"`
	Permissions *server.Permissions `mapstructure:"permissions"`
}

// Check returns true if connection is valid
func (auth *JWTAuth) Check(c server.ClientAuthentication) (verified bool) {
	if len(auth.PublicKeys) <= 0 {
		auth.Debugf("no public keys")
		return
	}
	// retrive token
	opts := c.GetOpts()
	if opts == nil {
		return
	}
	token, err := auth.Verify(opts.Authorization, &jwt.MapClaims{})
	if err != nil {
		auth.Errorf("failed to auth token, %v", err)
		return
	}

	user := auth.GetUser(token.Claims)
	if user == nil {
		return
	}
	auth.Debugf("Verified user %q, with perms %v", user.Username, user.Permissions != nil)
	c.RegisterUser(user)
	return true
}

// GetUser extract user from given claims
func (auth *JWTAuth) GetUser(claims jwt.Claims) *server.User {
	var user server.User
	var token *Token
	mapstructure.Decode(claims.(*jwt.MapClaims), &token)

	if token.Subject != "" {
		user.Username = token.Subject
	} else if token.User != "" {
		user.Username = token.User
	} else if token.Name != "" {
		user.Username = token.Name
	} else if auth.UserField != "" {
		customClaims := claims.(*jwt.MapClaims)
		if username, ok := (*customClaims)[auth.UserField].(string); ok {
			user.Username = username
		}
	}
	if user.Username == "" {
		auth.Errorf("User name is required")
		return nil
	}

	if auth.NatsField != "" {
		customClaims := claims.(*jwt.MapClaims)
		if nats, ok := (*customClaims)[auth.NatsField].(map[string]interface{}); ok {
			mapstructure.Decode(nats["permissions"], &token.Permissions)
		} else {
			auth.Errorf("Unable to parse JWT field %v", auth.NatsField)
			return nil
		}
	}
	if token.Permissions != nil {
		// check permissions
		if func() bool {
			for _, pubs := range token.Permissions.Publish {
				if !server.IsValidSubject(pubs) {
					auth.Errorf("%v is invalid subject in Publish", pubs)
					return false
				}
			}
			for _, subs := range token.Permissions.Subscribe {
				if !server.IsValidSubject(subs) {
					auth.Errorf("%v is invalid subject in Subscribe", subs)
					return false
				}
			}
			return true
		}() {
			user.Permissions = token.Permissions
		}
	}
	return &user
}

// Verify will return a parsed token if it passes validation, or an
// error if any part of the token fails validation.  Possible errors include
// malformed tokens, unknown/unspecified signing algorithms, missing secret key,
// tokens that are not valid yet (i.e., 'nbf' field), tokens that are expired,
// and tokens that fail signature verification (forged)
func (auth *JWTAuth) Verify(uToken string, claims jwt.Claims) (token *jwt.Token, err error) {
	if len(uToken) <= 0 {
		return nil, errors.New("token is empty")
	}

	if splitted := strings.SplitN(uToken, ".", 3); len(splitted) == 2 {
		uToken = "eyJhbGciOiJFUzI1NiIsInR5cCI6IkpXVCJ9." + uToken
	}

	for _, kp := range auth.PublicKeys {
		// Validate token
		token, err = jwt.ParseWithClaims(uToken, claims, func(t *jwt.Token) (interface{}, error) {
			pk, err := kp.PublicKey()
			if err != nil {
				return nil, err
			}
			switch pk.(type) {
			case *rsa.PublicKey:
				if _, ok := t.Method.(*jwt.SigningMethodRSA); !ok {
					return nil, fmt.Errorf("expect token signed with RSA but got %v", token.Header["alg"])
				}
			case *ecdsa.PublicKey:
				if _, ok := t.Method.(*jwt.SigningMethodECDSA); !ok {
					return nil, fmt.Errorf("expect token signed with ECDSA but got %v", token.Header["alg"])
				}
			default:
				return nil, fmt.Errorf("only RSA & ECDSA are supported but got %v", token.Header["alg"])
			}
			return pk, nil
		})

		if err == nil {
			// break on first correctly validated token
			break
		}
	}

	if err != nil {
		token = nil
	}

	return
}

// StrictMode is a global config if true, any token without exp will be rejected
var StrictMode = false

// Valid lets us use the user info as Claim for jwt-go.
// It checks the token expiry.
func (u Token) Valid() error {
	if u.ExpiresAt == nil && !StrictMode {
		return nil
	}
	if *u.ExpiresAt < jwt.TimeFunc().Unix() {
		return errors.New("token expired")
	}
	return nil
}
