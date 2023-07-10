package accesstokens

import (
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/google/uuid"
)

// AcquirePoPTokenForHost - pop token built using SHR token format
// - https://tools.ietf.org/html/draft-ietf-oauth-signed-http-request-03#section-3
// host is included as "u" claim
func (tkn *TokenResponse) AcquirePoPTokenForHost(host string) (string, error) {

	if tkn.poPKey == nil {
		return "", errors.New("token does not support pop semantics")
	}

	ts := time.Now().Unix()
	nonce := uuid.New().String()
	nonce = strings.Replace(nonce, "-", "", -1)
	header := fmt.Sprintf(`{"typ":"pop","alg":"%s","kid":"%s"}`, tkn.poPKey.Alg(), tkn.poPKey.KeyID())
	headerB64 := base64.RawURLEncoding.EncodeToString([]byte(header))
	payload := fmt.Sprintf(`{"at":"%s","ts":%d,"u":"%s","cnf":{"jwk":%s},"nonce":"%s"}`, tkn.AccessToken, ts, host, tkn.poPKey.JWK(), nonce)
	payloadB64 := base64.RawURLEncoding.EncodeToString([]byte(payload))
	h256 := sha256.Sum256([]byte(headerB64 + "." + payloadB64))
	signature, err := tkn.poPKey.Sign(h256[:])
	if err != nil {
		return "", err
	}
	signatureB64 := base64.RawURLEncoding.EncodeToString(signature)

	return headerB64 + "." + payloadB64 + "." + signatureB64, nil
}
