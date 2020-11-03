package tokens

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"errors"
	"strings"
)

// Claims has user, email and name
type Claims struct {
	User  string `json:"user,omitempty"`
	Email string `json:"email,omitempty"`
	Name  string `json:"name,omitempty"`
}

// Header has timestamp and exp, both in UnixNano
type Header struct {
	Timestamp int64 `json:"timestamp,omitempty"`
	Exp       int64 `json:"exp,omitempty"`
}

/* TODO
Create a tokenA

use tokenA plus signature to sign a tokenB (child)

New()   return tokenA
NewChild() return tokenB
Validate() takes a token and returns claims

*/

func newToken(i interface{}, h interface{}, key []byte) (encoded string, err error) {
	js, err := json.Marshal(i)
	if err != nil {
		return "", err
	}
	head, err := json.Marshal(h)
	if err != nil {
		return "", err
	}

	hasher := hmac.New(sha256.New, key)
	//
	hj := append(js, head...)

	_, err = hasher.Write(hj)
	if err != nil {
		return "", err
	}
	signature := base64.RawURLEncoding.EncodeToString(hasher.Sum(nil))
	claims := base64.RawURLEncoding.EncodeToString(js)
	header := base64.RawURLEncoding.EncodeToString(head)
	encoded = header + "." + claims + "." + signature
	return encoded, nil
}

// Validate validates token with a given secret key and returns header and claims
func Validate(token string, key []byte) (h *Header, cl *Claims, err error) {
	strs := strings.Split(token, ".")
	a, _ := base64.RawURLEncoding.DecodeString(strs[0])
	b, _ := base64.RawURLEncoding.DecodeString(strs[1])

	// s,_ := base64.RawURLEncoding.DecodeString(strs[2])
	// fmt.Println(s)

	err = json.Unmarshal(a, &h)
	if err != nil {
		return nil, nil, err
	}
	// if h.Exp < time.Now().UnixNano() {
	// 	return nil, nil, errors.New("Expired")
	// }
	//check if claims

	err = json.Unmarshal(b, &cl)
	if err != nil {
		return nil, nil, err
	}
	//make sure is not empty
	if cl.User != "" && cl.Name != "" && cl.Email != "" {
		t, err := newToken(cl, h, key)
		if err != nil {
			return nil, nil, err
		}
		if subtle.ConstantTimeCompare([]byte(t), []byte(token)) == 1 {
			return h, cl, nil
		}
		return nil, nil, errors.New("Invalid token")
	}
	return nil, nil, errors.New("Invalid token")

}

// New generates a token A and token B with a given secret key
func New(cls Claims, head Header, secret []byte) (tokenA string, err error) {
	tokenA, err = newToken(cls, head, []byte(secret))
	if err != nil {
		return "", err
	}
	return tokenA, nil
}

func generateRandomBytes(n uint32) ([]byte, error) {
	b := make([]byte, n)
	_, err := rand.Read(b)
	if err != nil {
		return nil, err
	}

	return b, nil
}
