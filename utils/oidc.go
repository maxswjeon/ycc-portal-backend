package utils

import (
  "context"
  "crypto/rand"
  "encoding/base64"
  "os"
  "strings"

  "github.com/coreos/go-oidc/v3/oidc"
  "golang.org/x/oauth2"
)

func GenerateOIDCConfig() (*oidc.Provider, *oauth2.Config, *oidc.IDTokenVerifier, error) {
  provider, err := oidc.NewProvider(context.Background(), os.Getenv("OIDC_AUTHORITY"))
  if err != nil {
    return nil, nil, nil, err
  }

  config := &oauth2.Config{
    ClientID:    os.Getenv("OIDC_CLIENT_ID"),
    RedirectURL: os.Getenv("OIDC_REDIRECT_URL"),
    Endpoint:    provider.Endpoint(),
    Scopes:      strings.Split(os.Getenv("OIDC_SCOPES"), " "),
  }

  verifier := provider.Verifier(&oidc.Config{ClientID: os.Getenv("OIDC_CLIENT_ID")})

  return provider, config, verifier, nil
}

func OIDCRandString(n int) (string, error) {
  b := make([]byte, n)
  if _, err := rand.Read(b); err != nil {
    return "", err
  }
  return base64.RawURLEncoding.EncodeToString(b), nil
}
