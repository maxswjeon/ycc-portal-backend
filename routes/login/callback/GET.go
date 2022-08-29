package login

import (
	"context"
	"lmm_backend/utils"
	"log"
	"net/http"
	"os"

	"github.com/gin-contrib/sessions"
	"github.com/gin-gonic/gin"
)

func GET(c *gin.Context) {
  session := sessions.Default(c)

  state := c.Query("state")
  code := c.Query("code")

  if state == "" || code == "" {
    c.AbortWithStatusJSON(http.StatusBadRequest, gin.H{
      "result": false,
      "error":  "Bad response",
    })
    return
  }

  if state != session.Get("state") {
    c.AbortWithStatusJSON(http.StatusBadRequest, gin.H{
      "result": false,
      "error":  "State mismatch",
    })
    return
  }

  _, config, verifier, err := utils.GenerateOIDCConfig()

  oauth2Token, err := config.Exchange(context.Background(), code)
  if err != nil {
    c.AbortWithStatusJSON(http.StatusInternalServerError, gin.H{
      "result": false,
      "error":  "Failed to get OIDC token from code - Failed Exchange",
    })
    return
  }

  rawIDToken, ok := oauth2Token.Extra("id_token").(string)
  if !ok {
    c.AbortWithStatusJSON(http.StatusInternalServerError, gin.H{
      "result": false,
      "error":  "Failed to get OIDC token from code - Missing token",
    })
    return
  }

  idToken, err := verifier.Verify(context.Background(), rawIDToken)
  if err != nil {
    c.AbortWithStatusJSON(http.StatusInternalServerError, gin.H{
      "result": false,
      "error":  "Failed to get OIDC token from code - Failed Verify",
    })
    return
  }

  if idToken.Nonce != session.Get("nonce") {
    c.AbortWithStatusJSON(http.StatusBadRequest, gin.H{
      "result": false,
      "error":  "Nonce mismatch",
    })
    return
  }

  log.Print("ID Token Expiry:", idToken.Expiry)
  log.Print("OAuth2 Token Expiry:", oauth2Token.Expiry)

  session.Set("oidc_token", *idToken)
  session.Set("oauth2_token", *oauth2Token)
  session.Set("authorized", true)
  session.Save()

  c.Redirect(302, os.Getenv("OIDC_FINAL_URL"))
}
