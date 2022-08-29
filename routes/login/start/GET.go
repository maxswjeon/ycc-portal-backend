package login

import (
	"lmm_backend/utils"
	"net/http"

	"github.com/coreos/go-oidc/v3/oidc"
	"github.com/gin-contrib/sessions"
	"github.com/gin-gonic/gin"
)

func GET(c *gin.Context) {
  session := sessions.Default(c)

  _, config, _, err := utils.GenerateOIDCConfig()
  if err != nil {
    c.AbortWithStatusJSON(http.StatusInternalServerError, gin.H{
      "result": false,
      "error":  "Failed to create OIDC provider",
    })
  }

  state, err := utils.OIDCRandString(16)
  if err != nil {
    c.AbortWithStatusJSON(http.StatusInternalServerError, gin.H{
      "result": false,
      "error":  "Failed to generate OIDC state",
    })
  }

  nonce, err := utils.OIDCRandString(16)
  if err != nil {
    c.AbortWithStatusJSON(http.StatusInternalServerError, gin.H{
      "result": false,
      "error":  "Failed to generate OIDC nonce",
    })
  }

  session.Set("state", state)
  session.Set("nonce", nonce)
  session.Save()

  c.Redirect(302, config.AuthCodeURL(state, oidc.Nonce(nonce)))
}
