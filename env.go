package main

import (
	"log"
	"os"

	"github.com/joho/godotenv"
)

type Env struct {
	name     string
	required bool
}

var ENVIRONMENT_VARIABLES = []Env{
	{
		name: "DOMAIN",
		required: true,
	},
	{
		name:     "GIN_MODE",
		required: false,
	},
	{
		name:     "PORT",
		required: false,
	},
	{
		name:     "TRUSTED_PROXIES",
		required: false,
	},
	{
		name:     "CORS_ORIGIN",
		required: false,
	},
	{
		name:     "CORS_METHODS",
		required: false,
	},
	{
		name:     "CORS_HEADERS",
		required: false,
	},
	{
		name:     "CORS_CREDENTIALS",
		required: false,
	},
	{
		name:     "CORS_CACHE_TIME",
		required: false,
	},

	{
		name:     "LDAP_BASE_DN",
		required: true,
	},
	{
		name:     "LDAP_BIND_DN",
		required: false,
	},
	{
		name:     "LDAP_BIND_PW",
		required: false,
	},
	{
		name:     "LDAP_DOMAIN",
		required: true,
	},
	{
		name:     "LDAP_USER_QUERY",
		required: true,
	},

	{
		name:     "SESSION_NAME",
		required: true,
	},
	{
		name:     "SESSION_REDIS_URL",
		required: true,
	},
	{
		name:     "SESSION_REDIS_PASSWORD",
		required: false,
	},
	{
		name:     "SESSION_REDIS_CONECTIONS",
		required: false,
	},
	{
		name:     "SESSION_REDIS_AUTHENTICATION_KEY",
		required: true,
	},
	{
		name:     "SESSION_REDIS_ENCRYPTION_KEY",
		required: true,
	},

	{
		name:     "OIDC_AUTHORITY",
		required: true,
	},
	{
		name:     "OIDC_CLIENT_ID",
		required: true,
	},
	{
		name:     "OIDC_REDIRECT_URL",
		required: true,
	},
	{
		name:     "OIDC_SCOPES",
		required: true,
	},

	{
		name:		  "SMTP_DOMAIN",
		required: true,
	},
	{
		name:		  "SMTP_PORT",
		required: true,
	},
	{
		name:		  "SMTP_STARTTLS",
		required: true,
	},
	{
		name:		  "SMTP_USER",
		required: true,
	},
	{
		name:		  "SMTP_PASS",
		required: true,
	},
	{
		name:		  "SMTP_SENDER_NAME",
		required: true,
	},
	{
		name:		  "SMTP_SENDER_MAIL",
		required: true,
	},
}

func Load_env() {
	err := godotenv.Load()

	if err != nil && !os.IsNotExist(err) {
		log.Panicf("Error loading .env file with error %v", err)
	}
}

func Ensure_env() {
	for _, env := range ENVIRONMENT_VARIABLES {
		if _, ok := os.LookupEnv(env.name); !ok && env.required {
			log.Panicf("%s environment variable not set, but it is required", env.name)
		}
	}
}
