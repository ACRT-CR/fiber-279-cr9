package cors

import (
	"log"
	"net/url"
	"strconv"
	"strings"

	"github.com/gofiber/fiber/v2"
)

// Config defines the config for middleware.
type Config struct {
	// Next defines a function to skip this middleware when returned true.
	//
	// Optional. Default: nil
	Next func(c *fiber.Ctx) bool

	// AllowOrigin defines a comma separated list of origins that may access the resource.
	//
	// Optional. Default value "*"
	AllowOrigins string

	// AllowMethods defines a list methods allowed when accessing the resource.
	// This is used in response to a preflight request.
	//
	// Optional. Default value "GET,POST,HEAD,PUT,DELETE,PATCH"
	AllowMethods string

	// AllowHeaders defines a list of request headers that can be used when
	// making the actual request. This is in response to a preflight request.
	//
	// Optional. Default value "".
	AllowHeaders string

	// AllowCredentials indicates whether or not the response to the request
	// can be exposed when the credentials flag is true. When used as part of
	// a response to a preflight request, this indicates whether or not the
	// actual request can be made using credentials. Note: If true, AllowOrigins
	// cannot be set to a wildcard ("*") to prevent security vulnerabilities.
	//
	// Optional. Default value false.
	AllowCredentials bool

	// ExposeHeaders defines a whitelist headers that clients are allowed to
	// access.
	//
	// Optional. Default value "".
	ExposeHeaders string

	// MaxAge indicates how long (in seconds) the results of a preflight request
	// can be cached.
	//
	// Optional. Default value 0.
	MaxAge int
}

// ConfigDefault is the default config
var ConfigDefault = Config{
	Next:         nil,
	AllowOrigins: "*",
	AllowMethods: strings.Join([]string{
		fiber.MethodGet,
		fiber.MethodPost,
		fiber.MethodHead,
		fiber.MethodPut,
		fiber.MethodDelete,
		fiber.MethodPatch,
	}, ","),
	AllowHeaders:     "",
	AllowCredentials: false,
	ExposeHeaders:    "",
	MaxAge:           0,
}

// normalizeOrigin validates an HTTP(S) origin and removes a trailing slash.
func normalizeOrigin(origin string) (bool, string) {
	parsed, err := url.Parse(origin)
	if err != nil || (parsed.Scheme != "http" && parsed.Scheme != "https") ||
		parsed.Host == "" || (parsed.Path != "" && parsed.Path != "/") ||
		parsed.RawQuery != "" || parsed.Fragment != "" {
		return false, ""
	}
	return true, strings.ToLower(parsed.Scheme) + "://" + strings.ToLower(parsed.Host)
}

// validateDomain retains scheme, port and subdomain boundaries when matching.
func validateDomain(domain, pattern string) bool {
	if domain == pattern {
		return true
	}
	valid, normalizedDomain := normalizeOrigin(domain)
	if !valid || normalizedDomain != domain {
		return false
	}
	schemeEnd := strings.Index(pattern, "://")
	if schemeEnd == -1 {
		return false
	}
	host := pattern[schemeEnd+3:]
	return strings.HasPrefix(host, "*.") && strings.Count(host, "*") == 1 &&
		matchSubdomain(domain, pattern)
}

// New creates a new middleware handler
func New(config ...Config) fiber.Handler {
	// Set default config
	cfg := ConfigDefault

	// Override config if provided
	if len(config) > 0 {
		cfg = config[0]

		// Set default values
		if cfg.AllowMethods == "" {
			cfg.AllowMethods = ConfigDefault.AllowMethods
		}
		if cfg.AllowOrigins == "" {
			cfg.AllowOrigins = ConfigDefault.AllowOrigins
		}
	}

	// Validate CORS credentials configuration
	if cfg.AllowCredentials && cfg.AllowOrigins == "*" {
		panic("[CORS] Insecure setup, 'AllowCredentials' is set to true, and 'AllowOrigins' is set to a wildcard.")
	}

	// Validate and normalize static AllowOrigins.
	if cfg.AllowOrigins != "" && cfg.AllowOrigins != "*" {
		validatedOrigins := []string{}
		for _, origin := range strings.Split(cfg.AllowOrigins, ",") {
			isValid, normalizedOrigin := normalizeOrigin(strings.TrimSpace(origin))
			if isValid {
				validatedOrigins = append(validatedOrigins, normalizedOrigin)
			} else {
				log.Printf("[CORS] Invalid origin format in configuration: %s", origin)
				panic("[CORS] Invalid origin provided in configuration")
			}
		}
		cfg.AllowOrigins = strings.Join(validatedOrigins, ",")
	}

	// Convert string to slice
	allowOrigins := strings.Split(strings.ReplaceAll(cfg.AllowOrigins, " ", ""), ",")

	// Strip white spaces
	allowMethods := strings.ReplaceAll(cfg.AllowMethods, " ", "")
	allowHeaders := strings.ReplaceAll(cfg.AllowHeaders, " ", "")
	exposeHeaders := strings.ReplaceAll(cfg.ExposeHeaders, " ", "")

	// Convert int to string
	maxAge := strconv.Itoa(cfg.MaxAge)

	// Return new handler
	return func(c *fiber.Ctx) error {
		// Don't execute middleware if Next returns true
		if cfg.Next != nil && cfg.Next(c) {
			return c.Next()
		}

		// Get origin header
		origin := c.Get(fiber.HeaderOrigin)
		allowOrigin := ""

		// Check allowed origins
		for _, o := range allowOrigins {
			if o == "*" {
				allowOrigin = "*"
				break
			}
			if validateDomain(origin, o) {
				allowOrigin = origin
				break
			}
		}

		// Simple request
		if c.Method() != fiber.MethodOptions {
			c.Vary(fiber.HeaderOrigin)
			c.Set(fiber.HeaderAccessControlAllowOrigin, allowOrigin)

			if cfg.AllowCredentials {
				c.Set(fiber.HeaderAccessControlAllowCredentials, "true")
			}
			if exposeHeaders != "" {
				c.Set(fiber.HeaderAccessControlExposeHeaders, exposeHeaders)
			}
			return c.Next()
		}

		// Preflight request
		c.Vary(fiber.HeaderOrigin)
		c.Vary(fiber.HeaderAccessControlRequestMethod)
		c.Vary(fiber.HeaderAccessControlRequestHeaders)
		c.Set(fiber.HeaderAccessControlAllowOrigin, allowOrigin)
		c.Set(fiber.HeaderAccessControlAllowMethods, allowMethods)

		// Set Allow-Credentials only for a specific allowed origin.
		if cfg.AllowCredentials {
			if allowOrigin != "*" && allowOrigin != "" {
				c.Set(fiber.HeaderAccessControlAllowCredentials, "true")
			} else if allowOrigin == "*" {
				log.Printf("[CORS] 'AllowCredentials' is true, but 'AllowOrigins' cannot be set to '*'.")
			}
		}

		// Set Allow-Headers if not empty
		if allowHeaders != "" {
			c.Set(fiber.HeaderAccessControlAllowHeaders, allowHeaders)
		} else {
			h := c.Get(fiber.HeaderAccessControlRequestHeaders)
			if h != "" {
				c.Set(fiber.HeaderAccessControlAllowHeaders, h)
			}
		}

		// Set MaxAge is set
		if cfg.MaxAge > 0 {
			c.Set(fiber.HeaderAccessControlMaxAge, maxAge)
		}

		// Send 204 No Content
		return c.SendStatus(fiber.StatusNoContent)
	}
}
