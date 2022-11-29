package jwtmiddleware

import (
	"context"
	"fmt"
	"net/http"
)

// New constructs a new JWTMiddleware instance with the supplied options.
// It requires a ValidateToken function to be passed in, so it can
// properly validate tokens.
func Build(validateToken ValidateToken, opts ...Option) func(http.Handler) http.Handler {
	m := &JWTMiddleware{
		validateToken:       validateToken,
		errorHandler:        DefaultErrorHandler,
		credentialsOptional: false,
		tokenExtractor:      AuthHeaderTokenExtractor,
		validateOnOptions:   true,
	}

	for _, opt := range opts {
		opt(m)
	}

	return buildMiddleware(m.validateToken, m.errorHandler, m.credentialsOptional, m.tokenExtractor, m.validateOnOptions)
}

func buildMiddleware(validateToken ValidateToken,
	errorHandler ErrorHandler,
	credentialsOptional bool,
	tokenExtractor TokenExtractor,
	validateOnOptions bool) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// If we don't validate on OPTIONS and this is OPTIONS
			// then continue onto next without validating.
			if !validateOnOptions && r.Method == http.MethodOptions {
				next.ServeHTTP(w, r)
				return
			}

			token, err := tokenExtractor(r)
			if err != nil {
				// This is not ErrJWTMissing because an error here means that the
				// tokenExtractor had an error and _not_ that the token was missing.
				errorHandler(w, r, fmt.Errorf("error extracting token: %w", err))
				return
			}

			if token == "" {
				// If credentials are optional continue
				// onto next without validating.
				if credentialsOptional {
					next.ServeHTTP(w, r)
					return
				}

				// Credentials were not optional so we error.
				errorHandler(w, r, ErrJWTMissing)
				return
			}

			// Validate the token using the token validator.
			validToken, err := validateToken(r.Context(), token)
			if err != nil {
				errorHandler(w, r, &invalidError{details: err})
				return
			}

			// No err means we have a valid token, so set
			// it into the context and continue onto next.
			r = r.Clone(context.WithValue(r.Context(), ContextKey{}, validToken))
			next.ServeHTTP(w, r)
		})
	}
}
