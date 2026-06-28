package auth

import (
	"testing"

	"github.com/golang-jwt/jwt/v5"
)

func svc(clientID string) *AuthService {
	return New(nil, "dev-secret", "", clientID, "", "")
}

func TestValidateIDTokenAudience(t *testing.T) {
	a := svc("reflag-client")

	tests := []struct {
		name    string
		aud     jwt.ClaimStrings
		wantErr bool
	}{
		{
			name: "valid single audience",
			aud:  jwt.ClaimStrings{"reflag-client"},
		},
		{
			name:    "missing audience",
			aud:     jwt.ClaimStrings{},
			wantErr: true,
		},
		{
			name:    "single wrong audience",
			aud:     jwt.ClaimStrings{"other-client"},
			wantErr: true,
		},
		{
			name:    "multiple audiences including client_id",
			aud:     jwt.ClaimStrings{"reflag-client", "other-client"},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			claims := &jwt.RegisteredClaims{Audience: tt.aud}
			err := a.validateIDTokenAudience(claims)
			if tt.wantErr && err == nil {
				t.Fatal("expected error, got nil")
			}
			if !tt.wantErr && err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
		})
	}
}
