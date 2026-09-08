package service

import (
	"encoding/json"
	"net/http"
)

// Router returns the service's http.Handler. It uses net/http's method+pattern
// mux (Go 1.22+) so the routes read as the contract's paths, and wraps every
// account-scoped route in the auth middleware — the ONE place a request acquires
// its account claim. The health/readiness probes are mounted OUTSIDE the auth
// middleware (they opt out with `security: []` in the contract).
func (s *Service) Router() http.Handler {
	mux := http.NewServeMux()

	// System probes — unauthenticated (spec: security: []).
	mux.HandleFunc("GET /v1/healthz", s.handleHealth)
	mux.HandleFunc("GET /v1/readyz", s.handleReady)

	// Account-scoped API, all behind the token verifier. Each handler reads the
	// account from auth.FromContext, never from the request.
	api := http.NewServeMux()
	api.HandleFunc("GET /v1/assets/{assetId}/url", s.handleResolveDeliveryURL)
	api.HandleFunc("GET /v1/assets/{assetId}", s.handleGetAsset)
	api.HandleFunc("DELETE /v1/assets/{assetId}", s.handleDeleteAsset)
	api.HandleFunc("GET /v1/assets", s.handleListAssets)
	api.HandleFunc("POST /v1/assets/{assetId}/renditions", s.handleRequestRendition)
	api.HandleFunc("GET /v1/jobs/{jobId}", s.handleGetJob)
	api.HandleFunc("POST /v1/uploads", s.handleCreateUpload)
	api.HandleFunc("POST /v1/uploads/{uploadId}/finalize", s.handleFinalizeUpload)
	api.HandleFunc("POST /v1/grants", s.handleCreateGrant)
	api.HandleFunc("GET /v1/grants/{grantId}", s.handleGetGrant)
	api.HandleFunc("DELETE /v1/grants/{grantId}", s.handleRevokeGrant)

	mux.Handle("/v1/", s.verf.Middleware(api))
	return mux
}

// writeJSON writes v as JSON with the given status.
func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

// writeError writes the contract's structured Error. The message must NEVER
// contain another account's data (spec: Error.message).
func writeError(w http.ResponseWriter, status int, code, message string) {
	writeJSON(w, status, map[string]string{"code": code, "message": message})
}
