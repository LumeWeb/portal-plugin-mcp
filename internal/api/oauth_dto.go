package api

// OAuthApproveRequest is the JSON body of the authorize POST (consent page
// approve/reject), RFC 6749 §4.1.1 consent step.
type OAuthApproveRequest struct {
	Approve bool `json:"approve"`
}

// OAuthRedirectResponse is the JSON response of the authorize POST. It carries
// the final client redirect URI (with code or error) that the consent page JS
// navigates the browser to.
type OAuthRedirectResponse struct {
	RedirectURI string `json:"redirect_uri"`
}

// OAuthTokenRequest represents the form-encoded OAuth token endpoint request
// (RFC 6749 §5). It is used for OpenAPI schema documentation only.
// Per RFC 6749 §4.1.3/§6 only grant_type (and client_id for unauthenticated
// public clients) is required; the remaining fields apply only to specific
// grant types. Fields omitted from the OpenAPI required list are marked
// omitempty below.
type OAuthTokenRequest struct {
	GrantType    string `json:"grant_type"`
	ClientID     string `json:"client_id"`
	Code         string `json:"code,omitempty"`
	RedirectURI  string `json:"redirect_uri,omitempty"`
	CodeVerifier string `json:"code_verifier,omitempty"`
	Resource     string `json:"resource,omitempty"`
	RefreshToken string `json:"refresh_token,omitempty"`
}

// OAuthRegisterRequest is the RFC 7591 §3.1 dynamic client registration
// request body.
type OAuthRegisterRequest struct {
	ClientName              string   `json:"client_name"`
	RedirectURIs            []string `json:"redirect_uris"`
	ApplicationType         string   `json:"application_type"`
	TokenEndpointAuthMethod string   `json:"token_endpoint_auth_method"`
	GrantTypes              []string `json:"grant_types"`
	ResponseTypes           []string `json:"response_types"`
}

// OAuthClientResponse is the RFC 7591 §3.2.1 client registration response.
type OAuthClientResponse struct {
	ClientID                string   `json:"client_id"`
	ClientName              string   `json:"client_name"`
	RedirectURIs            []string `json:"redirect_uris"`
	GrantTypes              []string `json:"grant_types"`
	ResponseTypes           []string `json:"response_types"`
	TokenEndpointAuthMethod string   `json:"token_endpoint_auth_method"`
}
