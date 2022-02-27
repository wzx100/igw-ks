package onepower

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"github.com/mitchellh/mapstructure"
	"golang.org/x/oauth2"
	"io/ioutil"
	"kubesphere.io/kubesphere/pkg/apiserver/authentication/identityprovider"
	"kubesphere.io/kubesphere/pkg/apiserver/authentication/oauth"
	"net/http"
)



const (
	userInfoURL = "https://api.github.com/user"
	authURL     = "https://github.com/login/oauth/authorize"
	tokenURL    = "https://github.com/login/oauth/access_token"
)


func init() {
	identityprovider.RegisterOAuthProvider(&idpProviderFactory{})
}

type onepower struct {
	// ClientID is the application's ID.
	ClientID string `json:"clientID" yaml:"clientID"`

	// ClientSecret is the application's secret.
	ClientSecret string `json:"-" yaml:"clientSecret"`

	// Endpoint contains the resource server's token endpoint
	// URLs. These are constants specific to each server and are
	// often available via site-specific packages, such as
	// google.Endpoint or github.endpoint.
	Endpoint endpoint `json:"endpoint" yaml:"endpoint"`

	// RedirectURL is the URL to redirect users going through
	// the OAuth flow, after the resource owner's URLs.
	RedirectURL string `json:"redirectURL" yaml:"redirectURL"`

	// Used to turn off TLS certificate checks
	InsecureSkipVerify bool `json:"insecureSkipVerify" yaml:"insecureSkipVerify"`

	// Scope specifies optional requested permissions.
	Scopes []string `json:"scopes" yaml:"scopes"`

	Config *oauth2.Config `json:"-" yaml:"-"`
}


// endpoint represents an OAuth 2.0 provider's authorization and token
// endpoint URLs.
type endpoint struct {
	AuthURL     string `json:"authURL" yaml:"authURL"`
	TokenURL    string `json:"tokenURL" yaml:"tokenURL"`
	UserInfoURL string `json:"userInfoURL" yaml:"userInfoURL"`
}

type onepowerIdentity struct {
	AccountID string  `json:"accountID"`
	From      string         `json:"from,omitempty"`
	Nickname  string         `json:"nickname,omitempty"`
	Email     string         `json:"email,omitempty"`
	Mobile    string         `json:"email,omitempty"`
}

type idpProviderFactory struct {
}

func (o *idpProviderFactory) Type() string {
	return "OnepowerIdentityProvider"
}

func (o *idpProviderFactory) Create(options oauth.DynamicOptions) (identityprovider.OAuthProvider, error) {
	var op onepower
	if err := mapstructure.Decode(options, &op); err != nil {
		return nil, err
	}

	if op.Endpoint.AuthURL == "" {
		op.Endpoint.AuthURL = authURL
	}
	if op.Endpoint.TokenURL == "" {
		op.Endpoint.TokenURL = tokenURL
	}
	if op.Endpoint.UserInfoURL == "" {
		op.Endpoint.UserInfoURL = userInfoURL
	}
	// fixed options
	options["endpoint"] = oauth.DynamicOptions{
		"authURL":     op.Endpoint.AuthURL,
		"tokenURL":    op.Endpoint.TokenURL,
		"userInfoURL": op.Endpoint.UserInfoURL,
	}
	op.Config = &oauth2.Config{
		ClientID:     op.ClientID,
		ClientSecret: op.ClientSecret,
		Endpoint: oauth2.Endpoint{
			AuthURL:  op.Endpoint.AuthURL,
			TokenURL: op.Endpoint.TokenURL,
		},
		RedirectURL: op.RedirectURL,
		Scopes:      op.Scopes,
	}
	return &op, nil
}

func (o onepowerIdentity) GetUserID() string {
	return o.AccountID
}

func (o onepowerIdentity) GetUsername() string {
	return o.Nickname
}

func (o onepowerIdentity) GetEmail() string {
	return o.Email
}

func (o *onepower) IdentityExchangeCallback(req *http.Request) (identityprovider.Identity, error){
	code := req.URL.Query().Get("code")
	ctx := context.TODO()
	if o.InsecureSkipVerify {
		client := &http.Client{
			Transport: &http.Transport{
				TLSClientConfig: &tls.Config{
					InsecureSkipVerify: true,
				},
			},
		}
		ctx = context.WithValue(ctx, oauth2.HTTPClient, client)
	}
	token, err := o.Config.Exchange(ctx, code)
	if err != nil {
		return nil, err
	}
	resp, err := oauth2.NewClient(ctx, oauth2.StaticTokenSource(token)).Get(o.Endpoint.UserInfoURL)
	if err != nil {
		return nil, err
	}

	data, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	var onepowerIdentity onepowerIdentity
	err = json.Unmarshal(data, &onepowerIdentity)
	if err != nil {
		return nil, err
	}

	return onepowerIdentity, nil
}