package onepower

import (
	"context"
	"encoding/json"
	"fmt"
	"github.com/mitchellh/mapstructure"
	"io/ioutil"
	"kubesphere.io/kubesphere/pkg/apiserver/authentication/identityprovider"
	"kubesphere.io/kubesphere/pkg/apiserver/authentication/identityprovider/oauth2"
	"kubesphere.io/kubesphere/pkg/apiserver/authentication/oauth"
	"net/http"
)

const (
	//userInfoURL = "http://gzlwy.uat.internal.virtueit.net/v3/gateway/auth/v1.0.0/oauth/userInfo"
	//authURL     = "http://gzlwy.uat.internal.virtueit.net/v1/home/login"
	//tokenURL    = "http://gzlwy.uat.internal.virtueit.net/v3/gateway/auth/v1.0.0/oauth/token"
	userInfoURL = "https://onepower.ft.industry-cmcc.com/v3/gateway/auth/v1.0.0/oauth/userInfo"
	authURL     = "https://onepower.ft.industry-cmcc.com/login"
	tokenURL    = "https://onepower.ft.industry-cmcc.com/v3/gateway/auth/v1.0.0/oauth/token"
)

var opTokenMap = make(map[string]string)

func init() {
	identityprovider.RegisterOAuthProvider(&onepowerProviderFactory{})
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
	Code    string               `json:"code"`
	Message string               `json:"message"`
	Data    onepowerIdentityData `json:"data"`
}

type onepowerIdentityData struct {
	AccountID string `json:"accountName"`
	Nickname  string `json:"userName,omitempty"`
	Email     string `json:"email,omitempty"`
	Mobile    string `json:"tel,omitempty"`
	//onepower中的id
	OnepowerID string `json:"id"`
	//租户ID
	TenantId         string `json:"tenantId"`
	OriginalUserId   string `json:"originalUserId"`
	OriginalTenantId string `json:"originalTenantId"`
	OriginalDeptId   string `json:"originalDeptId"`
	OpAccessToken    string `json:"opAccessToken"`
}

type onepowerProviderFactory struct {
}

func (o *onepowerProviderFactory) Type() string {
	return "OnepowerIdentityProvider"
}

func (o *onepowerProviderFactory) Create(options oauth.DynamicOptions) (identityprovider.OAuthProvider, error) {
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
	return o.Data.OnepowerID
}
func (o onepowerIdentity) GetOpuid() string {
	return o.Data.OriginalUserId
}

func (o onepowerIdentity) GetUsername() string {
	if o.Data.AccountID != "" {
		return o.Data.AccountID
	} else {
		return o.Data.Mobile
	}
}
func (o onepowerIdentity) GetDeptid() string {
	return o.Data.OriginalDeptId
}
func (o onepowerIdentity) GetCustomerId() string {
	return o.Data.OriginalUserId
}
func (o onepowerIdentity) GetTenantId() string {
	return o.Data.OriginalTenantId
}

func (o onepowerIdentity) GetEmail() string {
	return o.Data.Email
}
func (o onepowerIdentity) GetOpAccessToken() string {
	return o.Data.OpAccessToken
}

func GetOpToken() string {
	return opTokenMap["accessOpToken"]
}
func GetCustomerId() string {
	return opTokenMap["customerId"]
}
func GetDeptId() string {
	return opTokenMap["deptId"]
}
func GetTenantId() string {
	return opTokenMap["tenantId"]
}

func (o *onepower) IdentityExchangeCallback(req *http.Request) (identityprovider.Identity, error) {
	code := req.URL.Query().Get("code")
	ctx := context.TODO()

	//获取token
	token, err := o.Config.Exchange(ctx, code)
	if err != nil {
		return nil, err
	}
	fmt.Println("===========>登录跳转成功开始<=========")

	//存储token值
	opTokenMap["accessOpToken"] = token.AccessToken

	fmt.Println("OP单点登录跳转成功，token：" + token.AccessToken)
	userResp, err := oauth2.NewClient(ctx, oauth2.StaticTokenSource(token)).Get(o.Endpoint.UserInfoURL + "?token=" + token.AccessToken)
	if err != nil {
		return nil, err
	}

	data, err := ioutil.ReadAll(userResp.Body)
	if err != nil {
		return nil, err
	}
	defer userResp.Body.Close()

	var onepowerIdentity onepowerIdentity
	err = json.Unmarshal(data, &onepowerIdentity)
	onepowerIdentity.Data.OpAccessToken = token.AccessToken
	fmt.Println("=====customerId为:", onepowerIdentity.Data.OriginalUserId, "===========")
	fmt.Println("=====tenantId为:", onepowerIdentity.Data.OriginalTenantId, "===========")
	fmt.Println("=====deptId为:", onepowerIdentity.Data.OriginalDeptId, "===========")

	opTokenMap["customerId"] = onepowerIdentity.Data.OriginalUserId
	opTokenMap["tenantId"] = onepowerIdentity.Data.OriginalTenantId
	opTokenMap["deptId"] = onepowerIdentity.Data.OriginalDeptId

	if err != nil {
		return nil, err
	}

	return onepowerIdentity, nil
}
