package types

import (
	"context"

	http_utils "github.com/zitadel/zitadel/internal/api/http"
	"github.com/zitadel/zitadel/internal/api/ui/console"
	"github.com/zitadel/zitadel/internal/domain"
	"github.com/zitadel/zitadel/internal/query"
)

func (notify Notify) SendPasswordChange(ctx context.Context, user *query.NotifyUser, org *query.Org, policy *query.LoginPolicy) error {
	url := console.LoginHintLink(http_utils.ComposedOrigin(ctx), user.PreferredLoginName)
	if policy != nil && policy.DefaultRedirectURI != "" {
		url = policy.DefaultRedirectURI + "?login_hint=" + user.PreferredLoginName
	}
	args := make(map[string]interface{})
	orgName := ""
	if org != nil && org.Name != "" {
		orgName = org.Name
	}
	args["OrgName"] = orgName
	return notify(url, args, domain.PasswordChangeMessageType, true)
}
