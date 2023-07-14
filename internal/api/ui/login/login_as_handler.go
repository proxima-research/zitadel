package login

import (
	"context"
	http_mw "github.com/zitadel/zitadel/internal/api/http/middleware"
	"github.com/zitadel/zitadel/internal/domain"
	"github.com/zitadel/zitadel/internal/errors"
	"github.com/zitadel/zitadel/internal/query"
	"net/http"
)

const (
	tmplLoginAs = "loginas"
)

type loginAsData struct {
	LoginAsName string `schema:"loginAsName"`
}

func (l *Login) handleLoginAsCheck(w http.ResponseWriter, r *http.Request) {
	data := new(loginAsData)
	authReq, err := l.getAuthRequestAndParseData(r, data)
	if err != nil {
		l.renderLogin(w, r, authReq, err)
		return
	}
	if authReq == nil {
		l.renderLogin(w, r, nil, errors.ThrowInvalidArgument(nil, "LOGIN-adrg3", "Errors.AuthRequest.NotFound"))
		return
	}
	userAgentID, _ := http_mw.UserAgentIDFromCtx(r.Context())
	loginName := data.LoginAsName
	err = l.authRepo.CheckLoginAsName(r.Context(), authReq.ID, loginName, userAgentID)
	if err != nil {
		l.renderLoginAs(w, r, authReq, err)
		return
	}
	l.renderNextStep(w, r, authReq)
}

func (l *Login) renderLoginAs(w http.ResponseWriter, r *http.Request, authReq *domain.AuthRequest, err error) {
	var errID, errMessage string
	if err != nil {
		errID, errMessage = l.getErrorMessage(r, err)
	}

	loginNames, err := l.getLoginNames(r.Context(), authReq.RequestedOrgID)
	if err != nil {
		l.renderError(w, r, authReq, err)
		return
	}

	data := &struct {
		userData
		LoginNames []string
	}{
		l.getUserData(r, authReq, "Login.Title", "Login.Description", errID, errMessage),
		loginNames,
	}

	l.renderer.RenderTemplate(w, r, l.getTranslator(r.Context(), authReq), l.renderer.Templates[tmplLoginAs], data, nil)
}

func (l *Login) getLoginNames(ctx context.Context, orgId string) ([]string, error) {
	userTypeSearchQuery, err := query.NewUserTypeSearchQuery(int32(domain.UserTypeHuman))
	if err != nil {
		return nil, err
	}

	queries := &query.UserSearchQueries{
		SearchRequest: query.SearchRequest{
			Offset:        0,
			Limit:         100,
			Asc:           true,
			SortingColumn: query.UserUsernameCol,
		},
		Queries: []query.SearchQuery{userTypeSearchQuery},
	}

	if orgId != "" {
		err = queries.AppendMyResourceOwnerQuery(orgId)
		if err != nil {
			return nil, err
		}
	}

	users, err := l.query.SearchUsers(ctx, queries, false)
	if err != nil {
		return nil, err
	}
	var loginNames = make([]string, len(users.Users))
	for i, user := range users.Users {
		if user.PreferredLoginName != "" {
			loginNames[i] = user.PreferredLoginName
		} else {
			loginNames[i] = user.Username
		}
	}
	return loginNames, nil
}
