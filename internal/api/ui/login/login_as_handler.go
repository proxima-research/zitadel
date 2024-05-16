package login

import (
	"context"
	http_mw "github.com/zitadel/zitadel/internal/api/http/middleware"
	"github.com/zitadel/zitadel/internal/auth/repository/eventsourcing"
	"github.com/zitadel/zitadel/internal/domain"
	"github.com/zitadel/zitadel/internal/query"
	"github.com/zitadel/zitadel/internal/zerrors"
	"net/http"
	"sort"
	"strings"
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
		l.renderLoginAs(w, r, authReq, err)
		return
	}
	if authReq == nil {
		l.renderLoginAs(w, r, nil, zerrors.ThrowInvalidArgument(nil, "LOGIN-adrg3", "Errors.AuthRequest.NotFound"))
		return
	}

	userOrigID := authReq.UserID
	userOrigLoginName := authReq.LoginName

	userAgentID, _ := http_mw.UserAgentIDFromCtx(r.Context())
	loginName := strings.Split(data.LoginAsName, " / ")[0]
	authReq, err = l.checkLoginNameAndGetAuthRequest(r, authReq.ID, loginName, userAgentID)
	if err != nil {
		l.renderLoginAs(w, r, authReq, err)
		return
	}

	err = l.checkUserResourceOwner(r, authReq.UserID, userOrigID)
	if err != nil {
		l.renderLoginAs(w, r, authReq, err)
		return
	}

	userWithoutPrivileges, err := l.isUserWithoutPrivileges(r.Context(), authReq.UserID)
	if err != nil {
		l.renderLoginAs(w, r, authReq, err)
		return
	}

	if !userWithoutPrivileges {
		authReq, _ = l.checkLoginNameAndGetAuthRequest(r, authReq.ID, userOrigLoginName, userAgentID)
		l.renderLoginAs(w, r, authReq, zerrors.ThrowPermissionDenied(nil, "AUTH-Bds7d", "Selected user has privileges"))
		return
	}

	authReq.UserOrigID = &userOrigID
	err = l.updateAuthRequest(r, authReq)
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

	translator := l.getTranslator(r.Context(), authReq)
	data := &struct {
		userData
		LoginNames []string
	}{
		l.getUserData(r, authReq, translator, "Login.Title", "Login.Description", errID, errMessage),
		loginNames,
	}

	l.renderer.RenderTemplate(w, r, l.getTranslator(r.Context(), authReq), l.renderer.Templates[tmplLoginAs], data, nil)
}

func (l *Login) checkUserResourceOwner(r *http.Request, userID, userOrigID string) error {
	if userID != userOrigID {
		i, _ := l.query.Instance(r.Context(), false)
		u, _ := l.query.GetUserByID(r.Context(), false, userID)
		uo, _ := l.query.GetUserByID(r.Context(), false, userOrigID)
		if uo.ResourceOwner != i.DefaultOrgID && uo.ResourceOwner != u.ResourceOwner {
			return zerrors.ThrowPermissionDenied(nil, "AUTH-Bss7s", "Orig and target users belong to different orgs")
		}

		if uo.ResourceOwner == i.DefaultOrgID {
			um, _ := l.query.GetUserMetadataByKey(r.Context(), false, uo.ID, "LOGIN_AS_ORGS", false)
			if um != nil {
				umValue := strings.TrimSpace(string(um.Value))
				loginAsPossible := false
				if umValue != "" {
					orgIds := strings.Split(umValue, ",")
					for _, orgId := range orgIds {
						if strings.TrimSpace(orgId) == u.ResourceOwner {
							loginAsPossible = true
							break
						}
					}
				}
				if !loginAsPossible {
					return zerrors.ThrowPermissionDenied(nil, "AUTH-Bjj7s", "Target org is not set in login as orgs list")
				}
			}
		}
		return nil
	}
	return nil
}

func (l *Login) updateAuthRequest(r *http.Request, request *domain.AuthRequest) error {
	authRequestRepo, ok := l.authRepo.(*eventsourcing.EsRepository)
	var err error
	if ok {
		err = authRequestRepo.AuthRequests.UpdateAuthRequest(r.Context(), request)
	} else {
		err = zerrors.ThrowInternal(err, "AUTH-7Mssd", "unable assert interface to type")
	}
	return err
}

func (l *Login) checkLoginNameAndGetAuthRequest(r *http.Request, id, loginName, userAgentID string) (*domain.AuthRequest, error) {
	err := l.authRepo.CheckLoginName(r.Context(), id, loginName, userAgentID)
	if err != nil {
		return nil, err
	}
	return l.getAuthRequest(r)
}

func (l *Login) getLoginNames(ctx context.Context, orgId string) ([]string, error) {
	userTypeSearchQuery, err := query.NewUserTypeSearchQuery(int32(domain.UserTypeHuman))
	if err != nil {
		return nil, err
	}

	queries := &query.UserSearchQueries{
		SearchRequest: query.SearchRequest{
			Offset:        0,
			Limit:         1000,
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

	loginPolicy, err := l.query.LoginPolicyByID(ctx, false, orgId, false)
	if err != nil {
		return nil, err
	}
	users, err := l.query.SearchUsers(ctx, queries)
	if err != nil {
		return nil, err
	}
	var loginNames = make([]string, 0)
	for _, user := range users.Users {
		userWithoutPrivileges, err := l.isUserWithoutPrivileges(ctx, user.ID)
		if err != nil {
			return nil, err
		}
		if !userWithoutPrivileges {
			continue
		}
		loginNameParts := make([]string, 0)
		if user.PreferredLoginName != "" {
			loginNameParts = append(loginNameParts, user.PreferredLoginName)
		} else {
			loginNameParts = append(loginNameParts, user.Username)
		}
		if !loginPolicy.DisableLoginWithEmail && user.Human.IsEmailVerified {
			loginNameParts = append(loginNameParts, string(user.Human.Email))
		}
		loginNames = append(loginNames, strings.Join(loginNameParts, " / "))
	}
	sort.Strings(loginNames)
	return loginNames, nil
}

func (l *Login) getUserRoles(ctx context.Context, userId string) (map[string]struct{}, error) {
	userQuery, err := query.NewMembershipUserIDQuery(userId)
	if err != nil {
		return nil, err
	}
	memberships, err := l.query.Memberships(ctx, &query.MembershipSearchQuery{
		Queries: []query.SearchQuery{userQuery},
	}, false)
	if err != nil {
		return nil, err
	}
	rolesMap := make(map[string]struct{})
	for _, membership := range memberships.Memberships {
		for _, role := range membership.Roles {
			if _, ok := rolesMap[role]; !ok {
				rolesMap[role] = struct{}{}
			}
		}
	}
	return rolesMap, nil
}

func (l *Login) isUserWithoutPrivileges(ctx context.Context, userId string) (bool, error) {
	userRoles, err := l.getUserRoles(ctx, userId)
	if err != nil {
		return false, err
	}
	um, err := l.query.GetUserMetadataByKey(ctx, false, userId, "LOGIN_AS", false)
	if err != nil && !zerrors.IsNotFound(err) {
		return false, err
	}
	if um != nil && strings.ToUpper(string(um.Value)) == "ON" || len(userRoles) > 0 {
		return false, nil
	}
	return true, nil
}
