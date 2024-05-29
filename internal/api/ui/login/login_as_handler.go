package login

import (
	"context"
	http_mw "github.com/zitadel/zitadel/internal/api/http/middleware"
	"github.com/zitadel/zitadel/internal/auth/repository/eventsourcing"
	"github.com/zitadel/zitadel/internal/domain"
	"github.com/zitadel/zitadel/internal/query"
	"github.com/zitadel/zitadel/internal/zerrors"
	"net/http"
	"strings"
)

const (
	tmplLoginAs = "loginas"
	pageSize    = 10
)

type loginAsCheck struct {
	LoginAsName string `schema:"loginAsName"`
}

type loginAs struct {
	Search string `schema:"search"`
	Page   int    `schema:"page"`
}

func (l *Login) handleLoginAsCheck(w http.ResponseWriter, r *http.Request) {
	d := new(loginAsCheck)
	authReq, err := l.getAuthRequestAndParseData(r, d)
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
	authReq, err = l.checkLoginNameAndGetAuthRequest(r, authReq.ID, d.LoginAsName, userAgentID)
	if err != nil {
		l.renderLoginAs(w, r, authReq, err)
		return
	}

	err = l.checkUserResourceOwner(r, authReq.UserID, userOrigID)
	if err != nil {
		authReq, _ = l.checkLoginNameAndGetAuthRequest(r, authReq.ID, userOrigLoginName, userAgentID)
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

	d := new(loginAs)
	err = l.getParseData(r, d)
	if err != nil {
		l.renderError(w, r, authReq, err)
		return
	}

	users, hasNextPage, err := l.usersForLoginAs(r.Context(), authReq.RequestedOrgID, d.Search, d.Page)
	if err != nil {
		l.renderError(w, r, authReq, err)
		return
	}

	translator := l.getTranslator(r.Context(), authReq)
	nextPage := 0
	if hasNextPage {
		nextPage = d.Page + 1
	}
	data := &struct {
		userData
		UserId   string
		Search   string
		PrevPage int
		Page     int
		NextPage int
		Users    []domain.UserLoginAs
	}{
		l.getUserData(r, authReq, translator, "Login.Title", "Login.Description", errID, errMessage),
		authReq.UserID,
		d.Search,
		d.Page - 1,
		d.Page,
		nextPage,
		users,
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
	authReq, authReqErr := l.getAuthRequest(r)
	if err != nil {
		return authReq, err
	}
	return authReq, authReqErr
}

func (l *Login) usersForLoginAs(ctx context.Context, orgId string, search string, page int) ([]domain.UserLoginAs, bool, error) {
	userTypeSearchQuery, err := query.NewUserTypeSearchQuery(int32(domain.UserTypeHuman))
	if err != nil {
		return nil, false, err
	}

	notUsersWithLoginAsSearchQuery, err := query.NewNotUsersWithLoginAsSearchQuery()
	if err != nil {
		return nil, false, err
	}

	queries := &query.UserSearchQueries{
		SearchRequest: query.SearchRequest{
			Offset:        uint64(page * pageSize),
			Limit:         pageSize,
			SortingColumn: query.UserUsernameCol,
			Asc:           true,
		},
		Queries: []query.SearchQuery{
			userTypeSearchQuery,
			notUsersWithLoginAsSearchQuery,
			query.NewNotMembersSearchQuery(),
		},
	}

	if search != "" {
		userDisplayNameSearchQuery, err := query.NewUserUsernameSearchQuery(search, query.TextContainsIgnoreCase)
		if err != nil {
			return nil, false, err
		}
		userEmailSearchQuery, err := query.NewUserEmailSearchQuery(search, query.TextContainsIgnoreCase)
		if err != nil {
			return nil, false, err
		}
		userDisplayNameOrEmailSearchQuery, err := query.NewUserOrSearchQuery([]query.SearchQuery{
			userDisplayNameSearchQuery,
			userEmailSearchQuery,
		})
		if err != nil {
			return nil, false, err
		}
		queries.Queries = append(queries.Queries, userDisplayNameOrEmailSearchQuery)
	}

	if orgId != "" {
		grantedOrgIds, err := l.query.GetOrgGrantedOrgIds(ctx, orgId)
		if err != nil && !zerrors.IsNotFound(err) {
			return nil, false, err
		}
		userResourceOwnerSearchQuery, err := query.NewUserResourceOwnerSearchQuery(orgId, query.TextEquals)
		if err != nil {
			return nil, false, err
		}
		if len(grantedOrgIds) == 0 {
			queries.Queries = append(queries.Queries, userResourceOwnerSearchQuery)
		} else {
			userResourceOwnerOrGrantedOrgsSearchQuery, err := query.NewUserOrSearchQuery([]query.SearchQuery{
				userResourceOwnerSearchQuery,
				query.NewUserResourceOwnersSearchQuery(grantedOrgIds),
			})
			if err != nil {
				return nil, false, err
			}
			queries.Queries = append(queries.Queries, userResourceOwnerOrGrantedOrgsSearchQuery)
		}
	}

	users, err := l.query.SearchUsers(ctx, queries)
	if err != nil {
		return nil, false, err
	}
	var usersLoginAs = make([]domain.UserLoginAs, 0)
	for _, user := range users.Users {
		loginName := user.Username
		if user.PreferredLoginName != "" {
			loginName = user.PreferredLoginName
		}

		usersLoginAs = append(usersLoginAs, domain.UserLoginAs{
			UserID:        user.ID,
			LoginName:     loginName,
			Username:      user.Username,
			Email:         string(user.Human.Email),
			AvatarKey:     user.Human.AvatarKey,
			ResourceOwner: user.ResourceOwner,
		})
	}

	queries.SearchRequest.Offset += pageSize
	nextUsers, err := l.query.SearchUsers(ctx, queries)
	if err != nil {
		return nil, false, err
	}
	return usersLoginAs, len(nextUsers.Users) > 0, nil
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
