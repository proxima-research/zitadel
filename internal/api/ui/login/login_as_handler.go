package login

import (
	"context"
	http_mw "github.com/zitadel/zitadel/internal/api/http/middleware"
	"github.com/zitadel/zitadel/internal/auth/repository/eventsourcing"
	"github.com/zitadel/zitadel/internal/domain"
	"github.com/zitadel/zitadel/internal/zerrors"
	"net/http"
)

const (
	tmplLoginAs = "loginas"
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

	userRoles, err := l.query.GetUserRoles(r.Context(), authReq.UserID)
	if err != nil {
		l.renderLoginAs(w, r, authReq, err)
		return
	}

	if len(userRoles) != 0 {
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
		Users    []*domain.UserLoginAs
	}{
		l.getUserData(r, authReq, translator, "Login.Title", "Login.Description", errID, errMessage),
		authReq.UserID,
		d.Search,
		d.Page - 1,
		d.Page,
		nextPage,
		users,
	}

	l.renderer.RenderTemplate(w, r, translator, l.renderer.Templates[tmplLoginAs], data, nil)
}

func (l *Login) checkUserResourceOwner(r *http.Request, userID, userOrigID string) error {
	if userID != userOrigID {
		i, _ := l.query.Instance(r.Context(), false)
		u, _ := l.query.GetUserByID(r.Context(), false, userID)
		uo, _ := l.query.GetUserByID(r.Context(), false, userOrigID)
		if uo.ResourceOwner != i.DefaultOrgID && uo.ResourceOwner != u.ResourceOwner {
			return zerrors.ThrowPermissionDenied(nil, "AUTH-Bss7s", "Orig and target users belong to different orgs")
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

func (l *Login) usersForLoginAs(ctx context.Context, orgId string, search string, page int) ([]*domain.UserLoginAs, bool, error) {
	users, err := l.query.SearchUsersForLoginAs(ctx, orgId, search, page)
	if err != nil {
		return nil, false, err
	}
	var usersLoginAs = make([]*domain.UserLoginAs, 0, len(users.Users))
	for _, user := range users.Users {
		loginName := user.Username
		if user.PreferredLoginName != "" {
			loginName = user.PreferredLoginName
		}

		usersLoginAs = append(usersLoginAs, &domain.UserLoginAs{
			UserID:        user.ID,
			LoginName:     loginName,
			Username:      user.Human.DisplayName,
			Email:         string(user.Human.Email),
			AvatarKey:     user.Human.AvatarKey,
			ResourceOwner: user.ResourceOwner,
		})
	}
	nextUsers, err := l.query.SearchUsersForLoginAs(ctx, orgId, search, page+1)
	if err != nil {
		return nil, false, err
	}
	return usersLoginAs, nextUsers.Count > 0, nil
}
