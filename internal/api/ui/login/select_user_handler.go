package login

import (
	"net/http"

	"github.com/zitadel/zitadel/internal/domain"

	http_mw "github.com/zitadel/zitadel/internal/api/http/middleware"
)

const (
	tmplUserSelection = "userselection"
)

type userSelectionFormData struct {
	UserID  string `schema:"userID"`
	LoginAs bool   `schema:"loginAs"`
}

func (l *Login) renderUserSelection(w http.ResponseWriter, r *http.Request, authReq *domain.AuthRequest, selectionData *domain.SelectUserStep) {
	translator := l.getTranslator(r.Context(), authReq)

	linking := len(authReq.LinkingUsers) > 0

	titleI18nKey := "SelectAccount.Title"
	descriptionI18nKey := "SelectAccount.Description"
	if linking {
		titleI18nKey = "SelectAccount.TitleLinking"
		descriptionI18nKey = "SelectAccount.DescriptionLinking"
	}
	data := userSelectionData{
		baseData: l.getBaseData(r, authReq, titleI18nKey, descriptionI18nKey, "", ""),
		Users:    selectionData.Users,
		Linking:  linking,
	}
	l.renderer.RenderTemplate(w, r, translator, l.renderer.Templates[tmplUserSelection], data, nil)
}

func (l *Login) handleSelectUser(w http.ResponseWriter, r *http.Request) {
	data := new(userSelectionFormData)
	authSession, err := l.getAuthRequestAndParseData(r, data)

	authSession.LoginAs = data.LoginAs
	err = l.updateAuthRequest(r.Context(), authSession)
	if err != nil {
		l.renderError(w, r, authSession, err)
		return
	}

	if err != nil {
		l.renderError(w, r, authSession, err)
		return
	}
	if data.UserID == "0" {
		l.renderLogin(w, r, authSession, nil)
		return
	}
	userAgentID, _ := http_mw.UserAgentIDFromCtx(r.Context())
	err = l.authRepo.SelectUser(r.Context(), authSession.ID, data.UserID, userAgentID)
	if err != nil {
		l.renderError(w, r, authSession, err)
		return
	}
	l.renderNextStep(w, r, authSession)
}
