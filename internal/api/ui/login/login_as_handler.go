package login

import (
	http_mw "github.com/zitadel/zitadel/internal/api/http/middleware"
	"github.com/zitadel/zitadel/internal/domain"
	"github.com/zitadel/zitadel/internal/errors"
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

	data := l.getUserData(r, authReq, "Login.Title", "Login.Description", errID, errMessage)

	l.renderer.RenderTemplate(w, r, l.getTranslator(r.Context(), authReq), l.renderer.Templates[tmplLoginAs], data, nil)
}
