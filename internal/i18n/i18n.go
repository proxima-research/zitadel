package i18n

import (
	"context"
	"encoding/json"
	"io/ioutil"
	"net/http"
	"os"
	"strings"

	"github.com/BurntSushi/toml"
	"github.com/grpc-ecosystem/go-grpc-middleware/util/metautils"
	"github.com/nicksnyder/go-i18n/v2/i18n"
	"github.com/zitadel/logging"
	"golang.org/x/text/language"
	"sigs.k8s.io/yaml"

	"github.com/zitadel/zitadel/internal/api/authz"
	http_util "github.com/zitadel/zitadel/internal/api/http"
	"github.com/zitadel/zitadel/internal/errors"
)

const (
	i18nPath = "/i18n"
)

type Translator struct {
	bundle             *i18n.Bundle
	cookieName         string
	cookieHandler      *http_util.CookieHandler
	preferredLanguages []string
}

type TranslatorConfig struct {
	DefaultLanguage language.Tag
	CookieName      string
}

type Message struct {
	ID   string
	Text string
}

func NewTranslator(dir http.FileSystem, defaultLanguage language.Tag, cookieName string) (*Translator, error) {
	t := new(Translator)
	var err error
	t.bundle, err = newBundle(dir, defaultLanguage)
	if err != nil {
		return nil, err
	}
	t.cookieHandler = http_util.NewCookieHandler()
	t.cookieName = cookieName
	return t, nil
}

func newBundle(dir http.FileSystem, defaultLanguage language.Tag) (*i18n.Bundle, error) {
	bundle := i18n.NewBundle(defaultLanguage)
	bundle.RegisterUnmarshalFunc("yaml", func(data []byte, v interface{}) error { return yaml.Unmarshal(data, v) })
	bundle.RegisterUnmarshalFunc("json", json.Unmarshal)
	bundle.RegisterUnmarshalFunc("toml", toml.Unmarshal)
	i18nDir, err := dir.Open(i18nPath)
	if err != nil {
		return nil, errors.ThrowNotFound(err, "I18N-MnXRie", "path not found")
	}
	defer i18nDir.Close()
	files, err := i18nDir.Readdir(0)
	if err != nil {
		return nil, errors.ThrowNotFound(err, "I18N-Gew23", "cannot read dir")
	}
	for _, file := range files {
		if err := addFileFromFileSystemToBundle(dir, bundle, file); err != nil {
			return nil, errors.ThrowNotFoundf(err, "I18N-ZS2AW", "cannot append file %s to Bundle", file.Name())
		}
	}
	return bundle, nil
}

func addFileFromFileSystemToBundle(dir http.FileSystem, bundle *i18n.Bundle, file os.FileInfo) error {
	f, err := dir.Open("/i18n/" + file.Name())
	if err != nil {
		return err
	}
	defer f.Close()
	content, err := ioutil.ReadAll(f)
	if err != nil {
		return err
	}
	_, err = bundle.ParseMessageFileBytes(content, file.Name())
	return err
}

func SupportedLanguages(dir http.FileSystem) ([]language.Tag, error) {
	i18nDir, err := dir.Open("/i18n")
	if err != nil {
		return nil, errors.ThrowNotFound(err, "I18N-Dbt42", "cannot open dir")
	}
	defer i18nDir.Close()
	files, err := i18nDir.Readdir(0)
	if err != nil {
		return nil, errors.ThrowNotFound(err, "I18N-Gh4zk", "cannot read dir")
	}
	languages := make([]language.Tag, 0, len(files))
	for _, file := range files {
		lang := language.Make(strings.TrimSuffix(file.Name(), ".yaml"))
		if lang != language.Und {
			languages = append(languages, lang)
		}
	}
	return languages, nil
}

func (t *Translator) SupportedLanguages() []language.Tag {
	return t.bundle.LanguageTags()
}

func (t *Translator) AddMessages(tag language.Tag, messages ...Message) error {
	if len(messages) == 0 {
		return nil
	}
	i18nMessages := make([]*i18n.Message, len(messages))
	for i, message := range messages {
		i18nMessages[i] = &i18n.Message{
			ID:    message.ID,
			Other: message.Text,
		}
	}
	return t.bundle.AddMessages(tag, i18nMessages...)
}

func (t *Translator) LocalizeFromRequest(r *http.Request, id string, args map[string]interface{}) string {
	return localize(t.localizerFromRequest(r), id, args)
}

func (t *Translator) LocalizeFromCtx(ctx context.Context, id string, args map[string]interface{}) string {
	return localize(t.localizerFromCtx(ctx), id, args)
}

func (t *Translator) Localize(id string, args map[string]interface{}, langs ...string) string {
	return localize(t.localizer(langs...), id, args)
}

func (t *Translator) LocalizeWithoutArgs(id string, langs ...string) string {
	return localize(t.localizer(langs...), id, map[string]interface{}{})
}

func (t *Translator) Lang(r *http.Request) language.Tag {
	matcher := language.NewMatcher(t.bundle.LanguageTags())
	tag, _ := language.MatchStrings(matcher, t.langsFromRequest(r)...)
	return tag
}

func (t *Translator) SetLangCookie(w http.ResponseWriter, r *http.Request, lang language.Tag) {
	t.cookieHandler.SetCookie(w, t.cookieName, r.Host, lang.String())
}

func (t *Translator) localizerFromRequest(r *http.Request) *i18n.Localizer {
	return t.localizer(t.langsFromRequest(r)...)
}

func (t *Translator) localizerFromCtx(ctx context.Context) *i18n.Localizer {
	return t.localizer(t.langsFromCtx(ctx)...)
}

func (t *Translator) localizer(langs ...string) *i18n.Localizer {
	langs = append(langs, "en")
	return i18n.NewLocalizer(t.bundle, langs...)
}

func (t *Translator) langsFromRequest(r *http.Request) []string {
	langs := t.preferredLanguages
	if r != nil {
		lang, err := t.cookieHandler.GetCookieValue(r, t.cookieName)
		if err == nil {
			langs = append(langs, lang)
		}
		langs = append(langs, r.Header.Get("Accept-Language"))
	}
	return langs
}

func (t *Translator) langsFromCtx(ctx context.Context) []string {
	langs := t.preferredLanguages
	if ctx != nil {
		ctxData := authz.GetCtxData(ctx)
		if ctxData.PreferredLanguage != language.Und.String() {
			langs = append(langs, authz.GetCtxData(ctx).PreferredLanguage)
		}
		langs = append(langs, getAcceptLanguageHeader(ctx))
	}
	return langs
}

func (t *Translator) SetPreferredLanguages(langs ...string) {
	t.preferredLanguages = langs
}

func getAcceptLanguageHeader(ctx context.Context) string {
	acceptLanguage := metautils.ExtractIncoming(ctx).Get("accept-language")
	if acceptLanguage != "" {
		return acceptLanguage
	}
	return metautils.ExtractIncoming(ctx).Get("grpcgateway-accept-language")
}

func localize(localizer *i18n.Localizer, id string, args map[string]interface{}) string {
	s, err := localizer.Localize(&i18n.LocalizeConfig{
		MessageID:    id,
		TemplateData: args,
	})
	if err != nil {
		logging.WithFields("id", id, "args", args).WithError(err).Warnf("missing translation")
		return id
	}
	return s
}
