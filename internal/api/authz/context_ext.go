package authz

import "context"

type authRequestIdKey struct{}

var _authRequestIdKey *authRequestIdKey = (*authRequestIdKey)(nil)

func SetAuthRequestIdToCtx(ctx context.Context, id string) context.Context {
	return context.WithValue(ctx, _authRequestIdKey, id)
}

func GetAuthRequestIdFromCtx(ctx context.Context) string {
	v, _ := ctx.Value(_authRequestIdKey).(string)
	return v
}
