package setup

import (
	"context"
	_ "embed"

	"github.com/zitadel/zitadel/internal/database"
	"github.com/zitadel/zitadel/internal/eventstore"
)

var (
	//go:embed 25_add_auth_request_id_to_auth_tokens.sql
	addTokenAuthRequestId string
)

type AddAuthRequestIdToAuthTokens struct {
	dbClient *database.DB
}

func (mig *AddAuthRequestIdToAuthTokens) Execute(ctx context.Context, _ eventstore.Event) error {
	_, err := mig.dbClient.ExecContext(ctx, addTokenAuthRequestId)
	return err
}

func (mig *AddAuthRequestIdToAuthTokens) String() string {
	return "25_add_auth_request_id_to_auth_tokens"
}
