package command

import (
	"context"
	"testing"
	"time"

	"github.com/golang/mock/gomock"
	"github.com/stretchr/testify/assert"
	openid "github.com/zitadel/oidc/v2/pkg/oidc"
	"golang.org/x/text/language"

	"github.com/zitadel/zitadel/internal/api/authz"
	"github.com/zitadel/zitadel/internal/crypto"
	"github.com/zitadel/zitadel/internal/domain"
	"github.com/zitadel/zitadel/internal/errors"
	"github.com/zitadel/zitadel/internal/eventstore"
	"github.com/zitadel/zitadel/internal/eventstore/repository"
	"github.com/zitadel/zitadel/internal/eventstore/v1/models"
	"github.com/zitadel/zitadel/internal/id"
	id_mock "github.com/zitadel/zitadel/internal/id/mock"
	"github.com/zitadel/zitadel/internal/repository/member"
	"github.com/zitadel/zitadel/internal/repository/org"
	"github.com/zitadel/zitadel/internal/repository/project"
	"github.com/zitadel/zitadel/internal/repository/user"
)

func TestAddOrg(t *testing.T) {
	type args struct {
		a    *org.Aggregate
		name string
	}

	ctx := context.Background()
	agg := org.NewAggregate("test")

	tests := []struct {
		name string
		args args
		want Want
	}{
		{
			name: "invalid domain",
			args: args{
				a:    agg,
				name: "",
			},
			want: Want{
				ValidationErr: errors.ThrowInvalidArgument(nil, "ORG-mruNY", "Errors.Invalid.Argument"),
			},
		},
		{
			name: "correct",
			args: args{
				a:    agg,
				name: "caos ag",
			},
			want: Want{
				Commands: []eventstore.Command{
					org.NewOrgAddedEvent(ctx, &agg.Aggregate, "caos ag"),
					org.NewDomainAddedEvent(ctx, &agg.Aggregate, "caos-ag.localhost"),
					org.NewDomainVerifiedEvent(ctx, &agg.Aggregate, "caos-ag.localhost"),
					org.NewDomainPrimarySetEvent(ctx, &agg.Aggregate, "caos-ag.localhost"),
				},
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			AssertValidation(t, context.Background(), AddOrgCommand(authz.WithRequestedDomain(context.Background(), "localhost"), tt.args.a, tt.args.name), nil, tt.want)
		})
	}
}

func TestCommandSide_AddOrg(t *testing.T) {
	type fields struct {
		eventstore   *eventstore.Eventstore
		idGenerator  id.Generator
		zitadelRoles []authz.RoleMapping
	}
	type args struct {
		ctx            context.Context
		name           string
		userID         string
		resourceOwner  string
		claimedUserIDs []string
	}
	type res struct {
		want *domain.Org
		err  func(error) bool
	}
	tests := []struct {
		name   string
		fields fields
		args   args
		res    res
	}{
		{
			name: "invalid org, error",
			fields: fields{
				eventstore: eventstoreExpect(
					t,
				),
			},
			args: args{
				ctx:           context.Background(),
				userID:        "user1",
				resourceOwner: "org1",
			},
			res: res{
				err: errors.IsErrorInvalidArgument,
			},
		},
		{
			name: "invalid org (spaces), error",
			fields: fields{
				eventstore: eventstoreExpect(
					t,
				),
			},
			args: args{
				ctx:           context.Background(),
				userID:        "user1",
				resourceOwner: "org1",
				name:          "  ",
			},
			res: res{
				err: errors.IsErrorInvalidArgument,
			},
		},
		{
			name: "user removed, error",
			fields: fields{
				eventstore: eventstoreExpect(
					t,
					expectFilterOrgDomainNotFound(),
					expectFilter(
						eventFromEventPusher(
							user.NewHumanAddedEvent(context.Background(),
								&user.NewAggregate("user1", "org1").Aggregate,
								"username1",
								"firstname1",
								"lastname1",
								"nickname1",
								"displayname1",
								language.German,
								domain.GenderMale,
								"email1",
								true,
							),
						),
						eventFromEventPusher(
							user.NewUserRemovedEvent(
								context.Background(),
								&user.NewAggregate("user1", "org1").Aggregate,
								"username1",
								nil,
								true,
							),
						),
					),
				),
				idGenerator: id_mock.NewIDGeneratorExpectIDs(t, "org2"),
			},
			args: args{
				ctx:           context.Background(),
				name:          "Org",
				userID:        "user1",
				resourceOwner: "org1",
			},
			res: res{
				err: errors.IsPreconditionFailed,
			},
		},
		{
			name: "push failed unique constraint, error",
			fields: fields{
				eventstore: eventstoreExpect(
					t,
					expectFilterOrgDomainNotFound(),
					expectFilter(
						eventFromEventPusher(
							user.NewHumanAddedEvent(context.Background(),
								&user.NewAggregate("user1", "org1").Aggregate,
								"username1",
								"firstname1",
								"lastname1",
								"nickname1",
								"displayname1",
								language.German,
								domain.GenderMale,
								"email1",
								true,
							),
						),
					),
					expectFilterOrgMemberNotFound(),
					expectPushFailed(errors.ThrowAlreadyExists(nil, "id", "internal"),
						[]*repository.Event{
							eventFromEventPusher(org.NewOrgAddedEvent(
								context.Background(),
								&org.NewAggregate("org2").Aggregate,
								"Org")),
							eventFromEventPusher(org.NewDomainAddedEvent(
								context.Background(),
								&org.NewAggregate("org2").Aggregate,
								"org.iam-domain")),
							eventFromEventPusher(org.NewDomainVerifiedEvent(
								context.Background(),
								&org.NewAggregate("org2").Aggregate,
								"org.iam-domain")),
							eventFromEventPusher(org.NewDomainPrimarySetEvent(
								context.Background(),
								&org.NewAggregate("org2").Aggregate,
								"org.iam-domain")),
							eventFromEventPusher(org.NewMemberAddedEvent(
								context.Background(),
								&org.NewAggregate("org2").Aggregate,
								"user1", domain.RoleOrgOwner)),
						},
						uniqueConstraintsFromEventConstraint(org.NewAddOrgNameUniqueConstraint("Org")),
						uniqueConstraintsFromEventConstraint(org.NewAddOrgDomainUniqueConstraint("org.iam-domain")),
						uniqueConstraintsFromEventConstraint(member.NewAddMemberUniqueConstraint("org2", "user1")),
					),
				),
				idGenerator: id_mock.NewIDGeneratorExpectIDs(t, "org2"),
				zitadelRoles: []authz.RoleMapping{
					{
						Role: "ORG_OWNER",
					},
				},
			},
			args: args{
				ctx:           authz.WithRequestedDomain(context.Background(), "iam-domain"),
				name:          "Org",
				userID:        "user1",
				resourceOwner: "org1",
			},
			res: res{
				err: errors.IsErrorAlreadyExists,
			},
		},
		{
			name: "push failed, error",
			fields: fields{
				eventstore: eventstoreExpect(
					t,
					expectFilterOrgDomainNotFound(),
					expectFilter(
						eventFromEventPusher(
							user.NewHumanAddedEvent(context.Background(),
								&user.NewAggregate("user1", "org1").Aggregate,
								"username1",
								"firstname1",
								"lastname1",
								"nickname1",
								"displayname1",
								language.German,
								domain.GenderMale,
								"email1",
								true,
							),
						),
					),
					expectFilterOrgMemberNotFound(),
					expectPushFailed(errors.ThrowInternal(nil, "id", "internal"),
						[]*repository.Event{
							eventFromEventPusher(org.NewOrgAddedEvent(
								context.Background(),
								&org.NewAggregate("org2").Aggregate,
								"Org")),
							eventFromEventPusher(org.NewDomainAddedEvent(
								context.Background(),
								&org.NewAggregate("org2").Aggregate,
								"org.iam-domain")),
							eventFromEventPusher(org.NewDomainVerifiedEvent(
								context.Background(),
								&org.NewAggregate("org2").Aggregate,
								"org.iam-domain")),
							eventFromEventPusher(org.NewDomainPrimarySetEvent(
								context.Background(),
								&org.NewAggregate("org2").Aggregate,
								"org.iam-domain")),
							eventFromEventPusher(org.NewMemberAddedEvent(
								context.Background(),
								&org.NewAggregate("org2").Aggregate,
								"user1", domain.RoleOrgOwner)),
						},
						uniqueConstraintsFromEventConstraint(org.NewAddOrgNameUniqueConstraint("Org")),
						uniqueConstraintsFromEventConstraint(org.NewAddOrgDomainUniqueConstraint("org.iam-domain")),
						uniqueConstraintsFromEventConstraint(member.NewAddMemberUniqueConstraint("org2", "user1")),
					),
				),
				idGenerator: id_mock.NewIDGeneratorExpectIDs(t, "org2"),
				zitadelRoles: []authz.RoleMapping{
					{
						Role: "ORG_OWNER",
					},
				},
			},
			args: args{
				ctx:           authz.WithRequestedDomain(context.Background(), "iam-domain"),
				name:          "Org",
				userID:        "user1",
				resourceOwner: "org1",
			},
			res: res{
				err: errors.IsInternal,
			},
		},
		{
			name: "add org, no error",
			fields: fields{
				eventstore: eventstoreExpect(
					t,
					expectFilterOrgDomainNotFound(),
					expectFilter(
						eventFromEventPusher(
							user.NewHumanAddedEvent(context.Background(),
								&user.NewAggregate("user1", "org1").Aggregate,
								"username1",
								"firstname1",
								"lastname1",
								"nickname1",
								"displayname1",
								language.German,
								domain.GenderMale,
								"email1",
								true,
							),
						),
					),
					expectFilterOrgMemberNotFound(),
					expectPush(
						[]*repository.Event{
							eventFromEventPusher(org.NewOrgAddedEvent(context.Background(),
								&org.NewAggregate("org2").Aggregate,
								"Org",
							)),
							eventFromEventPusher(org.NewDomainAddedEvent(context.Background(),
								&org.NewAggregate("org2").Aggregate, "org.iam-domain",
							)),
							eventFromEventPusher(org.NewDomainVerifiedEvent(context.Background(),
								&org.NewAggregate("org2").Aggregate,
								"org.iam-domain",
							)),
							eventFromEventPusher(org.NewDomainPrimarySetEvent(context.Background(),
								&org.NewAggregate("org2").Aggregate,
								"org.iam-domain",
							)),
							eventFromEventPusher(org.NewMemberAddedEvent(context.Background(),
								&org.NewAggregate("org2").Aggregate,
								"user1",
								domain.RoleOrgOwner,
							)),
						},
						uniqueConstraintsFromEventConstraint(org.NewAddOrgNameUniqueConstraint("Org")),
						uniqueConstraintsFromEventConstraint(org.NewAddOrgDomainUniqueConstraint("org.iam-domain")),
						uniqueConstraintsFromEventConstraint(member.NewAddMemberUniqueConstraint("org2", "user1")),
					),
				),
				idGenerator: id_mock.NewIDGeneratorExpectIDs(t, "org2"),
				zitadelRoles: []authz.RoleMapping{
					{
						Role: "ORG_OWNER",
					},
				},
			},
			args: args{
				ctx:           authz.WithRequestedDomain(context.Background(), "iam-domain"),
				name:          "Org",
				userID:        "user1",
				resourceOwner: "org1",
			},
			res: res{
				want: &domain.Org{
					ObjectRoot: models.ObjectRoot{
						AggregateID:   "org2",
						ResourceOwner: "org2",
					},
					Name:          "Org",
					State:         domain.OrgStateActive,
					PrimaryDomain: "org.iam-domain",
				},
			},
		},
		{
			name: "add org (remove spaces), no error",
			fields: fields{
				eventstore: eventstoreExpect(
					t,
					expectFilterOrgDomainNotFound(),
					expectFilter(
						eventFromEventPusher(
							user.NewHumanAddedEvent(context.Background(),
								&user.NewAggregate("user1", "org1").Aggregate,
								"username1",
								"firstname1",
								"lastname1",
								"nickname1",
								"displayname1",
								language.German,
								domain.GenderMale,
								"email1",
								true,
							),
						),
					),
					expectFilterOrgMemberNotFound(),
					expectPush(
						[]*repository.Event{
							eventFromEventPusher(org.NewOrgAddedEvent(context.Background(),
								&org.NewAggregate("org2").Aggregate,
								"Org",
							)),
							eventFromEventPusher(org.NewDomainAddedEvent(context.Background(),
								&org.NewAggregate("org2").Aggregate, "org.iam-domain",
							)),
							eventFromEventPusher(org.NewDomainVerifiedEvent(context.Background(),
								&org.NewAggregate("org2").Aggregate,
								"org.iam-domain",
							)),
							eventFromEventPusher(org.NewDomainPrimarySetEvent(context.Background(),
								&org.NewAggregate("org2").Aggregate,
								"org.iam-domain",
							)),
							eventFromEventPusher(org.NewMemberAddedEvent(context.Background(),
								&org.NewAggregate("org2").Aggregate,
								"user1",
								domain.RoleOrgOwner,
							)),
						},
						uniqueConstraintsFromEventConstraint(org.NewAddOrgNameUniqueConstraint("Org")),
						uniqueConstraintsFromEventConstraint(org.NewAddOrgDomainUniqueConstraint("org.iam-domain")),
						uniqueConstraintsFromEventConstraint(member.NewAddMemberUniqueConstraint("org2", "user1")),
					),
				),
				idGenerator: id_mock.NewIDGeneratorExpectIDs(t, "org2"),
				zitadelRoles: []authz.RoleMapping{
					{
						Role: "ORG_OWNER",
					},
				},
			},
			args: args{
				ctx:           authz.WithRequestedDomain(context.Background(), "iam-domain"),
				name:          " Org ",
				userID:        "user1",
				resourceOwner: "org1",
			},
			res: res{
				want: &domain.Org{
					ObjectRoot: models.ObjectRoot{
						AggregateID:   "org2",
						ResourceOwner: "org2",
					},
					Name:          "Org",
					State:         domain.OrgStateActive,
					PrimaryDomain: "org.iam-domain",
				},
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := &Commands{
				eventstore:   tt.fields.eventstore,
				idGenerator:  tt.fields.idGenerator,
				zitadelRoles: tt.fields.zitadelRoles,
			}
			got, err := r.AddOrg(tt.args.ctx, tt.args.name, tt.args.userID, tt.args.resourceOwner, tt.args.claimedUserIDs)
			if tt.res.err == nil {
				assert.NoError(t, err)
			}
			if tt.res.err != nil && !tt.res.err(err) {
				t.Errorf("got wrong err: %v ", err)
			}
			if tt.res.err == nil {
				assert.Equal(t, tt.res.want, got)
			}
		})
	}
}

func TestCommandSide_ChangeOrg(t *testing.T) {
	type fields struct {
		eventstore *eventstore.Eventstore
	}
	type args struct {
		ctx   context.Context
		orgID string
		name  string
	}
	type res struct {
		err func(error) bool
	}
	tests := []struct {
		name   string
		fields fields
		args   args
		res    res
	}{
		{
			name: "empty name, invalid argument error",
			fields: fields{
				eventstore: eventstoreExpect(
					t,
				),
			},
			args: args{
				ctx:   context.Background(),
				orgID: "org1",
			},
			res: res{
				err: errors.IsErrorInvalidArgument,
			},
		},
		{
			name: "empty name (spaces), invalid argument error",
			fields: fields{
				eventstore: eventstoreExpect(
					t,
				),
			},
			args: args{
				ctx:   context.Background(),
				orgID: "org1",
				name:  "  ",
			},
			res: res{
				err: errors.IsErrorInvalidArgument,
			},
		},
		{
			name: "org not found, error",
			fields: fields{
				eventstore: eventstoreExpect(
					t,
					expectFilter(),
				),
			},
			args: args{
				ctx:   context.Background(),
				orgID: "org1",
				name:  "org",
			},
			res: res{
				err: errors.IsNotFound,
			},
		},
		{
			name: "no change (spaces), error",
			fields: fields{
				eventstore: eventstoreExpect(
					t,
					expectFilter(
						eventFromEventPusher(
							org.NewOrgAddedEvent(context.Background(),
								&org.NewAggregate("org1").Aggregate,
								"org"),
						),
					),
				),
			},
			args: args{
				ctx:   authz.WithRequestedDomain(context.Background(), "zitadel.ch"),
				orgID: "org1",
				name:  " org ",
			},
			res: res{
				err: errors.IsPreconditionFailed,
			},
		},
		{
			name: "push failed, error",
			fields: fields{
				eventstore: eventstoreExpect(
					t,
					expectFilter(
						eventFromEventPusher(
							org.NewOrgAddedEvent(context.Background(),
								&org.NewAggregate("org1").Aggregate,
								"org"),
						),
					),
					expectFilter(),
					expectPushFailed(
						errors.ThrowInternal(nil, "id", "message"),
						[]*repository.Event{
							eventFromEventPusher(org.NewOrgChangedEvent(context.Background(),
								&org.NewAggregate("org1").Aggregate, "org", "neworg")),
						},
						uniqueConstraintsFromEventConstraint(org.NewRemoveOrgNameUniqueConstraint("org")),
						uniqueConstraintsFromEventConstraint(org.NewAddOrgNameUniqueConstraint("neworg")),
					),
				),
			},
			args: args{
				ctx:   authz.WithRequestedDomain(context.Background(), "zitadel.ch"),
				orgID: "org1",
				name:  "neworg",
			},
			res: res{
				err: errors.IsInternal,
			},
		},
		{
			name: "change org name verified, not primary",
			fields: fields{
				eventstore: eventstoreExpect(
					t,
					expectFilter(
						eventFromEventPusher(
							org.NewOrgAddedEvent(context.Background(),
								&org.NewAggregate("org1").Aggregate,
								"org"),
						),
					),
					expectFilter(
						eventFromEventPusher(
							org.NewOrgAddedEvent(context.Background(),
								&org.NewAggregate("org1").Aggregate,
								"org"),
						),
						eventFromEventPusher(
							org.NewDomainAddedEvent(context.Background(),
								&org.NewAggregate("org1").Aggregate,
								"org.zitadel.ch"),
						),
						eventFromEventPusher(
							org.NewDomainVerifiedEvent(context.Background(),
								&org.NewAggregate("org1").Aggregate,
								"org.zitadel.ch"),
						),
					),
					expectPush(
						[]*repository.Event{
							eventFromEventPusher(org.NewOrgChangedEvent(context.Background(),
								&org.NewAggregate("org1").Aggregate, "org", "neworg")),
							eventFromEventPusher(org.NewDomainAddedEvent(context.Background(),
								&org.NewAggregate("org1").Aggregate, "neworg.zitadel.ch")),
							eventFromEventPusher(org.NewDomainVerifiedEvent(context.Background(),
								&org.NewAggregate("org1").Aggregate, "neworg.zitadel.ch")),
							eventFromEventPusher(org.NewDomainRemovedEvent(context.Background(),
								&org.NewAggregate("org1").Aggregate, "org.zitadel.ch", true)),
						},
						uniqueConstraintsFromEventConstraint(org.NewRemoveOrgNameUniqueConstraint("org")),
						uniqueConstraintsFromEventConstraint(org.NewAddOrgNameUniqueConstraint("neworg")),
						uniqueConstraintsFromEventConstraint(org.NewAddOrgDomainUniqueConstraint("neworg.zitadel.ch")),
						uniqueConstraintsFromEventConstraint(org.NewRemoveOrgDomainUniqueConstraint("org.zitadel.ch")),
					),
				),
			},
			args: args{
				ctx:   authz.WithRequestedDomain(context.Background(), "zitadel.ch"),
				orgID: "org1",
				name:  "neworg",
			},
			res: res{},
		},
		{
			name: "change org name verified, with primary",
			fields: fields{
				eventstore: eventstoreExpect(
					t,
					expectFilter(
						eventFromEventPusher(
							org.NewOrgAddedEvent(context.Background(),
								&org.NewAggregate("org1").Aggregate,
								"org"),
						),
					),
					expectFilter(
						eventFromEventPusher(
							org.NewOrgAddedEvent(context.Background(),
								&org.NewAggregate("org1").Aggregate,
								"org"),
						),
						eventFromEventPusher(
							org.NewDomainAddedEvent(context.Background(),
								&org.NewAggregate("org1").Aggregate,
								"org.zitadel.ch"),
						),
						eventFromEventPusher(
							org.NewDomainVerifiedEvent(context.Background(),
								&org.NewAggregate("org1").Aggregate,
								"org.zitadel.ch"),
						),
						eventFromEventPusher(
							org.NewDomainPrimarySetEvent(context.Background(),
								&org.NewAggregate("org1").Aggregate,
								"org.zitadel.ch"),
						),
					),
					expectPush(
						[]*repository.Event{
							eventFromEventPusher(org.NewOrgChangedEvent(context.Background(),
								&org.NewAggregate("org1").Aggregate, "org", "neworg")),
							eventFromEventPusher(org.NewDomainAddedEvent(context.Background(),
								&org.NewAggregate("org1").Aggregate, "neworg.zitadel.ch")),
							eventFromEventPusher(org.NewDomainVerifiedEvent(context.Background(),
								&org.NewAggregate("org1").Aggregate, "neworg.zitadel.ch")),
							eventFromEventPusher(org.NewDomainPrimarySetEvent(context.Background(),
								&org.NewAggregate("org1").Aggregate, "neworg.zitadel.ch")),
							eventFromEventPusher(org.NewDomainRemovedEvent(context.Background(),
								&org.NewAggregate("org1").Aggregate, "org.zitadel.ch", true)),
						},
						uniqueConstraintsFromEventConstraint(org.NewRemoveOrgNameUniqueConstraint("org")),
						uniqueConstraintsFromEventConstraint(org.NewAddOrgNameUniqueConstraint("neworg")),
						uniqueConstraintsFromEventConstraint(org.NewAddOrgDomainUniqueConstraint("neworg.zitadel.ch")),
						uniqueConstraintsFromEventConstraint(org.NewRemoveOrgDomainUniqueConstraint("org.zitadel.ch")),
					),
				),
			},
			args: args{
				ctx:   authz.WithRequestedDomain(context.Background(), "zitadel.ch"),
				orgID: "org1",
				name:  "neworg",
			},
			res: res{},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := &Commands{
				eventstore: tt.fields.eventstore,
			}
			_, err := r.ChangeOrg(tt.args.ctx, tt.args.orgID, tt.args.name)
			if tt.res.err == nil {
				assert.NoError(t, err)
			}
			if tt.res.err != nil && !tt.res.err(err) {
				t.Errorf("got wrong err: %v ", err)
			}
		})
	}
}

func TestCommandSide_DeactivateOrg(t *testing.T) {
	type fields struct {
		eventstore  *eventstore.Eventstore
		idGenerator id.Generator
		iamDomain   string
	}
	type args struct {
		ctx   context.Context
		orgID string
	}
	type res struct {
		want *domain.Org
		err  func(error) bool
	}
	tests := []struct {
		name   string
		fields fields
		args   args
		res    res
	}{
		{
			name: "org not found, error",
			fields: fields{
				eventstore: eventstoreExpect(
					t,
					expectFilter(),
				),
			},
			args: args{
				ctx:   context.Background(),
				orgID: "org1",
			},
			res: res{
				err: errors.IsNotFound,
			},
		},
		{
			name: "org already inactive, error",
			fields: fields{
				eventstore: eventstoreExpect(
					t,
					expectFilter(
						eventFromEventPusher(
							org.NewOrgAddedEvent(context.Background(),
								&org.NewAggregate("org1").Aggregate,
								"org"),
						),
						eventFromEventPusher(
							org.NewOrgDeactivatedEvent(context.Background(),
								&org.NewAggregate("org1").Aggregate),
						),
					),
				),
			},
			args: args{
				ctx:   context.Background(),
				orgID: "org1",
			},
			res: res{
				err: errors.IsPreconditionFailed,
			},
		},
		{
			name: "push failed, error",
			fields: fields{
				eventstore: eventstoreExpect(
					t,
					expectFilter(
						eventFromEventPusher(
							org.NewOrgAddedEvent(context.Background(),
								&org.NewAggregate("org1").Aggregate,
								"org"),
						),
					),
					expectPushFailed(
						errors.ThrowInternal(nil, "id", "message"),
						[]*repository.Event{
							eventFromEventPusher(org.NewOrgDeactivatedEvent(context.Background(),
								&org.NewAggregate("org1").Aggregate)),
						},
					),
				),
			},
			args: args{
				ctx:   context.Background(),
				orgID: "org1",
			},
			res: res{
				err: errors.IsInternal,
			},
		},
		{
			name: "deactivate org",
			fields: fields{
				eventstore: eventstoreExpect(
					t,
					expectFilter(
						eventFromEventPusher(
							org.NewOrgAddedEvent(context.Background(),
								&org.NewAggregate("org1").Aggregate,
								"org"),
						),
					),
					expectPush(
						[]*repository.Event{
							eventFromEventPusher(org.NewOrgDeactivatedEvent(context.Background(),
								&org.NewAggregate("org1").Aggregate,
							)),
						},
					),
				),
			},
			args: args{
				ctx:   context.Background(),
				orgID: "org1",
			},
			res: res{},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := &Commands{
				eventstore:  tt.fields.eventstore,
				idGenerator: tt.fields.idGenerator,
			}
			_, err := r.DeactivateOrg(tt.args.ctx, tt.args.orgID)
			if tt.res.err == nil {
				assert.NoError(t, err)
			}
			if tt.res.err != nil && !tt.res.err(err) {
				t.Errorf("got wrong err: %v ", err)
			}
		})
	}
}
func TestCommandSide_ReactivateOrg(t *testing.T) {
	type fields struct {
		eventstore  *eventstore.Eventstore
		idGenerator id.Generator
		iamDomain   string
	}
	type args struct {
		ctx   context.Context
		orgID string
	}
	type res struct {
		want *domain.Org
		err  func(error) bool
	}
	tests := []struct {
		name   string
		fields fields
		args   args
		res    res
	}{
		{
			name: "org not found, error",
			fields: fields{
				eventstore: eventstoreExpect(
					t,
					expectFilter(),
				),
			},
			args: args{
				ctx:   context.Background(),
				orgID: "org1",
			},
			res: res{
				err: errors.IsNotFound,
			},
		},
		{
			name: "org already active, error",
			fields: fields{
				eventstore: eventstoreExpect(
					t,
					expectFilter(
						eventFromEventPusher(
							org.NewOrgAddedEvent(context.Background(),
								&org.NewAggregate("org1").Aggregate,
								"org"),
						),
					),
				),
			},
			args: args{
				ctx:   context.Background(),
				orgID: "org1",
			},
			res: res{
				err: errors.IsPreconditionFailed,
			},
		},
		{
			name: "push failed, error",
			fields: fields{
				eventstore: eventstoreExpect(
					t,
					expectFilter(
						eventFromEventPusher(
							org.NewOrgAddedEvent(context.Background(),
								&org.NewAggregate("org1").Aggregate,
								"org"),
						),
						eventFromEventPusher(
							org.NewOrgDeactivatedEvent(context.Background(),
								&org.NewAggregate("org1").Aggregate,
							),
						),
					),
					expectPushFailed(
						errors.ThrowInternal(nil, "id", "message"),
						[]*repository.Event{
							eventFromEventPusher(org.NewOrgReactivatedEvent(context.Background(),
								&org.NewAggregate("org1").Aggregate,
							)),
						},
					),
				),
			},
			args: args{
				ctx:   context.Background(),
				orgID: "org1",
			},
			res: res{
				err: errors.IsInternal,
			},
		},
		{
			name: "reactivate org",
			fields: fields{
				eventstore: eventstoreExpect(
					t,
					expectFilter(
						eventFromEventPusher(
							org.NewOrgAddedEvent(context.Background(),
								&org.NewAggregate("org1").Aggregate,
								"org"),
						),
						eventFromEventPusher(
							org.NewOrgDeactivatedEvent(context.Background(),
								&org.NewAggregate("org1").Aggregate),
						),
					),
					expectPush(
						[]*repository.Event{
							eventFromEventPusher(org.NewOrgReactivatedEvent(context.Background(),
								&org.NewAggregate("org1").Aggregate)),
						},
					),
				),
			},
			args: args{
				ctx:   context.Background(),
				orgID: "org1",
			},
			res: res{},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := &Commands{
				eventstore:  tt.fields.eventstore,
				idGenerator: tt.fields.idGenerator,
			}
			_, err := r.ReactivateOrg(tt.args.ctx, tt.args.orgID)
			if tt.res.err == nil {
				assert.NoError(t, err)
			}
			if tt.res.err != nil && !tt.res.err(err) {
				t.Errorf("got wrong err: %v ", err)
			}
		})
	}
}

func TestCommandSide_RemoveOrg(t *testing.T) {
	type fields struct {
		eventstore  *eventstore.Eventstore
		idGenerator id.Generator
	}
	type args struct {
		ctx   context.Context
		orgID string
	}
	type res struct {
		err func(error) bool
	}
	tests := []struct {
		name   string
		fields fields
		args   args
		res    res
	}{
		{
			name: "default org, error",
			fields: fields{
				eventstore: eventstoreExpect(
					t,
				),
			},
			args: args{
				ctx:   authz.WithInstance(context.Background(), &mockInstance{}),
				orgID: "defaultOrgID",
			},
			res: res{
				err: errors.IsPreconditionFailed,
			},
		},
		{
			name: "zitadel org, error",
			fields: fields{
				eventstore: eventstoreExpect(
					t,
					expectFilter(
						eventFromEventPusher(
							project.NewProjectAddedEvent(context.Background(),
								&project.NewAggregate("projectID", "org1").Aggregate,
								"ZITADEL",
								false,
								false,
								false,
								domain.PrivateLabelingSettingUnspecified,
							),
						)),
				),
			},
			args: args{
				ctx:   context.Background(),
				orgID: "org1",
			},
			res: res{
				err: errors.IsPreconditionFailed,
			},
		},
		{
			name: "org not found, error",
			fields: fields{
				eventstore: eventstoreExpect(
					t,
					expectFilter(), // zitadel project check
					expectFilter(),
				),
			},
			args: args{
				ctx:   context.Background(),
				orgID: "org1",
			},
			res: res{
				err: errors.IsNotFound,
			},
		},
		{
			name: "push failed, error",
			fields: fields{
				eventstore: eventstoreExpect(
					t,
					expectFilter(), // zitadel project check
					expectFilter(
						eventFromEventPusher(
							org.NewOrgAddedEvent(context.Background(),
								&org.NewAggregate("org1").Aggregate,
								"org"),
						),
					),
					expectFilter(
						eventFromEventPusher(
							org.NewDomainPolicyAddedEvent(context.Background(),
								&org.NewAggregate("org1").Aggregate,
								true,
								true,
								true,
							),
						),
					),
					expectFilter(),
					expectFilter(),
					expectFilter(),
					expectFilter(),
					expectPushFailed(
						errors.ThrowInternal(nil, "id", "message"),
						[]*repository.Event{
							eventFromEventPusher(
								org.NewOrgRemovedEvent(
									context.Background(), &org.NewAggregate("org1").Aggregate, "org", []string{}, false, []string{}, []*domain.UserIDPLink{}, []string{},
								),
							),
						},
						uniqueConstraintsFromEventConstraint(org.NewRemoveOrgNameUniqueConstraint("org")),
					),
				),
			},
			args: args{
				ctx:   context.Background(),
				orgID: "org1",
			},
			res: res{
				err: errors.IsInternal,
			},
		},
		{
			name: "remove org",
			fields: fields{
				eventstore: eventstoreExpect(
					t,
					expectFilter(), // zitadel project check
					expectFilter(
						eventFromEventPusher(
							org.NewOrgAddedEvent(context.Background(),
								&org.NewAggregate("org1").Aggregate,
								"org"),
						),
					),
					expectFilter(
						eventFromEventPusher(
							org.NewDomainPolicyAddedEvent(context.Background(),
								&org.NewAggregate("org1").Aggregate,
								true,
								true,
								true,
							),
						),
					),
					expectFilter(),
					expectFilter(),
					expectFilter(),
					expectFilter(),
					expectPush(
						[]*repository.Event{
							eventFromEventPusher(
								org.NewOrgRemovedEvent(
									context.Background(), &org.NewAggregate("org1").Aggregate, "org", []string{}, false, []string{}, []*domain.UserIDPLink{}, []string{},
								),
							),
						},
						uniqueConstraintsFromEventConstraint(org.NewRemoveOrgNameUniqueConstraint("org")),
					),
				),
			},
			args: args{
				ctx:   context.Background(),
				orgID: "org1",
			},
			res: res{},
		},
		{
			name: "remove org with usernames and domains",
			fields: fields{
				eventstore: eventstoreExpect(
					t,
					expectFilter(), // zitadel project check
					expectFilter(
						eventFromEventPusher(
							org.NewOrgAddedEvent(context.Background(),
								&org.NewAggregate("org1").Aggregate,
								"org"),
						),
					),

					expectFilter(
						eventFromEventPusher(
							org.NewDomainPolicyAddedEvent(context.Background(),
								&org.NewAggregate("org1").Aggregate,
								true,
								true,
								true,
							),
						),
					),
					expectFilter(
						eventFromEventPusher(
							user.NewHumanAddedEvent(context.Background(),
								&user.NewAggregate("user1", "org1").Aggregate,
								"user1",
								"firstname1",
								"lastname1",
								"nickname1",
								"displayname1",
								language.German,
								domain.GenderMale,
								"email1",
								true,
							),
						), eventFromEventPusher(
							user.NewMachineAddedEvent(context.Background(),
								&user.NewAggregate("user2", "org1").Aggregate,
								"user2",
								"name",
								"description",
								true,
								domain.OIDCTokenTypeBearer,
							),
						),
					),
					expectFilter(
						eventFromEventPusher(
							org.NewDomainVerifiedEvent(context.Background(), &org.NewAggregate("org1").Aggregate, "domain1"),
						),
						eventFromEventPusher(
							org.NewDomainVerifiedEvent(context.Background(), &org.NewAggregate("org1").Aggregate, "domain2"),
						),
					),
					expectFilter(
						eventFromEventPusher(
							user.NewUserIDPLinkAddedEvent(context.Background(), &user.NewAggregate("user1", "org1").Aggregate, "config1", "display1", "id1"),
						),
						eventFromEventPusher(
							user.NewUserIDPLinkAddedEvent(context.Background(), &user.NewAggregate("user2", "org1").Aggregate, "config2", "display2", "id2"),
						),
					),
					expectFilter(
						eventFromEventPusher(
							project.NewSAMLConfigAddedEvent(context.Background(), &project.NewAggregate("project1", "org1").Aggregate, "app1", "entity1", []byte{}, ""),
						),
						eventFromEventPusher(
							project.NewSAMLConfigAddedEvent(context.Background(), &project.NewAggregate("project2", "org1").Aggregate, "app2", "entity2", []byte{}, ""),
						),
					),
					expectPush(
						[]*repository.Event{
							eventFromEventPusher(
								org.NewOrgRemovedEvent(context.Background(), &org.NewAggregate("org1").Aggregate, "org",
									[]string{"user1", "user2"},
									false,
									[]string{"domain1", "domain2"},
									[]*domain.UserIDPLink{{IDPConfigID: "config1", ExternalUserID: "id1", DisplayName: "display1"}, {IDPConfigID: "config2", ExternalUserID: "id2", DisplayName: "display2"}},
									[]string{"entity1", "entity2"},
								),
							),
						},
						uniqueConstraintsFromEventConstraint(org.NewRemoveOrgNameUniqueConstraint("org")),
						uniqueConstraintsFromEventConstraint(user.NewRemoveUsernameUniqueConstraint("user1", "org1", true)),
						uniqueConstraintsFromEventConstraint(user.NewRemoveUsernameUniqueConstraint("user2", "org1", true)),
						uniqueConstraintsFromEventConstraint(org.NewRemoveOrgDomainUniqueConstraint("domain1")),
						uniqueConstraintsFromEventConstraint(org.NewRemoveOrgDomainUniqueConstraint("domain2")),
						uniqueConstraintsFromEventConstraint(user.NewRemoveUserIDPLinkUniqueConstraint("config1", "id1")),
						uniqueConstraintsFromEventConstraint(user.NewRemoveUserIDPLinkUniqueConstraint("config2", "id2")),
						uniqueConstraintsFromEventConstraint(project.NewRemoveSAMLConfigEntityIDUniqueConstraint("entity1")),
						uniqueConstraintsFromEventConstraint(project.NewRemoveSAMLConfigEntityIDUniqueConstraint("entity2")),
					),
				),
			},
			args: args{
				ctx:   context.Background(),
				orgID: "org1",
			},
			res: res{},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := &Commands{
				eventstore:  tt.fields.eventstore,
				idGenerator: tt.fields.idGenerator,
			}
			_, err := r.RemoveOrg(tt.args.ctx, tt.args.orgID)
			if tt.res.err == nil {
				assert.NoError(t, err)
			}
			if tt.res.err != nil && !tt.res.err(err) {
				t.Errorf("got wrong err: %v ", err)
			}
		})
	}
}

func TestCommandSide_SetUpOrg(t *testing.T) {
	type fields struct {
		eventstore   func(t *testing.T) *eventstore.Eventstore
		idGenerator  id.Generator
		newCode      cryptoCodeFunc
		keyAlgorithm crypto.EncryptionAlgorithm
	}
	type args struct {
		ctx              context.Context
		setupOrg         *OrgSetup
		allowInitialMail bool
		userIDs          []string
	}
	type res struct {
		createdOrg *CreatedOrg
		err        error
	}
	tests := []struct {
		name   string
		fields fields
		args   args
		res    res
	}{
		{
			name: "org name empty, error",
			fields: fields{
				eventstore:  expectEventstore(),
				idGenerator: id_mock.NewIDGeneratorExpectIDs(t, "orgID"),
			},
			args: args{
				ctx: authz.WithRequestedDomain(context.Background(), "iam-domain"),
				setupOrg: &OrgSetup{
					Name: "",
				},
			},
			res: res{
				err: errors.ThrowInvalidArgument(nil, "ORG-mruNY", "Errors.Invalid.Argument"),
			},
		},
		{
			name: "userID not existing, error",
			fields: fields{
				eventstore: expectEventstore(
					expectFilter(),
				),
				idGenerator: id_mock.NewIDGeneratorExpectIDs(t, "orgID"),
			},
			args: args{
				ctx: authz.WithRequestedDomain(context.Background(), "iam-domain"),
				setupOrg: &OrgSetup{
					Name: "Org",
					Admins: []*OrgSetupAdmin{
						{
							ID: "userID",
						},
					},
				},
			},
			res: res{
				err: errors.ThrowPreconditionFailed(nil, "ORG-GoXOn", "Errors.User.NotFound"),
			},
		},
		{
			name: "human invalid, error",
			fields: fields{
				eventstore:  expectEventstore(),
				idGenerator: id_mock.NewIDGeneratorExpectIDs(t, "orgID", "userID"),
			},
			args: args{
				ctx: authz.WithRequestedDomain(context.Background(), "iam-domain"),
				setupOrg: &OrgSetup{
					Name: "Org",
					Admins: []*OrgSetupAdmin{
						{
							Human: &AddHuman{
								Username:  "",
								FirstName: "firstname",
								LastName:  "lastname",
								Email: Email{
									Address:  "email@test.ch",
									Verified: true,
								},
								PreferredLanguage: language.English,
							},
						},
					},
				},
				allowInitialMail: true,
			},
			res: res{
				err: errors.ThrowInvalidArgument(nil, "V2-zzad3", "Errors.Invalid.Argument"),
			},
		},
		{
			name: "human added with initial mail",
			fields: fields{
				eventstore: expectEventstore(
					expectFilter(), // add human exists check
					expectFilter(
						eventFromEventPusher(
							org.NewDomainPolicyAddedEvent(context.Background(),
								&user.NewAggregate("userID", "orgID").Aggregate,
								true,
								true,
								true,
							),
						),
					),
					expectFilter(), // org member check
					expectFilter(
						eventFromEventPusher(
							user.NewHumanAddedEvent(context.Background(),
								&user.NewAggregate("user1", "orgID").Aggregate,
								"username",
								"firstname",
								"lastname",
								"",
								"firstname lastname",
								language.English,
								domain.GenderUnspecified,
								"email@test.ch",
								true,
							),
						),
					),
					expectPush(
						[]*repository.Event{
							eventFromEventPusher(org.NewOrgAddedEvent(context.Background(),
								&org.NewAggregate("orgID").Aggregate,
								"Org",
							)),
							eventFromEventPusher(org.NewDomainAddedEvent(context.Background(),
								&org.NewAggregate("orgID").Aggregate, "org.iam-domain",
							)),
							eventFromEventPusher(org.NewDomainVerifiedEvent(context.Background(),
								&org.NewAggregate("orgID").Aggregate,
								"org.iam-domain",
							)),
							eventFromEventPusher(org.NewDomainPrimarySetEvent(context.Background(),
								&org.NewAggregate("orgID").Aggregate,
								"org.iam-domain",
							)),
							eventFromEventPusher(
								user.NewHumanAddedEvent(context.Background(),
									&user.NewAggregate("userID", "orgID").Aggregate,
									"username",
									"firstname",
									"lastname",
									"",
									"firstname lastname",
									language.English,
									domain.GenderUnspecified,
									"email@test.ch",
									true,
								),
							),
							eventFromEventPusher(
								user.NewHumanEmailVerifiedEvent(context.Background(),
									&user.NewAggregate("userID", "orgID").Aggregate,
								),
							),
							eventFromEventPusher(
								user.NewHumanInitialCodeAddedEvent(
									context.Background(),
									&user.NewAggregate("userID", "orgID").Aggregate,
									&crypto.CryptoValue{
										CryptoType: crypto.TypeEncryption,
										Algorithm:  "enc",
										KeyID:      "id",
										Crypted:    []byte("userinit"),
									},
									1*time.Hour,
								),
							),
							eventFromEventPusher(org.NewMemberAddedEvent(context.Background(),
								&org.NewAggregate("orgID").Aggregate,
								"userID",
								domain.RoleOrgOwner,
							)),
						},
						uniqueConstraintsFromEventConstraint(org.NewAddOrgNameUniqueConstraint("Org")),
						uniqueConstraintsFromEventConstraint(org.NewAddOrgDomainUniqueConstraint("org.iam-domain")),
						uniqueConstraintsFromEventConstraint(user.NewAddUsernameUniqueConstraint("email@test.ch", "orgID", true)),
						uniqueConstraintsFromEventConstraint(member.NewAddMemberUniqueConstraint("orgID", "userID")),
					),
				),
				idGenerator: id_mock.NewIDGeneratorExpectIDs(t, "orgID", "userID"),
				newCode:     mockCode("userinit", time.Hour),
			},
			args: args{
				ctx: authz.WithRequestedDomain(context.Background(), "iam-domain"),
				setupOrg: &OrgSetup{
					Name: "Org",
					Admins: []*OrgSetupAdmin{
						{
							Human: &AddHuman{
								Username:  "username",
								FirstName: "firstname",
								LastName:  "lastname",
								Email: Email{
									Address:  "email@test.ch",
									Verified: true,
								},
								PreferredLanguage: language.English,
							},
						},
					},
				},
				allowInitialMail: true,
			},
			res: res{
				createdOrg: &CreatedOrg{
					ObjectDetails: &domain.ObjectDetails{
						ResourceOwner: "orgID",
					},
					CreatedAdmins: []*CreatedOrgAdmin{
						{
							ID: "userID",
						},
					},
				},
			},
		},
		{
			name: "existing human added",
			fields: fields{
				eventstore: expectEventstore(
					expectFilter(
						eventFromEventPusher(
							user.NewHumanAddedEvent(context.Background(),
								&user.NewAggregate("user1", "orgID").Aggregate,
								"username",
								"firstname",
								"lastname",
								"",
								"firstname lastname",
								language.English,
								domain.GenderUnspecified,
								"email@test.ch",
								true,
							),
						),
					),
					expectFilter(), // org member check
					expectPush(
						[]*repository.Event{
							eventFromEventPusher(org.NewOrgAddedEvent(context.Background(),
								&org.NewAggregate("orgID").Aggregate,
								"Org",
							)),
							eventFromEventPusher(org.NewDomainAddedEvent(context.Background(),
								&org.NewAggregate("orgID").Aggregate, "org.iam-domain",
							)),
							eventFromEventPusher(org.NewDomainVerifiedEvent(context.Background(),
								&org.NewAggregate("orgID").Aggregate,
								"org.iam-domain",
							)),
							eventFromEventPusher(org.NewDomainPrimarySetEvent(context.Background(),
								&org.NewAggregate("orgID").Aggregate,
								"org.iam-domain",
							)),
							eventFromEventPusher(org.NewMemberAddedEvent(context.Background(),
								&org.NewAggregate("orgID").Aggregate,
								"userID",
								domain.RoleOrgOwner,
							)),
						},
						uniqueConstraintsFromEventConstraint(org.NewAddOrgNameUniqueConstraint("Org")),
						uniqueConstraintsFromEventConstraint(org.NewAddOrgDomainUniqueConstraint("org.iam-domain")),
						uniqueConstraintsFromEventConstraint(member.NewAddMemberUniqueConstraint("orgID", "userID")),
					),
				),
				idGenerator: id_mock.NewIDGeneratorExpectIDs(t, "orgID"),
			},
			args: args{
				ctx: authz.WithRequestedDomain(context.Background(), "iam-domain"),
				setupOrg: &OrgSetup{
					Name: "Org",
					Admins: []*OrgSetupAdmin{
						{
							ID: "userID",
						},
					},
				},
				allowInitialMail: true,
			},
			res: res{
				createdOrg: &CreatedOrg{
					ObjectDetails: &domain.ObjectDetails{
						ResourceOwner: "orgID",
					},
					CreatedAdmins: []*CreatedOrgAdmin{},
				},
			},
		},
		{
			name: "machine added with pat",
			fields: fields{
				eventstore: expectEventstore(
					expectFilter(), // add machine exists check
					expectFilter(
						eventFromEventPusher(
							org.NewDomainPolicyAddedEvent(context.Background(),
								&user.NewAggregate("userID", "orgID").Aggregate,
								true,
								true,
								true,
							),
						),
					),
					expectFilter(),
					expectFilter(),
					expectFilter(), // org member check
					expectFilter(
						eventFromEventPusher(
							user.NewHumanAddedEvent(context.Background(),
								&user.NewAggregate("user1", "orgID").Aggregate,
								"username",
								"firstname",
								"lastname",
								"",
								"firstname lastname",
								language.English,
								domain.GenderUnspecified,
								"email@test.ch",
								true,
							),
						),
					),
					expectPush(
						[]*repository.Event{
							eventFromEventPusher(org.NewOrgAddedEvent(context.Background(),
								&org.NewAggregate("orgID").Aggregate,
								"Org",
							)),
							eventFromEventPusher(org.NewDomainAddedEvent(context.Background(),
								&org.NewAggregate("orgID").Aggregate, "org.iam-domain",
							)),
							eventFromEventPusher(org.NewDomainVerifiedEvent(context.Background(),
								&org.NewAggregate("orgID").Aggregate,
								"org.iam-domain",
							)),
							eventFromEventPusher(org.NewDomainPrimarySetEvent(context.Background(),
								&org.NewAggregate("orgID").Aggregate,
								"org.iam-domain",
							)),
							eventFromEventPusher(
								user.NewMachineAddedEvent(context.Background(),
									&user.NewAggregate("userID", "orgID").Aggregate,
									"username",
									"name",
									"description",
									true,
									domain.OIDCTokenTypeBearer,
								),
							),
							eventFromEventPusher(
								user.NewPersonalAccessTokenAddedEvent(context.Background(),
									&user.NewAggregate("userID", "orgID").Aggregate,
									"tokenID",
									testNow.Add(time.Hour),
									[]string{openid.ScopeOpenID},
								),
							),
							eventFromEventPusher(org.NewMemberAddedEvent(context.Background(),
								&org.NewAggregate("orgID").Aggregate,
								"userID",
								domain.RoleOrgOwner,
							)),
						},
						uniqueConstraintsFromEventConstraint(org.NewAddOrgNameUniqueConstraint("Org")),
						uniqueConstraintsFromEventConstraint(org.NewAddOrgDomainUniqueConstraint("org.iam-domain")),
						uniqueConstraintsFromEventConstraint(user.NewAddUsernameUniqueConstraint("username", "orgID", true)),
						uniqueConstraintsFromEventConstraint(member.NewAddMemberUniqueConstraint("orgID", "userID")),
					),
				),
				idGenerator:  id_mock.NewIDGeneratorExpectIDs(t, "orgID", "userID", "tokenID"),
				newCode:      mockCode("userinit", time.Hour),
				keyAlgorithm: crypto.CreateMockEncryptionAlg(gomock.NewController(t)),
			},
			args: args{
				ctx: authz.WithRequestedDomain(context.Background(), "iam-domain"),
				setupOrg: &OrgSetup{
					Name: "Org",
					Admins: []*OrgSetupAdmin{
						{
							Machine: &AddMachine{
								Machine: &Machine{
									Username:        "username",
									Name:            "name",
									Description:     "description",
									AccessTokenType: domain.OIDCTokenTypeBearer,
								},
								Pat: &AddPat{
									ExpirationDate: testNow.Add(time.Hour),
									Scopes:         []string{openid.ScopeOpenID},
								},
							},
						},
					},
				},
			},
			res: res{
				createdOrg: &CreatedOrg{
					ObjectDetails: &domain.ObjectDetails{
						ResourceOwner: "orgID",
					},
					CreatedAdmins: []*CreatedOrgAdmin{
						{
							ID: "userID",
							PAT: &PersonalAccessToken{
								ObjectRoot: models.ObjectRoot{
									AggregateID:   "userID",
									ResourceOwner: "orgID",
								},
								ExpirationDate:  testNow.Add(time.Hour),
								Scopes:          []string{openid.ScopeOpenID},
								AllowedUserType: domain.UserTypeMachine,
								TokenID:         "tokenID",
								Token:           "dG9rZW5JRDp1c2VySUQ", // token
							},
						},
					},
				},
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := &Commands{
				eventstore:   tt.fields.eventstore(t),
				idGenerator:  tt.fields.idGenerator,
				newCode:      tt.fields.newCode,
				keyAlgorithm: tt.fields.keyAlgorithm,
				zitadelRoles: []authz.RoleMapping{
					{
						Role: domain.RoleOrgOwner,
					},
				},
			}
			got, err := r.SetUpOrg(tt.args.ctx, tt.args.setupOrg, tt.args.allowInitialMail, tt.args.userIDs...)
			assert.ErrorIs(t, err, tt.res.err)
			assert.Equal(t, tt.res.createdOrg, got)
		})
	}
}
