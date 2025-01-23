package query

import (
	"context"
	"encoding/json"
	"errors"
	sq "github.com/Masterminds/squirrel"
	"github.com/zitadel/zitadel/internal/domain"
	"github.com/zitadel/zitadel/internal/zerrors"
	"strings"
	"time"
)

const (
	pageSize = 10
)

type ExprQuery struct {
	Column    Column
	Condition string
	Args      []interface{}
}

func (q *ExprQuery) Col() Column {
	return q.Column
}

func (q *ExprQuery) toQuery(query sq.SelectBuilder) sq.SelectBuilder {
	return query.Where(q.comp())
}

func (q *ExprQuery) comp() sq.Sqlizer {
	return sq.Expr(q.Column.identifier()+" "+q.Condition, q.Args...)
}

func newNotMembersSearchQuery() SearchQuery {
	return &ExprQuery{Column: UserIDCol, Condition: "NOT IN (" + membersQuery() + ")"}
}

func newUserResourceOwnersSearchQuery(ids []string) SearchQuery {
	return &ExprQuery{Column: UserResourceOwnerCol, Condition: "IN ('" + strings.Join(ids, "','") + "')"}
}

func (q *Queries) GetOrgGrantedOrgIds(ctx context.Context, orgId string) ([]string, error) {
	om, err := q.GetOrgMetadataByKey(ctx, false, orgId, "GRANTED_ORGS", false)
	if err != nil {
		return nil, err
	}
	var grantedOrgIds []string
	if om != nil {
		if omValue := strings.TrimSpace(string(om.Value)); omValue != "" {
			for _, grantedOrgId := range strings.Split(omValue, ",") {
				if strings.TrimSpace(orgId) != "" {
					grantedOrgIds = append(grantedOrgIds, grantedOrgId)
				}
			}
		}
	}
	return grantedOrgIds, nil
}

type DateOnly time.Time

func (d *DateOnly) UnmarshalJSON(data []byte) error {
	if string(data) == "null" {
		return nil
	}

	// TODO(https://go.dev/issue/47353): Properly unescape a JSON string.
	if len(data) < 2 || data[0] != '"' || data[len(data)-1] != '"' {
		return errors.New("DateOnly.UnmarshalJSON: input is not a JSON string")
	}

	data = data[len(`"`) : len(data)-len(`"`)]
	t, err := time.Parse(time.DateOnly, string(data))
	if err != nil {
		return err
	}

	*d = DateOnly(t)

	return nil
}

type UserLoginAsMetadata map[string]*struct {
	ExpiresAt DateOnly `json:"expires_at"`
}

func (q *Queries) GetUserLoginAsConfigMetadata(ctx context.Context, userID string) (UserLoginAsMetadata, error) {
	um, err := q.GetUserMetadataByKey(ctx, false, userID, "LOGIN_AS_CONFIG", false)
	if err != nil {
		return nil, err
	}
	var md UserLoginAsMetadata
	if um != nil {
		err = json.Unmarshal(um.Value, &md)
		if err != nil {
			return nil, err
		}
	}
	return md, nil
}

func (q *Queries) SearchUsersForLoginAs(ctx context.Context, orgId string, search string, page int) (*Users, error) {
	userTypeSearchQuery, err := NewUserTypeSearchQuery(int32(domain.UserTypeHuman))
	if err != nil {
		return nil, err
	}

	userStateSearchQuery, err := NewUserStateSearchQuery(int32(domain.UserStateInactive))
	if err != nil {
		return nil, err
	}

	userNotStateSearchQuery, err := NewUserNotSearchQuery(userStateSearchQuery)
	if err != nil {
		return nil, err
	}

	queries := &UserSearchQueries{
		SearchRequest: SearchRequest{
			Offset:        uint64(page * pageSize),
			Limit:         pageSize,
			SortingColumn: UserUsernameCol,
			Asc:           true,
		},
		Queries: []SearchQuery{
			userTypeSearchQuery,
			newNotMembersSearchQuery(),
			userNotStateSearchQuery,
		},
	}

	if search != "" {
		userDisplayNameSearchQuery, err := NewUserDisplayNameSearchQuery(search, TextContainsIgnoreCase)
		if err != nil {
			return nil, err
		}
		userEmailSearchQuery, err := NewUserEmailSearchQuery(search, TextContainsIgnoreCase)
		if err != nil {
			return nil, err
		}
		userDisplayNameOrEmailSearchQuery, err := NewUserOrSearchQuery([]SearchQuery{
			userDisplayNameSearchQuery,
			userEmailSearchQuery,
		})
		if err != nil {
			return nil, err
		}
		queries.Queries = append(queries.Queries, userDisplayNameOrEmailSearchQuery)
	}

	if orgId != "" {
		grantedOrgIds, err := q.GetOrgGrantedOrgIds(ctx, orgId)
		if err != nil && !zerrors.IsNotFound(err) {
			return nil, err
		}
		userResourceOwnerSearchQuery, err := NewUserResourceOwnerSearchQuery(orgId, TextEquals)
		if err != nil {
			return nil, err
		}
		if len(grantedOrgIds) == 0 {
			queries.Queries = append(queries.Queries, userResourceOwnerSearchQuery)
		} else {
			userResourceOwnerOrGrantedOrgsSearchQuery, err := NewUserOrSearchQuery([]SearchQuery{
				userResourceOwnerSearchQuery,
				newUserResourceOwnersSearchQuery(grantedOrgIds),
			})
			if err != nil {
				return nil, err
			}
			queries.Queries = append(queries.Queries, userResourceOwnerOrGrantedOrgsSearchQuery)
		}
	}

	return q.SearchUsers(ctx, queries)
}

func (q *Queries) GetUserRoles(ctx context.Context, userId string) ([]string, error) {
	userQuery, err := NewMembershipUserIDQuery(userId)
	if err != nil {
		return nil, err
	}
	memberships, err := q.Memberships(ctx, &MembershipSearchQuery{
		Queries: []SearchQuery{userQuery},
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
	roles := make([]string, 0, len(rolesMap))
	for role := range rolesMap {
		roles = append(roles, role)
	}
	return roles, nil
}

func membersQuery() string {
	orgMembers, _ := sq.Select(OrgMemberUserID.identifier()).From(orgMemberTable.identifier()).MustSql()
	iamMembers, _ := sq.Select(InstanceMemberUserID.identifier()).From(instanceMemberTable.identifier()).MustSql()
	projectMembers, _ := sq.Select(ProjectMemberUserID.identifier()).From(projectMemberTable.identifier()).MustSql()
	projectGrantMembers, _ := sq.Select(ProjectGrantMemberUserID.identifier()).From(projectGrantMemberTable.identifier()).MustSql()

	return orgMembers + " UNION " + iamMembers + " UNION " + projectMembers + " UNION " + projectGrantMembers
}
