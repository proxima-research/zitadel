package query

import (
	"context"
	sq "github.com/Masterminds/squirrel"
	"strings"
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

func NewNotUsersWithLoginAsSearchQuery() (SearchQuery, error) {
	sql, args, err := usersWithLoginAsQuery().ToSql()
	return &ExprQuery{Column: UserIDCol, Condition: "NOT IN (" + sql + ")", Args: args}, err
}

func NewNotMembersSearchQuery() SearchQuery {
	return &ExprQuery{Column: UserIDCol, Condition: "NOT IN (" + membersQuery() + ")"}
}

func NewUserResourceOwnersSearchQuery(ids []string) SearchQuery {
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

func usersWithLoginAsQuery() sq.SelectBuilder {
	return sq.Select(UserMetadataUserIDCol.identifier()).
		From(userMetadataTable.identifier()).
		Where(sq.ILike{UserMetadataKeyCol.identifier(): "LOGIN_AS"}).
		Where(sq.Expr("encode(" + UserMetadataValueCol.identifier() + ", 'escape') ILIKE 'ON'"))
}

func membersQuery() string {
	orgMembers, _ := sq.Select(OrgMemberUserID.identifier()).From(orgMemberTable.identifier()).MustSql()
	iamMembers, _ := sq.Select(InstanceMemberUserID.identifier()).From(instanceMemberTable.identifier()).MustSql()
	projectMembers, _ := sq.Select(ProjectMemberUserID.identifier()).From(projectMemberTable.identifier()).MustSql()
	projectGrantMembers, _ := sq.Select(ProjectGrantMemberUserID.identifier()).From(projectGrantMemberTable.identifier()).MustSql()

	return orgMembers + " UNION " + iamMembers + " UNION " + projectMembers + " UNION " + projectGrantMembers
}
