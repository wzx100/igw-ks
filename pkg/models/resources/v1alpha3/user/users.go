/*
Copyright 2019 The KubeSphere Authors.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package user

import (
	v1alpha2 "kubesphere.io/api/iam/v1alpha2"

	rbacv1 "k8s.io/api/rbac/v1"
	"k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/apimachinery/pkg/runtime"
	k8sinformers "k8s.io/client-go/informers"
	"k8s.io/klog"
	"strings"

	iamv1alpha2 "kubesphere.io/api/iam/v1alpha2"
	tenantv1alpha1 "kubesphere.io/api/tenant/v1alpha1"

	"kubesphere.io/kubesphere/pkg/api"
	"kubesphere.io/kubesphere/pkg/apiserver/query"
	ksinformers "kubesphere.io/kubesphere/pkg/client/informers/externalversions"
	"kubesphere.io/kubesphere/pkg/models/resources/v1alpha3"
	"kubesphere.io/kubesphere/pkg/utils/sliceutil"
)

type usersGetter struct {
	ksInformer  ksinformers.SharedInformerFactory
	k8sInformer k8sinformers.SharedInformerFactory
}

func New(ksinformer ksinformers.SharedInformerFactory, k8sinformer k8sinformers.SharedInformerFactory) v1alpha3.Interface {
	return &usersGetter{ksInformer: ksinformer, k8sInformer: k8sinformer}
}

func (d *usersGetter) Get(_, name string) (runtime.Object, error) {
	return d.ksInformer.Iam().V1alpha2().Users().Lister().Get(name)
}

func (d *usersGetter) List(_ string, query *query.Query) (*api.ListResult, error) {

	delete(query.Filters, iamv1alpha2.ScopeWorkspace)

	editmembers := query.Filters["editmembers"]
	if editmembers != "" {
		delete(query.Filters, "editmembers")
	}
	workspacename := query.Filters["workspacename"]
	if editmembers != "" {
		delete(query.Filters, "workspacename")
	}
	loginusername := query.Filters["loginusername"]
	delete(query.Filters, "loginusername")
	var users []*iamv1alpha2.User
	var err error

	//项目
	if namespace := query.Filters[iamv1alpha2.ScopeNamespace]; namespace != "" {
		role := query.Filters[iamv1alpha2.ResourcesSingularRole]
		users, err = d.listAllUsersInNamespace(string(namespace), string(role))
		delete(query.Filters, iamv1alpha2.ScopeNamespace)
		delete(query.Filters, iamv1alpha2.ResourcesSingularRole)
		//企业空间
	} else if workspace := query.Filters[iamv1alpha2.ScopeWorkspace]; workspace != "" {
		workspaceRole := query.Filters[iamv1alpha2.ResourcesSingularWorkspaceRole]
		users, err = d.listAllUsersInWorkspace(string(workspace), string(workspaceRole))
		delete(query.Filters, iamv1alpha2.ResourcesSingularWorkspaceRole)
		//集群级别
	} else if cluster := query.Filters[iamv1alpha2.ScopeCluster]; cluster == "true" {
		clusterRole := query.Filters[iamv1alpha2.ResourcesSingularClusterRole]
		users, err = d.listAllUsersInCluster(string(clusterRole))
		delete(query.Filters, iamv1alpha2.ScopeCluster)
		delete(query.Filters, iamv1alpha2.ResourcesSingularClusterRole)
	} else if globalRole := query.Filters[iamv1alpha2.ResourcesSingularGlobalRole]; globalRole != "" {
		users, err = d.listAllUsersByGlobalRole(string(globalRole))
		delete(query.Filters, iamv1alpha2.ResourcesSingularGlobalRole)
	} else {
		users, err = d.ksInformer.Iam().V1alpha2().Users().Lister().List(query.Selector())
	}

	if err != nil {
		return nil, err
	}
	isWorkspaceManager := false
	isBind := false
	isEditMember := true
	//企业空间管理员查询当前企业空间的成员
	var loginUserGlobalRole *v1alpha2.GlobalRole
	if loginusername != "" {
		globalRoleBindings, _ := d.ksInformer.Iam().V1alpha2().GlobalRoleBindings().Lister().List(query.Selector())
		for _, globalRoleBinding := range globalRoleBindings {
			if globalRoleBinding.Subjects[0].Name == string(loginusername) {
				globalRole, _ := d.ksInformer.Iam().V1alpha2().GlobalRoles().Lister().Get(globalRoleBinding.RoleRef.Name)
				loginUserGlobalRole = globalRole
				if globalRole.Name == "workspaces-manager" || globalRole.Spec.ExtendFrom == "workspaces-manager" {

					isWorkspaceManager = true
					if workspacename == "" || editmembers == "" {
						isEditMember = false
						//说明是企业空间管理员,则查询该企业空间管理员绑定的用户
						workspaceRoleBindings, _ := d.ksInformer.Iam().V1alpha2().WorkspaceRoleBindings().Lister().List(query.Selector())
						for _, workspaceRoleBinding := range workspaceRoleBindings {
							if workspaceRoleBinding.Subjects[0].Name == string(loginusername) {
								workspaceName := strings.Split(workspaceRoleBinding.RoleRef.Name, "-")[0]
								users, _ = d.listAllUsersInWorkspace(workspaceName, "")
								isBind = true
								break
							}
						}
					}
				}
			}
		}
	}
	//是企业空间管理员/并且该企业空间管理员未绑定了企业空间,而且不是编辑成员查找
	if isWorkspaceManager && !isBind && !isEditMember {
		users = []*iamv1alpha2.User{}
	}
	var result []runtime.Object
	for _, user := range users {
		//编辑成员企业空间查看,查询未绑定企业空间的
		if workspacename != "" && editmembers != "" {
			//如果是租户管理员或者是超管则不查询出来
			if loginUserGlobalRole.Name == "tenant-admin" || loginUserGlobalRole.Spec.ExtendFrom == "platform-admin" || loginUserGlobalRole.Name == "platform-admin" || loginUserGlobalRole.Spec.ExtendFrom == "tenant-admin" {
				continue
			}
			workSpaceRoleBinds, _ := d.ksInformer.Iam().V1alpha2().WorkspaceRoleBindings().Lister().List(query.Selector())
			//循环遍历
			flag1 := false
			for _, workSpaceRoleBind := range workSpaceRoleBinds {
				if strings.Contains(workSpaceRoleBind.Subjects[0].Name, user.Name) && !strings.Contains(workSpaceRoleBind.RoleRef.Name, string(workspacename)) {
					//已绑定但不是该企业空间的成员,则跳过
					flag1 = true
					break
				}
			}
			if flag1 {
				continue
			}
		}
		tenantname := string(query.Filters["tenantname"])
		if tenantname != "" {
			//查询租户信息
			opTenantId := user.Spec.OpTenantId
			opTenant, _ := d.ksInformer.OpTenant().V1alpha1().OpTenants().Lister().Get(opTenantId)
			if opTenant != nil && opTenant.Spec.TenantName != "" {
				if !strings.Contains(opTenant.Spec.TenantName, tenantname) {
					continue
				}
			}
		}
		workspacenames := string(query.Filters["workspacenames"])
		if workspacenames != "" {
			//查询租户信息
			globalRoleBindings, err := d.ksInformer.Iam().V1alpha2().WorkspaceRoleBindings().Lister().List(query.Selector())
			if err != nil {
				return nil, err
			}

			var globalRoleBindingResult []runtime.Object
			for _, globalRoleBinding := range globalRoleBindings {
				globalRoleBindingResult = append(globalRoleBindingResult, globalRoleBinding)
			}
			workspaceRoleBindings := make([]*iamv1alpha2.WorkspaceRoleBinding, 0)
			for _, obj := range globalRoleBindingResult {
				roleBinding := obj.(*iamv1alpha2.WorkspaceRoleBinding)
				if subjectsContains(roleBinding.Subjects, user.Name, nil) {
					workspaceRoleBindings = append(workspaceRoleBindings, roleBinding)
				}
			}
			flag := false
			for _, roleBinding := range workspaceRoleBindings {
				workspaceName := roleBinding.Labels[tenantv1alpha1.WorkspaceLabel]

				// label matching selector, remove duplicate entity
				if strings.Contains(workspaceName, workspacenames) {
					flag = true
					break
				}
			}
			if !flag {
				continue
			}
		}
		rolename := string(query.Filters["rolename"])
		if rolename != "" {
			{
				globalRoleBindings, err := d.ksInformer.Iam().V1alpha2().GlobalRoleBindings().Lister().List(query.Selector())

				if err != nil {
					return nil, err
				}
				containGlobalRoleBindings := make([]*iamv1alpha2.GlobalRoleBinding, 0)
				for _, obj := range globalRoleBindings {
					if globalRoleContains(obj.Subjects, user.Name, nil) {
						containGlobalRoleBindings = append(containGlobalRoleBindings, obj)
					}
				}
				flag := false
				for _, roleBinding := range containGlobalRoleBindings {
					globalRoleName := roleBinding.RoleRef.Name

					// label matching selector, remove duplicate entity
					if strings.Contains(globalRoleName, rolename) {
						flag = true
						break
					}
				}
				if !flag {
					continue
				}
			}
		}
		result = append(result, user)
	}

	return v1alpha3.DefaultList(result, query, d.compare, d.filter), nil
}
func globalRoleContains(subjects []rbacv1.Subject, username string, groups []string) bool {
	// if username is nil means list all role bindings
	if username == "" {
		return true
	}
	for _, subject := range subjects {
		if subject.Kind == rbacv1.UserKind && subject.Name == username {
			return true
		}
		if subject.Kind == rbacv1.GroupKind && sliceutil.HasString(groups, subject.Name) {
			return true
		}
	}
	return false
}

func subjectsContains(subjects []rbacv1.Subject, username string, groups []string) bool {
	// if username is nil means list all role bindings
	if username == "" {
		return true
	}
	for _, subject := range subjects {
		if subject.Kind == rbacv1.UserKind && subject.Name == username {
			return true
		}
		if subject.Kind == rbacv1.GroupKind && sliceutil.HasString(groups, subject.Name) {
			return true
		}
	}
	return false
}

func (d *usersGetter) compare(left runtime.Object, right runtime.Object, field query.Field) bool {

	leftUser, ok := left.(*iamv1alpha2.User)
	if !ok {
		return false
	}

	rightUser, ok := right.(*iamv1alpha2.User)
	if !ok {
		return false
	}

	return v1alpha3.DefaultObjectMetaCompare(leftUser.ObjectMeta, rightUser.ObjectMeta, field)
}

func (d *usersGetter) filter(object runtime.Object, filter query.Filter) bool {
	user, ok := object.(*iamv1alpha2.User)

	if !ok {
		return false
	}

	switch filter.Field {
	case "tenantname":
		return true
	case "workspacenames":
		return true
	case "rolename":
		return true
	case iamv1alpha2.FieldOptenantId:
		return user.Spec.OpTenantId == string(filter.Value)
	case iamv1alpha2.ExtraUsername:
		return strings.Contains(user.Name, string(filter.Value))
	case iamv1alpha2.FieldOpuid:
		return user.Spec.Opuid == string(filter.Value)
	case iamv1alpha2.FieldEmail:
		return user.Spec.Email == string(filter.Value)
	case iamv1alpha2.InGroup:
		return sliceutil.HasString(user.Spec.Groups, string(filter.Value))
	case iamv1alpha2.NotInGroup:
		return !sliceutil.HasString(user.Spec.Groups, string(filter.Value))
	default:
		return v1alpha3.DefaultObjectMetaFilter(user.ObjectMeta, filter)
	}
}

func (d *usersGetter) listAllUsersInWorkspace(workspace, role string) ([]*iamv1alpha2.User, error) {
	var users []*iamv1alpha2.User
	var err error
	workspaceRoleBindings, err := d.ksInformer.Iam().V1alpha2().
		WorkspaceRoleBindings().Lister().List(labels.SelectorFromValidatedSet(labels.Set{tenantv1alpha1.WorkspaceLabel: workspace}))

	if err != nil {
		klog.Error(err)
		return nil, err
	}

	for _, roleBinding := range workspaceRoleBindings {
		if role != "" && roleBinding.RoleRef.Name != role {
			continue
		}
		for _, subject := range roleBinding.Subjects {
			if subject.Kind == iamv1alpha2.ResourceKindUser {

				if contains(users, subject.Name) {
					klog.Warningf("conflict role binding found: %s, username:%s", roleBinding.ObjectMeta.String(), subject.Name)
					continue
				}

				obj, err := d.Get("", subject.Name)

				if err != nil {
					if errors.IsNotFound(err) {
						klog.Warningf("orphan subject: %s", subject.String())
						continue
					}
					klog.Error(err)
					return nil, err
				}

				user := obj.(*iamv1alpha2.User)
				user = user.DeepCopy()
				if user.Annotations == nil {
					user.Annotations = make(map[string]string, 0)
				}
				user.Annotations[iamv1alpha2.WorkspaceRoleAnnotation] = roleBinding.RoleRef.Name
				users = append(users, user)
			}
		}
	}

	return users, nil
}

func (d *usersGetter) listAllUsersInNamespace(namespace, role string) ([]*iamv1alpha2.User, error) {
	var users []*iamv1alpha2.User
	var err error

	roleBindings, err := d.k8sInformer.Rbac().V1().
		RoleBindings().Lister().RoleBindings(namespace).List(labels.Everything())

	if err != nil {
		klog.Error(err)
		return nil, err
	}

	for _, roleBinding := range roleBindings {
		if role != "" && roleBinding.RoleRef.Name != role {
			continue
		}
		for _, subject := range roleBinding.Subjects {
			if subject.Kind == iamv1alpha2.ResourceKindUser {
				if contains(users, subject.Name) {
					klog.Warningf("conflict role binding found: %s, username:%s", roleBinding.ObjectMeta.String(), subject.Name)
					continue
				}

				obj, err := d.Get("", subject.Name)

				if err != nil {
					if errors.IsNotFound(err) {
						klog.Warningf("orphan subject: %s", subject.String())
						continue
					}
					klog.Error(err)
					return nil, err
				}

				user := obj.(*iamv1alpha2.User)
				user = user.DeepCopy()
				if user.Annotations == nil {
					user.Annotations = make(map[string]string, 0)
				}
				user.Annotations[iamv1alpha2.RoleAnnotation] = roleBinding.RoleRef.Name
				users = append(users, user)
			}
		}
	}

	return users, nil
}

func (d *usersGetter) listAllUsersByGlobalRole(globalRole string) ([]*iamv1alpha2.User, error) {
	var users []*iamv1alpha2.User
	var err error

	globalRoleBindings, err := d.ksInformer.Iam().V1alpha2().
		GlobalRoleBindings().Lister().List(labels.Everything())

	if err != nil {
		klog.Error(err)
		return nil, err
	}

	for _, roleBinding := range globalRoleBindings {
		if roleBinding.RoleRef.Name != globalRole {
			continue
		}
		for _, subject := range roleBinding.Subjects {
			if subject.Kind == iamv1alpha2.ResourceKindUser {

				if contains(users, subject.Name) {
					klog.Warningf("conflict role binding found: %s, username:%s", roleBinding.ObjectMeta.String(), subject.Name)
					continue
				}

				obj, err := d.Get("", subject.Name)

				if err != nil {
					if errors.IsNotFound(err) {
						klog.Warningf("orphan subject: %s", subject.String())
						continue
					}
					klog.Error(err)
					return nil, err
				}

				user := obj.(*iamv1alpha2.User)
				user = user.DeepCopy()
				if user.Annotations == nil {
					user.Annotations = make(map[string]string, 0)
				}
				user.Annotations[iamv1alpha2.GlobalRoleAnnotation] = roleBinding.RoleRef.Name
				users = append(users, user)
			}
		}
	}

	return users, nil
}

func (d *usersGetter) listAllUsersInCluster(clusterRole string) ([]*iamv1alpha2.User, error) {
	var users []*iamv1alpha2.User
	var err error

	roleBindings, err := d.k8sInformer.Rbac().V1().ClusterRoleBindings().Lister().List(labels.Everything())

	if err != nil {
		klog.Error(err)
		return nil, err
	}

	for _, roleBinding := range roleBindings {
		if clusterRole != "" && roleBinding.RoleRef.Name != clusterRole {
			continue
		}
		for _, subject := range roleBinding.Subjects {
			if subject.Kind == iamv1alpha2.ResourceKindUser {
				if contains(users, subject.Name) {
					klog.Warningf("conflict role binding found: %s, username:%s", roleBinding.ObjectMeta.String(), subject.Name)
					continue
				}

				obj, err := d.Get("", subject.Name)

				if err != nil {
					if errors.IsNotFound(err) {
						klog.Warningf("orphan subject: %s", subject.String())
						continue
					}
					klog.Error(err)
					return nil, err
				}

				user := obj.(*iamv1alpha2.User)
				user = user.DeepCopy()
				if user.Annotations == nil {
					user.Annotations = make(map[string]string, 0)
				}
				user.Annotations[iamv1alpha2.ClusterRoleAnnotation] = roleBinding.RoleRef.Name
				users = append(users, user)
			}
		}
	}

	return users, nil
}

func contains(users []*iamv1alpha2.User, username string) bool {
	for _, user := range users {
		if user.Name == username {
			return true
		}
	}
	return false
}
