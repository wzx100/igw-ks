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

package globalrole

import (
	"encoding/json"
	"strings"

	"k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/klog"

	iamv1alpha2 "kubesphere.io/api/iam/v1alpha2"

	"kubesphere.io/kubesphere/pkg/api"
	"kubesphere.io/kubesphere/pkg/apiserver/query"
	informers "kubesphere.io/kubesphere/pkg/client/informers/externalversions"
	"kubesphere.io/kubesphere/pkg/models/resources/v1alpha3"
)

type globalrolesGetter struct {
	sharedInformers informers.SharedInformerFactory
}

func New(sharedInformers informers.SharedInformerFactory) v1alpha3.Interface {
	return &globalrolesGetter{sharedInformers: sharedInformers}
}

func (d *globalrolesGetter) Get(_, name string) (runtime.Object, error) {
	return d.sharedInformers.Iam().V1alpha2().GlobalRoles().Lister().Get(name)
}

func (d *globalrolesGetter) List(_ string, query *query.Query) (*api.ListResult, error) {

	loginuser := query.Filters["loginuser"]
	if string(loginuser) != "" {
		delete(query.Filters, "loginuser")
	}
	var roles []*iamv1alpha2.GlobalRole
	var err error

	if aggregateTo := query.Filters[iamv1alpha2.AggregateTo]; aggregateTo != "" {
		roles, err = d.fetchAggregationRoles(string(aggregateTo))
		delete(query.Filters, iamv1alpha2.AggregateTo)
	} else {
		roles, err = d.sharedInformers.Iam().V1alpha2().GlobalRoles().Lister().List(query.Selector())
	}

	if err != nil {
		return nil, err
	}
	globalRoleName := ""
	if string(loginuser) != "" {
		loginUserName := string(loginuser)
		//查询登录用户角色绑定
		globalRoleBindings, _ := d.sharedInformers.Iam().V1alpha2().GlobalRoleBindings().Lister().List(query.Selector())
		for _, globalRoleBinding := range globalRoleBindings {
			if globalRoleBinding.Subjects[0].Name == loginUserName {
				globalrole, _ := d.sharedInformers.Iam().V1alpha2().GlobalRoles().Lister().Get(globalRoleBinding.RoleRef.Name)
				if globalrole.Spec.ExtendFrom != "" {
					globalRoleName = globalrole.Spec.ExtendFrom
				} else {
					globalRoleName = globalrole.Name
				}
			}
		}
	}
	value := query.Filters["managerUser"]
	delete(query.Filters, "managerUser")

	var result []runtime.Object
	for _, role := range roles {
		if globalRoleName != "" {
			//属于新建和编辑用户,需要根据登录用户角色来判断
			if globalRoleName == "platform-admin" {
				//新建和编辑用户
				if stringValue := string(value); stringValue != "" {
					//不是企业空间管理员和普通用户的
					if role.Spec.ExtendFrom != "platform-regular" && role.Name != "platform-regular" && role.Spec.ExtendFrom != "workspaces-manager" && role.Name != "workspaces-manager" {
						continue
					}
				}
			} else if globalRoleName == "tenant-admin" {
				//不是企业空间管理员和普通用户的
				if role.Spec.ExtendFrom != "platform-regular" && role.Name != "platform-regular" && role.Spec.ExtendFrom != "workspaces-manager" && role.Name != "workspaces-manager" {
					continue
				}
			} else if globalRoleName == "workspaces-manager" {
				if role.Spec.Creator != "" && role.Spec.Creator != string(loginuser) {
					continue
				}
				//不是普通用户和继承自普通用户的
				if role.Spec.ExtendFrom != "platform-regular" && role.Name != "platform-regular" {
					continue
				}
			} else {
				continue
			}
		}
		result = append(result, role)
	}
	apiresult, err := v1alpha3.DefaultList(result, query, d.compare, d.filter), nil

	return apiresult, err
}

func (d *globalrolesGetter) compare(left runtime.Object, right runtime.Object, field query.Field) bool {

	leftRole, ok := left.(*iamv1alpha2.GlobalRole)
	if !ok {
		return false
	}

	rightRole, ok := right.(*iamv1alpha2.GlobalRole)
	if !ok {
		return false
	}

	return v1alpha3.DefaultObjectMetaCompare(leftRole.ObjectMeta, rightRole.ObjectMeta, field)
}

func (d *globalrolesGetter) filter(object runtime.Object, filter query.Filter) bool {
	role, ok := object.(*iamv1alpha2.GlobalRole)

	if !ok {
		return false
	}

	return DefaultObjectFilter(role, filter)
}

//  Default metadata filter
func DefaultObjectFilter(item *iamv1alpha2.GlobalRole, filter query.Filter) bool {
	switch filter.Field {
	case iamv1alpha2.FieldIsDefault:
		return item.Spec.IsDefault == string(filter.Value)
	case iamv1alpha2.FieldOptenantId:
		return item.Spec.OpTenantId == string(filter.Value) || item.Spec.OpTenantId == ""
	case query.FieldNames:
		for _, name := range strings.Split(string(filter.Value), ",") {
			if item.Name == name {
				return true
			}
		}
		return false
	// /namespaces?page=1&limit=10&name=default
	case query.FieldName:
		return strings.Contains(item.Name, string(filter.Value))
		// /namespaces?page=1&limit=10&uid=a8a8d6cf-f6a5-4fea-9c1b-e57610115706
	case query.FieldUID:
		return strings.Compare(string(item.UID), string(filter.Value)) == 0
		// /deployments?page=1&limit=10&namespace=kubesphere-system
	case query.FieldNamespace:
		return strings.Compare(item.Namespace, string(filter.Value)) == 0
		// /namespaces?page=1&limit=10&ownerReference=a8a8d6cf-f6a5-4fea-9c1b-e57610115706
	case query.FieldOwnerReference:
		for _, ownerReference := range item.OwnerReferences {
			if strings.Compare(string(ownerReference.UID), string(filter.Value)) == 0 {
				return true
			}
		}
		return false
		// /namespaces?page=1&limit=10&ownerKind=Workspace
	case query.FieldOwnerKind:
		for _, ownerReference := range item.OwnerReferences {
			if strings.Compare(ownerReference.Kind, string(filter.Value)) == 0 {
				return true
			}
		}
		return false
		// /namespaces?page=1&limit=10&annotation=openpitrix_runtime
	case query.FieldAnnotation:
		return labelMatch(item.Annotations, string(filter.Value))
		// /namespaces?page=1&limit=10&label=kubesphere.io/workspace:system-workspace
	case query.FieldLabel:
		return labelMatch(item.Labels, string(filter.Value))
	default:
		return false
	}
}

func labelMatch(labels map[string]string, filter string) bool {
	fields := strings.SplitN(filter, "=", 2)
	var key, value string
	var opposite bool
	if len(fields) == 2 {
		key = fields[0]
		if strings.HasSuffix(key, "!") {
			key = strings.TrimSuffix(key, "!")
			opposite = true
		}
		value = fields[1]
	} else {
		key = fields[0]
		value = "*"
	}
	for k, v := range labels {
		if opposite {
			if (k == key) && v != value {
				return true
			}
		} else {
			if (k == key) && (value == "*" || v == value) {
				return true
			}
		}
	}
	return false
}

func (d *globalrolesGetter) fetchAggregationRoles(name string) ([]*iamv1alpha2.GlobalRole, error) {
	roles := make([]*iamv1alpha2.GlobalRole, 0)

	obj, err := d.Get("", name)

	if err != nil {
		if errors.IsNotFound(err) {
			return roles, nil
		}
		return nil, err
	}

	if annotation := obj.(*iamv1alpha2.GlobalRole).Annotations[iamv1alpha2.AggregationRolesAnnotation]; annotation != "" {
		var roleNames []string
		if err = json.Unmarshal([]byte(annotation), &roleNames); err == nil {

			for _, roleName := range roleNames {
				role, err := d.Get("", roleName)

				if err != nil {
					if errors.IsNotFound(err) {
						klog.Warningf("invalid aggregation role found: %s, %s", name, roleName)
						continue
					}
					return nil, err
				}

				roles = append(roles, role.(*iamv1alpha2.GlobalRole))
			}
		}
	}

	return roles, nil
}
