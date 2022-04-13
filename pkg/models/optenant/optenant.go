/*
Copyright 2020 KubeSphere Authors

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

package optenant

import (
	"context"
	"fmt"
	"k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/validation/field"
	iamv1alpha2 "kubesphere.io/api/iam/v1alpha2"
	"kubesphere.io/kubesphere/pkg/informers"

	"k8s.io/client-go/kubernetes"
	"k8s.io/klog"

	optenantv1alpha1 "kubesphere.io/api/optenant/v1alpha1"

	"kubesphere.io/kubesphere/pkg/api"
	"kubesphere.io/kubesphere/pkg/apiserver/query"
	kubesphere "kubesphere.io/kubesphere/pkg/client/clientset/versioned"
	resourcesv1alpha1 "kubesphere.io/kubesphere/pkg/models/resources/v1alpha1/resource"
)

type OpTenantOperator interface {
	ListOpTenants(queryParam *query.Query) (*api.ListResult, error)
	CreateOpTenant(optenant *optenantv1alpha1.OpTenant) (*optenantv1alpha1.OpTenant, error)
	DescribeOpTenant(name string) (*optenantv1alpha1.OpTenant, error)
	DeleteOpTenant(name string) error
	UpdateOpTenant(optenant *optenantv1alpha1.OpTenant) (*optenantv1alpha1.OpTenant, error)
	//PatchGroup(workspace string, group *iamv1alpha2.Group) (*iamv1alpha2.Group, error)
	//DeleteGroupBinding(workspace, name string) error
	//CreateGroupBinding(workspace, groupName, userName string) (*iamv1alpha2.GroupBinding, error)
	//ListGroupBindings(workspace string, queryParam *query.Query) (*api.ListResult, error)
}

type optenantOperator struct {
	k8sclient      kubernetes.Interface
	ksclient       kubesphere.Interface
	resourceGetter *resourcesv1alpha1.ResourceGetter
}

func New(resourceGetter *resourcesv1alpha1.ResourceGetter, informers informers.InformerFactory, ksclient kubesphere.Interface, k8sclient kubernetes.Interface) OpTenantOperator {
	return &optenantOperator{
		resourceGetter: resourceGetter,
		k8sclient:      k8sclient,
		ksclient:       ksclient,
	}
}

func (t *optenantOperator) ListOpTenants(queryParam *query.Query) (*api.ListResult, error) {

	//if optenant != "" {
	//	// filter by optenant
	//	queryParam.Filters[query.FieldLabel] = query.Value(fmt.Sprintf("%s=%s", optenantv1alpha1.OpTenantLabel, optenant))
	//}

	result, err := t.resourceGetter.List("optenants", "", queryParam)
	if err != nil {
		klog.Error(err)
		return nil, err
	}
	return result, nil
}

// CreateGroup adds a workspace label to group which indicates group is under the workspace
func (t *optenantOperator) CreateOpTenant(optenant *optenantv1alpha1.OpTenant) (*optenantv1alpha1.OpTenant, error) {

	if optenant.GenerateName == "" {
		err := errors.NewInvalid(iamv1alpha2.SchemeGroupVersion.WithKind(optenantv1alpha1.ResourcePluralOpTenant).GroupKind(),
			"", []*field.Error{field.Required(field.NewPath("metadata.generateName"), "generateName is required")})
		klog.Error(err)
		return nil, err
	}
	// generateName is used as displayName
	// ensure generateName is unique in optenant scope
	if unique, err := t.isGenerateNameUnique(optenant.GenerateName); err != nil {
		return nil, err
	} else if !unique {
		err = errors.NewConflict(optenantv1alpha1.Resource(optenantv1alpha1.ResourcePluralOpTenant),
			optenant.GenerateName, fmt.Errorf("a named %s already exists in the optenant", optenant.GenerateName))
		klog.Error(err)
		return nil, err
	}

	return t.ksclient.OpTenantV1alpha1().OpTenants().Create(context.Background(), optenant, metav1.CreateOptions{})
}

//检查是否存在
func (t *optenantOperator) isGenerateNameUnique(generateName string) (bool, error) {
	result, err := t.ListOpTenants(query.New())
	if err != nil {
		klog.Error(err)
		return false, err
	}
	for _, obj := range result.Items {
		g := obj.(*optenantv1alpha1.OpTenant)
		if g.GenerateName == generateName {
			return false, err
		}
	}
	return true, nil
}

func (t *optenantOperator) DescribeOpTenant(name string) (*optenantv1alpha1.OpTenant, error) {
	obj, err := t.resourceGetter.Get("optenants", "", name)
	if err != nil {
		return nil, err
	}
	ns := obj.(*optenantv1alpha1.OpTenant)
	//这里匹配命名空间暂时不知道怎么用的，注释
	//if ns.Labels[optenantv1alpha1.OpTenantLabel] != optenant {
	//	err := errors.NewNotFound(corev1.Resource("optenant"), group)
	//	klog.Error(err)
	//	return nil, err
	//}
	return ns, nil
}

//
func (t *optenantOperator) DeleteOpTenant(name string) error {
	_, err := t.DescribeOpTenant(name)
	if err != nil {
		return err
	}
	return t.ksclient.OpTenantV1alpha1().OpTenants().Delete(context.Background(), name, *metav1.NewDeleteOptions(0))
}

//func (t *optenantOperator) UpdateOpTenant(workspace string, group *optenantv1alpha1.OpTenant) (*optenantv1alpha1.OpTenant, error) {
func (t *optenantOperator) UpdateOpTenant(optenant *optenantv1alpha1.OpTenant) (*optenantv1alpha1.OpTenant, error) {
	//_, err := t.DescribeOpTenant(workspace, group.Name)
	_, err := t.DescribeOpTenant(optenant.Name)
	if err != nil {
		return nil, err
	}
	//optenant = labelGroupWithWorkspaceName(optenant, workspace)
	return t.ksclient.OpTenantV1alpha1().OpTenants().Update(context.Background(), optenant, metav1.UpdateOptions{})
}

// labelGroupWithWorkspaceName adds a kubesphere.io/workspace=[workspaceName] label to namespace which
//// indicates namespace is under the workspace
//func labelGroupWithWorkspaceName(namespace *optenantv1alpha1.OpTenant, workspaceName string) *optenantv1alpha1.OpTenant {
//	if namespace.Labels == nil {
//		namespace.Labels = make(map[string]string, 0)
//	}
//
//	namespace.Labels[optenantv1alpha1.OpTenantLabel] = workspaceName // label namespace with workspace name
//
//	return namespace
//}

//
//func (t *groupOperator) PatchGroup(workspace string, group *iamv1alpha2.Group) (*iamv1alpha2.Group, error) {
//	_, err := t.DescribeGroup(workspace, group.Name)
//	if err != nil {
//		return nil, err
//	}
//	if group.Labels != nil {
//		group.Labels[tenantv1alpha1.WorkspaceLabel] = workspace
//	}
//	data, err := json.Marshal(group)
//	if err != nil {
//		return nil, err
//	}
//	return t.ksclient.IamV1alpha2().Groups().Patch(context.Background(), group.Name, types.MergePatchType, data, metav1.PatchOptions{})
//}
//
//func (t *groupOperator) DeleteGroupBinding(workspace, name string) error {
//	obj, err := t.resourceGetter.Get("groupbindings", "", name)
//	if err != nil {
//		return err
//	}
//	ns := obj.(*iamv1alpha2.GroupBinding)
//	if ns.Labels[tenantv1alpha1.WorkspaceLabel] != workspace {
//		err := errors.NewNotFound(corev1.Resource("groupbinding"), name)
//		klog.Error(err)
//		return err
//	}
//
//	return t.ksclient.IamV1alpha2().GroupBindings().Delete(context.Background(), name, *metav1.NewDeleteOptions(0))
//}
//
//func (t *groupOperator) CreateGroupBinding(workspace, groupName, userName string) (*iamv1alpha2.GroupBinding, error) {
//
//	groupBinding := iamv1alpha2.GroupBinding{
//		ObjectMeta: metav1.ObjectMeta{
//			GenerateName: fmt.Sprintf("%s-%s-", groupName, userName),
//			Labels: map[string]string{
//				iamv1alpha2.UserReferenceLabel:  userName,
//				iamv1alpha2.GroupReferenceLabel: groupName,
//				tenantv1alpha1.WorkspaceLabel:   workspace,
//			},
//		},
//		Users: []string{userName},
//		GroupRef: iamv1alpha2.GroupRef{
//			APIGroup: iamv1alpha2.SchemeGroupVersion.Group,
//			Kind:     iamv1alpha2.ResourcePluralGroup,
//			Name:     groupName,
//		},
//	}
//
//	return t.ksclient.IamV1alpha2().GroupBindings().Create(context.Background(), &groupBinding, metav1.CreateOptions{})
//}
//
//func (t *groupOperator) ListGroupBindings(workspace string, query *query.Query) (*api.ListResult, error) {
//
//	lableSelector, err := labels.ConvertSelectorToLabelsMap(query.LabelSelector)
//	if err != nil {
//		klog.Error(err)
//		return nil, err
//	}
//	// workspace resources must be filtered by workspace
//	wsSelector := labels.Set{tenantv1alpha1.WorkspaceLabel: workspace}
//	query.LabelSelector = labels.Merge(lableSelector, wsSelector).String()
//
//	result, err := t.resourceGetter.List("groupbindings", "", query)
//	if err != nil {
//		klog.Error(err)
//		return nil, err
//	}
//	return result, nil
//}
//
