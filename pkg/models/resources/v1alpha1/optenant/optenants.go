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

package optenant

import (
	"k8s.io/apimachinery/pkg/runtime"
	iamv1alpha2 "kubesphere.io/api/iam/v1alpha2"
	"kubesphere.io/kubesphere/pkg/models/resources/v1alpha1"
	"strings"

	tenantv1alpha1 "kubesphere.io/api/optenant/v1alpha1"

	"kubesphere.io/kubesphere/pkg/api"
	"kubesphere.io/kubesphere/pkg/apiserver/query"
	informers "kubesphere.io/kubesphere/pkg/client/informers/externalversions"
)

type optenantGetter struct {
	sharedInformers informers.SharedInformerFactory
}

func New(sharedInformers informers.SharedInformerFactory) v1alpha1.Interface {
	return &optenantGetter{sharedInformers: sharedInformers}
}

func (d *optenantGetter) Get(_, name string) (runtime.Object, error) {
	return d.sharedInformers.OpTenant().V1alpha1().OpTenants().Lister().Get(name)
}

func (d *optenantGetter) List(_ string, query *query.Query) (*api.ListResult, error) {

	optenants, err := d.sharedInformers.OpTenant().V1alpha1().OpTenants().Lister().List(query.Selector())
	//optenants, err := d.sharedInformers.Iam().V1alpha2().Users().Lister().List(query.Selector())
	if err != nil {
		return nil, err
	}

	var result []runtime.Object
	for _, optenant := range optenants {
		result = append(result, optenant)
	}

	return v1alpha1.DefaultList(result, query, d.compare, d.filter), nil
}

func (d *optenantGetter) compare(left runtime.Object, right runtime.Object, field query.Field) bool {

	leftWorkspace, ok := left.(*tenantv1alpha1.OpTenant)
	if !ok {
		return false
	}

	rightWorkspace, ok := right.(*tenantv1alpha1.OpTenant)
	if !ok {
		return false
	}

	return v1alpha1.DefaultObjectMetaCompare(leftWorkspace.ObjectMeta, rightWorkspace.ObjectMeta, field)
}

func (d *optenantGetter) filter(object runtime.Object, filter query.Filter) bool {
	role, ok := object.(*tenantv1alpha1.OpTenant)

	if !ok {
		return false
	}

	return DefaultObjectFilter(role, filter)
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
func DefaultObjectFilter(item *tenantv1alpha1.OpTenant, filter query.Filter) bool {
	switch filter.Field {
	case iamv1alpha2.FieldOptenantName:
		return item.Spec.TenantName == string(filter.Value)
	case iamv1alpha2.FieldOptenantId:
		return item.Name == string(filter.Value)
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
