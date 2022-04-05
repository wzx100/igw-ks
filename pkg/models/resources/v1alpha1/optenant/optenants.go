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
	"kubesphere.io/kubesphere/pkg/models/resources/v1alpha1"

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

	return v1alpha1.DefaultObjectMetaFilter(role.ObjectMeta, filter)
}
