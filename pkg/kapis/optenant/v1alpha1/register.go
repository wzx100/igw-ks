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

package v1alpha1

import (
	"kubesphere.io/kubesphere/pkg/models/optenant"
	"kubesphere.io/kubesphere/pkg/models/tenant"
	"kubesphere.io/kubesphere/pkg/server/errors"
	"net/http"

	"kubesphere.io/kubesphere/pkg/apiserver/authorization/authorizer"

	"github.com/emicklei/go-restful"
	restfulspec "github.com/emicklei/go-restful-openapi"
	"k8s.io/apimachinery/pkg/runtime/schema"

	optenantv1alpha1 "kubesphere.io/api/optenant/v1alpha1"

	"kubesphere.io/kubesphere/pkg/api"
	"kubesphere.io/kubesphere/pkg/apiserver/runtime"
	"kubesphere.io/kubesphere/pkg/constants"
	"kubesphere.io/kubesphere/pkg/models/iam/am"
	"kubesphere.io/kubesphere/pkg/models/iam/im"
)

const (
	GroupName = "optenant.kubesphere.io"
)

var GroupVersion = schema.GroupVersion{Group: GroupName, Version: "v1alpha1"}

func AddToContainer(tenant tenant.Interface, container *restful.Container, im im.IdentityManagementInterface, am am.AccessManagementInterface, group optenant.OpTenantOperator, authorizer authorizer.Authorizer) error {
	ws := runtime.NewWebService(GroupVersion)
	handler := newOPTEANTHandler(tenant, im, am, group, authorizer)

	// 新增租户信息
	ws.Route(ws.POST("/optenants").
		To(handler.CreateOpTenant).
		Doc("Create a optenant account.").
		Returns(http.StatusOK, api.StatusOK, optenantv1alpha1.OpTenant{}).
		Reads(optenantv1alpha1.OpTenant{}).
		Metadata(restfulspec.KeyOpenAPITags, []string{constants.OpTenantTag}))

	// 删除租户信息
	ws.Route(ws.DELETE("/optenants/{optenant}").
		To(handler.DeleteOpTenant).
		Doc("Delete the specified optenant.").
		Param(ws.PathParameter("user", "username")).
		Returns(http.StatusOK, api.StatusOK, errors.None).
		Metadata(restfulspec.KeyOpenAPITags, []string{constants.OpTenantTag}))

	//更新租户信息
	ws.Route(ws.PUT("/optenants/{optenant}").
		To(handler.UpdateOpTenant).
		Doc("Update optenant profile.").
		Reads(optenantv1alpha1.OpTenant{}).
		Param(ws.PathParameter("name", "optenant name")).
		Returns(http.StatusOK, api.StatusOK, optenantv1alpha1.OpTenant{}).
		Metadata(restfulspec.KeyOpenAPITags, []string{constants.OpTenantTag}))

	// 返回单个租户信息
	ws.Route(ws.GET("/optenants/{name}").
		To(handler.DescribeOpTeant).
		Doc("Return user details.").
		Param(ws.PathParameter("name", "optenant name")).
		Returns(http.StatusOK, api.StatusOK, optenantv1alpha1.OpTenant{}).
		Metadata(restfulspec.KeyOpenAPITags, []string{constants.OpTenantTag}))

	// 返回所有租户信息
	ws.Route(ws.GET("/optenants").
		To(handler.ListOpTenants).
		Doc("List all optenants.").
		Returns(http.StatusOK, api.StatusOK, api.ListResult{Items: []interface{}{optenantv1alpha1.OpTenant{}}}).
		Metadata(restfulspec.KeyOpenAPITags, []string{constants.OpTenantTag}))

	container.Add(ws)
	return nil
}
