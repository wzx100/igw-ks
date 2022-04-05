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

package v1alpha1

import (
	"fmt"
	"github.com/emicklei/go-restful"
	optenantv1alpha1 "kubesphere.io/api/optenant/v1alpha1"
	"kubesphere.io/kubesphere/pkg/api"
	"kubesphere.io/kubesphere/pkg/apiserver/authorization/authorizer"
	"kubesphere.io/kubesphere/pkg/apiserver/query"
	"kubesphere.io/kubesphere/pkg/models/auth"
	"kubesphere.io/kubesphere/pkg/models/iam/am"
	"kubesphere.io/kubesphere/pkg/models/iam/im"
	"kubesphere.io/kubesphere/pkg/models/optenant"
	servererr "kubesphere.io/kubesphere/pkg/server/errors"
	//servererr "kubesphere.io/kubesphere/pkg/server/errors"
)

type Member struct {
	Username string `json:"username"`
	RoleRef  string `json:"roleRef"`
}

type GroupMember struct {
	UserName  string `json:"userName"`
	GroupName string `json:"groupName"`
}

type PasswordReset struct {
	CurrentPassword string `json:"currentPassword"`
	Password        string `json:"password"`
}

type optenantHandler struct {
	am            am.AccessManagementInterface
	im            im.IdentityManagementInterface
	tokenOperator auth.TokenManagementInterface
	group         optenant.OpTenantOperator
	authorizer    authorizer.Authorizer
}

func newOPTEANTHandler(im im.IdentityManagementInterface, am am.AccessManagementInterface, group optenant.OpTenantOperator, authorizer authorizer.Authorizer) *optenantHandler {
	return &optenantHandler{
		am:         am,
		im:         im,
		group:      group,
		authorizer: authorizer,
	}
}

//返回单个租户信息
func (h *optenantHandler) DescribeOpTeant(request *restful.Request, response *restful.Response) {
	//workspaceName := request.PathParameter("optenant")
	optenantName := request.PathParameter("name")
	ns, err := h.group.DescribeOpTenant(optenantName)

	if err != nil {
		api.HandleError(response, request, err)
		return
	}

	response.WriteEntity(ns)
}

//返回所有租户信息
func (h *optenantHandler) ListOpTenants(request *restful.Request, response *restful.Response) {
	//optenantName := request.PathParameter("optenant")
	queryParam := query.ParseQueryParameter(request)
	result, err := h.group.ListOpTenants(queryParam)
	if err != nil {
		api.HandleError(response, request, err)
		return
	}

	response.WriteEntity(result)
}

//创建租户
func (h *optenantHandler) CreateOpTenant(request *restful.Request, response *restful.Response) {
	//workspace := request.PathParameter("optenant")
	var optenant optenantv1alpha1.OpTenant

	err := request.ReadEntity(&optenant)
	if err != nil {
		api.HandleBadRequest(response, request, err)
		return
	}

	created, err := h.group.CreateOpTenant(&optenant)
	if err != nil {
		api.HandleError(response, request, err)
		return
	}
	response.WriteEntity(created)
}

//删除租户
func (h *optenantHandler) DeleteOpTenant(request *restful.Request, response *restful.Response) {
	//workspaceName := request.PathParameter("optenant")
	optenantName := request.PathParameter("optenant")

	err := h.group.DeleteOpTenant(optenantName)
	if err != nil {
		api.HandleError(response, request, err)
		return
	}

	response.WriteEntity(servererr.None)
}

//更新租户
func (h *optenantHandler) UpdateOpTenant(request *restful.Request, response *restful.Response) {
	//workspaceName := request.PathParameter("workspace")
	optenantName := request.PathParameter("optenant")

	var optenant optenantv1alpha1.OpTenant
	err := request.ReadEntity(&optenant)
	if err != nil {
		api.HandleBadRequest(response, request, err)
		return
	}

	if optenantName != optenant.Name {
		err := fmt.Errorf("the name of the object (%s) does not match the name on the URL (%s)", optenant.Name, optenantName)
		api.HandleBadRequest(response, request, err)
		return
	}

	updated, err := h.group.UpdateOpTenant(&optenant)
	if err != nil {
		api.HandleError(response, request, err)
		return
	}

	response.WriteEntity(updated)
}

//
//func (h *optenantHandler) PatchOpTenant(request *restful.Request, response *restful.Response) {
//	workspaceName := request.PathParameter("workspace")
//	groupName := request.PathParameter("group")
//
//	var group iamv1alpha2.Group
//	err := request.ReadEntity(&group)
//	if err != nil {
//		api.HandleBadRequest(response, request, err)
//		return
//	}
//
//	group.Name = groupName
//	patched, err := h.group.PatchGroup(workspaceName, &group)
//	if err != nil {
//		api.HandleError(response, request, err)
//		return
//	}
//
//	response.WriteEntity(patched)
//}
//
//func (h *optenantHandler) CreateGroup(request *restful.Request, response *restful.Response) {
//	workspace := request.PathParameter("workspace")
//	var group iamv1alpha2.Group
//
//	err := request.ReadEntity(&group)
//	if err != nil {
//		api.HandleBadRequest(response, request, err)
//		return
//	}
//
//	created, err := h.group.CreateGroup(workspace, &group)
//	if err != nil {
//		api.HandleError(response, request, err)
//		return
//	}
//
//	response.WriteEntity(created)
//}
//
//func (h *optenantHandler) DescribeGroup(request *restful.Request, response *restful.Response) {
//	workspaceName := request.PathParameter("workspace")
//	groupName := request.PathParameter("group")
//	ns, err := h.group.DescribeGroup(workspaceName, groupName)
//
//	if err != nil {
//		api.HandleError(response, request, err)
//		return
//	}
//
//	response.WriteEntity(ns)
//}
//
//func (h *optenantHandler) DeleteGroup(request *restful.Request, response *restful.Response) {
//	workspaceName := request.PathParameter("workspace")
//	groupName := request.PathParameter("group")
//
//	err := h.group.DeleteGroup(workspaceName, groupName)
//	if err != nil {
//		api.HandleError(response, request, err)
//		return
//	}
//
//	response.WriteEntity(servererr.None)
//}
//
//func (h *optenantHandler) UpdateGroup(request *restful.Request, response *restful.Response) {
//	workspaceName := request.PathParameter("workspace")
//	groupName := request.PathParameter("group")
//
//	var group iamv1alpha2.Group
//	err := request.ReadEntity(&group)
//	if err != nil {
//		api.HandleBadRequest(response, request, err)
//		return
//	}
//
//	if groupName != group.Name {
//		err := fmt.Errorf("the name of the object (%s) does not match the name on the URL (%s)", group.Name, groupName)
//		api.HandleBadRequest(response, request, err)
//		return
//	}
//
//	updated, err := h.group.UpdateGroup(workspaceName, &group)
//	if err != nil {
//		api.HandleError(response, request, err)
//		return
//	}
//
//	response.WriteEntity(updated)
//}
//
//func (h *optenantHandler) PatchGroup(request *restful.Request, response *restful.Response) {
//	workspaceName := request.PathParameter("workspace")
//	groupName := request.PathParameter("group")
//
//	var group iamv1alpha2.Group
//	err := request.ReadEntity(&group)
//	if err != nil {
//		api.HandleBadRequest(response, request, err)
//		return
//	}
//
//	group.Name = groupName
//	patched, err := h.group.PatchGroup(workspaceName, &group)
//	if err != nil {
//		api.HandleError(response, request, err)
//		return
//	}
//
//	response.WriteEntity(patched)
//}
//
//func (h *optenantHandler) ListGroupBindings(request *restful.Request, response *restful.Response) {
//	workspaceName := request.PathParameter("workspace")
//	queryParam := query.ParseQueryParameter(request)
//	result, err := h.group.ListGroupBindings(workspaceName, queryParam)
//	if err != nil {
//		api.HandleError(response, request, err)
//		return
//	}
//
//	response.WriteEntity(result)
//}
//
//func (h *optenantHandler) ListGroupRoleBindings(request *restful.Request, response *restful.Response) {
//	workspaceName := request.PathParameter("workspace")
//	queryParam := query.ParseQueryParameter(request)
//	result, err := h.am.ListGroupRoleBindings(workspaceName, queryParam)
//	if err != nil {
//		api.HandleInternalError(response, request, err)
//		return
//	}
//
//	response.WriteEntity(result)
//}
//
//func (h *optenantHandler) CreateGroupBinding(request *restful.Request, response *restful.Response) {
//
//	workspace := request.PathParameter("workspace")
//
//	var members []GroupMember
//	err := request.ReadEntity(&members)
//	if err != nil {
//		api.HandleBadRequest(response, request, err)
//		return
//	}
//
//	var results []iamv1alpha2.GroupBinding
//	for _, item := range members {
//		b, err := h.group.CreateGroupBinding(workspace, item.GroupName, item.UserName)
//		if err != nil {
//			api.HandleError(response, request, err)
//			return
//		}
//		results = append(results, *b)
//	}
//
//	response.WriteEntity(results)
//}
//
//func (h *optenantHandler) DeleteGroupBinding(request *restful.Request, response *restful.Response) {
//	workspaceName := request.PathParameter("workspace")
//	name := request.PathParameter("groupbinding")
//
//	err := h.group.DeleteGroupBinding(workspaceName, name)
//	if err != nil {
//		api.HandleError(response, request, err)
//		return
//	}
//
//	response.WriteEntity(servererr.None)
//}
