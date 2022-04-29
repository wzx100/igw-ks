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

package v1alpha2

import (
	"encoding/json"
	"fmt"
	"kubesphere.io/kubesphere/pkg/models/iam/im"
	"kubesphere.io/kubesphere/pkg/models/optenant"

	"github.com/emicklei/go-restful"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apiserver/pkg/authentication/user"
	"k8s.io/klog"

	quotav1alpha2 "kubesphere.io/api/quota/v1alpha2"
	tenantv1alpha2 "kubesphere.io/api/tenant/v1alpha2"

	"kubesphere.io/kubesphere/pkg/api"
	auditingv1alpha1 "kubesphere.io/kubesphere/pkg/api/auditing/v1alpha1"
	eventsv1alpha1 "kubesphere.io/kubesphere/pkg/api/events/v1alpha1"
	loggingv1alpha2 "kubesphere.io/kubesphere/pkg/api/logging/v1alpha2"
	"kubesphere.io/kubesphere/pkg/apiserver/query"
	"kubesphere.io/kubesphere/pkg/apiserver/request"
	"kubesphere.io/kubesphere/pkg/models/tenant"
	servererr "kubesphere.io/kubesphere/pkg/server/errors"
	meteringclient "kubesphere.io/kubesphere/pkg/simple/client/metering"
)

type tenantHandler struct {
	im              im.IdentityManagementInterface
	opTenantGroup   optenant.OpTenantOperator
	tenant          tenant.Interface
	meteringOptions *meteringclient.Options
}

func newTenantHandler(tenant tenant.Interface, opTenantGroup optenant.OpTenantOperator, im im.IdentityManagementInterface,
	meteringOptions *meteringclient.Options) *tenantHandler {

	if meteringOptions == nil || meteringOptions.RetentionDay == "" {
		meteringOptions = &meteringclient.DefaultMeteringOption
	}

	return &tenantHandler{
		opTenantGroup:   opTenantGroup,
		im:              im,
		tenant:          tenant,
		meteringOptions: meteringOptions,
	}
}

func (h *tenantHandler) ListWorkspaces(req *restful.Request, resp *restful.Response) {
	user, ok := request.UserFrom(req.Request.Context())
	queryParam := query.ParseQueryParameter(req)
	if !ok {
		err := errors.NewInternalError(fmt.Errorf("cannot obtain user info"))
		api.HandleInternalError(resp, req, err)
		return
	}
	operatoruser, err := h.im.DescribeUser(user.GetName())
	if err != nil {
		klog.Error("=========查询用户信息异常======", err.Error())
		api.HandleInternalError(resp, req, err)
		return
	}
	if operatoruser == nil {
		klog.Error("==========查询用户信息为空===========")
		api.HandleError(resp, req, fmt.Errorf("==========查询用户信息为空==========="))
		return
	}
	if operatoruser.Spec.OpTenantId != "" {
		klog.Error("=========查询企业空间---当前用户名:", operatoruser.GetName(), "当前用户optenantid:", operatoruser.Spec.OpTenantId, "======")
		queryParam.Filters["optenantid"] = query.Value(operatoruser.Spec.OpTenantId)
	}

	if !ok {
		err := fmt.Errorf("cannot obtain user info")
		klog.Errorln(err)
		api.HandleForbidden(resp, nil, err)
		return
	}

	result, err := h.tenant.ListWorkspaces(user, queryParam)

	for i, item := range result.Items {
		workspace := item.(*tenantv1alpha2.WorkspaceTemplate)
		workspace = workspace.DeepCopy()
		if workspace.Spec.OpTenantId != "" {
			//查询用户所属租户名称
			opTenant, err := h.opTenantGroup.DescribeOpTenant(workspace.Spec.OpTenantId)
			if err != nil {
				api.HandleInternalError(resp, req, err)
				return
			}
			if opTenant != nil {
				tenantName := opTenant.Spec.TenantName
				workspace.Spec.OpTenantName = tenantName
			}
		}
		result.Items[i] = workspace
	}
	if err != nil {
		api.HandleInternalError(resp, nil, err)
		return
	}

	resp.WriteEntity(result)
}

func (h *tenantHandler) ListFederatedNamespaces(req *restful.Request, resp *restful.Response) {
	workspace := req.PathParameter("workspace")
	queryParam := query.ParseQueryParameter(req)

	workspaceMember, ok := request.UserFrom(req.Request.Context())
	if !ok {
		err := fmt.Errorf("cannot obtain user info")
		klog.Errorln(err)
		api.HandleForbidden(resp, nil, err)
		return
	}

	result, err := h.tenant.ListFederatedNamespaces(workspaceMember, workspace, queryParam)
	if err != nil {
		api.HandleInternalError(resp, nil, err)
		return
	}

	resp.WriteEntity(result)
}

func (h *tenantHandler) ListNamespaces(req *restful.Request, resp *restful.Response) {
	workspace := req.PathParameter("workspace")
	queryParam := query.ParseQueryParameter(req)

	var workspaceMember user.Info
	if username := req.PathParameter("workspacemember"); username != "" {
		workspaceMember = &user.DefaultInfo{
			Name: username,
		}
	} else {
		requestUser, ok := request.UserFrom(req.Request.Context())
		if !ok {
			err := fmt.Errorf("cannot obtain user info")
			klog.Errorln(err)
			api.HandleForbidden(resp, nil, err)
			return
		}
		workspaceMember = requestUser
	}

	result, err := h.tenant.ListNamespaces(workspaceMember, workspace, queryParam)
	if err != nil {
		api.HandleInternalError(resp, nil, err)
		return
	}

	resp.WriteEntity(result)
}

func (h *tenantHandler) ListDevOpsProjects(req *restful.Request, resp *restful.Response) {
	workspace := req.PathParameter("workspace")
	queryParam := query.ParseQueryParameter(req)

	var workspaceMember user.Info
	if username := req.PathParameter("workspacemember"); username != "" {
		workspaceMember = &user.DefaultInfo{
			Name: username,
		}
	} else {
		requestUser, ok := request.UserFrom(req.Request.Context())
		if !ok {
			err := fmt.Errorf("cannot obtain user info")
			klog.Errorln(err)
			api.HandleForbidden(resp, nil, err)
			return
		}
		workspaceMember = requestUser
	}

	result, err := h.tenant.ListDevOpsProjects(workspaceMember, workspace, queryParam)

	if err != nil {
		api.HandleInternalError(resp, nil, err)
		return
	}

	resp.WriteEntity(result)
}

func (h *tenantHandler) CreateNamespace(request *restful.Request, response *restful.Response) {
	workspace := request.PathParameter("workspace")
	var namespace corev1.Namespace

	err := request.ReadEntity(&namespace)

	if err != nil {
		klog.Error(err)
		api.HandleBadRequest(response, request, err)
		return
	}

	created, err := h.tenant.CreateNamespace(workspace, &namespace)

	if err != nil {
		klog.Error(err)
		if errors.IsNotFound(err) {
			api.HandleNotFound(response, request, err)
			return
		}
		api.HandleBadRequest(response, request, err)
		return
	}

	response.WriteEntity(created)
}

func (h *tenantHandler) CreateWorkspace(request *restful.Request, response *restful.Response) {
	var workspace tenantv1alpha2.WorkspaceTemplate

	err := request.ReadEntity(&workspace)

	if err != nil {
		klog.Error(err)
		api.HandleBadRequest(response, request, err)
		return
	}
	optenant, err := h.opTenantGroup.DescribeOpTenant(workspace.Spec.OpTenantId)
	if err != nil {
		klog.Error(err)
		api.HandleBadRequest(response, request, err)
		return
	}
	if optenant != nil {
		workspace.Spec.OpTenantName = optenant.Spec.TenantName
	}

	created, err := h.tenant.CreateWorkspace(&workspace)

	if err != nil {
		klog.Error(err)
		if errors.IsNotFound(err) {
			api.HandleNotFound(response, request, err)
			return
		}
		api.HandleBadRequest(response, request, err)
		return
	}

	response.WriteEntity(created)
}

func (h *tenantHandler) DeleteWorkspace(request *restful.Request, response *restful.Response) {
	workspace := request.PathParameter("workspace")

	opts := metav1.DeleteOptions{}

	err := request.ReadEntity(&opts)
	if err != nil {
		opts = *metav1.NewDeleteOptions(0)
	}

	err = h.tenant.DeleteWorkspace(workspace, opts)

	if err != nil {
		klog.Error(err)
		if errors.IsNotFound(err) {
			api.HandleNotFound(response, request, err)
			return
		}
		api.HandleBadRequest(response, request, err)
		return
	}

	response.WriteEntity(servererr.None)
}

func (h *tenantHandler) UpdateWorkspace(request *restful.Request, response *restful.Response) {
	workspaceName := request.PathParameter("workspace")
	var workspace tenantv1alpha2.WorkspaceTemplate
	err := request.ReadEntity(&workspace)

	opTenant, err := h.opTenantGroup.DescribeOpTenant(workspace.Spec.OpTenantId)
	if err != nil {
		klog.Error(err)
		api.HandleBadRequest(response, request, err)
		return
	}
	if opTenant != nil {
		workspace.Spec.OpTenantName = opTenant.Spec.TenantName
	}

	if err != nil {
		klog.Error(err)
		api.HandleBadRequest(response, request, err)
		return
	}

	if workspaceName != workspace.Name {
		err := fmt.Errorf("the name of the object (%s) does not match the name on the URL (%s)", workspace.Name, workspaceName)
		klog.Errorf("%+v", err)
		api.HandleBadRequest(response, request, err)
		return
	}

	updated, err := h.tenant.UpdateWorkspace(&workspace)

	if err != nil {
		klog.Error(err)
		if errors.IsNotFound(err) {
			api.HandleNotFound(response, request, err)
			return
		}
		if errors.IsBadRequest(err) {
			api.HandleBadRequest(response, request, err)
			return
		}
		api.HandleInternalError(response, request, err)
		return
	}

	response.WriteEntity(updated)
}

func (h *tenantHandler) DescribeWorkspace(request *restful.Request, response *restful.Response) {
	workspaceName := request.PathParameter("workspace")

	workspace, err := h.tenant.DescribeWorkspace(workspaceName)

	if err != nil {
		klog.Error(err)
		if errors.IsNotFound(err) {
			api.HandleNotFound(response, request, err)
			return
		}
		api.HandleInternalError(response, request, err)
		return
	}

	response.WriteEntity(workspace)
}

func (h *tenantHandler) ListWorkspaceClusters(request *restful.Request, response *restful.Response) {
	workspaceName := request.PathParameter("workspace")

	result, err := h.tenant.ListWorkspaceClusters(workspaceName)

	if err != nil {
		klog.Error(err)
		if errors.IsNotFound(err) {
			api.HandleNotFound(response, request, err)
			return
		}
		api.HandleInternalError(response, request, err)
		return
	}

	response.WriteEntity(result)
}

func (h *tenantHandler) Events(req *restful.Request, resp *restful.Response) {
	user, ok := request.UserFrom(req.Request.Context())
	if !ok {
		err := fmt.Errorf("cannot obtain user info")
		klog.Errorln(err)
		api.HandleForbidden(resp, req, err)
		return
	}
	queryParam, err := eventsv1alpha1.ParseQueryParameter(req)
	if err != nil {
		klog.Errorln(err)
		api.HandleInternalError(resp, req, err)
		return
	}

	result, err := h.tenant.Events(user, queryParam)
	if err != nil {
		klog.Errorln(err)
		api.HandleInternalError(resp, req, err)
		return
	}

	resp.WriteEntity(result)

}

func (h *tenantHandler) QueryLogs(req *restful.Request, resp *restful.Response) {
	user, ok := request.UserFrom(req.Request.Context())
	if !ok {
		err := fmt.Errorf("cannot obtain user info")
		klog.Errorln(err)
		api.HandleForbidden(resp, req, err)
		return
	}
	queryParam, err := loggingv1alpha2.ParseQueryParameter(req)
	if err != nil {
		klog.Errorln(err)
		api.HandleInternalError(resp, req, err)
		return
	}

	if queryParam.Operation == loggingv1alpha2.OperationExport {
		resp.Header().Set(restful.HEADER_ContentType, "text/plain")
		resp.Header().Set("Content-Disposition", "attachment")
		err := h.tenant.ExportLogs(user, queryParam, resp)
		if err != nil {
			klog.Errorln(err)
			api.HandleInternalError(resp, req, err)
			return
		}
	} else {
		result, err := h.tenant.QueryLogs(user, queryParam)
		if err != nil {
			klog.Errorln(err)
			api.HandleInternalError(resp, req, err)
			return
		}
		resp.WriteAsJson(result)
	}
}

func (h *tenantHandler) Auditing(req *restful.Request, resp *restful.Response) {
	user, ok := request.UserFrom(req.Request.Context())
	if !ok {
		err := fmt.Errorf("cannot obtain user info")
		klog.Errorln(err)
		api.HandleForbidden(resp, req, err)
		return
	}
	queryParam, err := auditingv1alpha1.ParseQueryParameter(req)
	if err != nil {
		klog.Errorln(err)
		api.HandleInternalError(resp, req, err)
		return
	}

	result, err := h.tenant.Auditing(user, queryParam)
	if err != nil {
		klog.Errorln(err)
		api.HandleInternalError(resp, req, err)
		return
	}

	_ = resp.WriteEntity(result)

}

func (h *tenantHandler) DescribeNamespace(request *restful.Request, response *restful.Response) {
	workspaceName := request.PathParameter("workspace")
	namespaceName := request.PathParameter("namespace")
	ns, err := h.tenant.DescribeNamespace(workspaceName, namespaceName)

	if err != nil {
		if errors.IsNotFound(err) {
			api.HandleNotFound(response, request, err)
			return
		}
		api.HandleInternalError(response, request, err)
		return
	}

	response.WriteEntity(ns)
}

func (h *tenantHandler) DeleteNamespace(request *restful.Request, response *restful.Response) {
	workspaceName := request.PathParameter("workspace")
	namespaceName := request.PathParameter("namespace")

	err := h.tenant.DeleteNamespace(workspaceName, namespaceName)

	if err != nil {
		if errors.IsNotFound(err) {
			api.HandleNotFound(response, request, err)
			return
		}
		api.HandleInternalError(response, request, err)
		return
	}

	response.WriteEntity(servererr.None)
}

func (h *tenantHandler) UpdateNamespace(request *restful.Request, response *restful.Response) {
	workspaceName := request.PathParameter("workspace")
	namespaceName := request.PathParameter("namespace")

	var namespace corev1.Namespace
	err := request.ReadEntity(&namespace)
	if err != nil {
		klog.Error(err)
		api.HandleBadRequest(response, request, err)
		return
	}

	if namespaceName != namespace.Name {
		err := fmt.Errorf("the name of the object (%s) does not match the name on the URL (%s)", namespace.Name, namespaceName)
		klog.Errorf("%+v", err)
		api.HandleBadRequest(response, request, err)
		return
	}

	updated, err := h.tenant.UpdateNamespace(workspaceName, &namespace)

	if err != nil {
		klog.Error(err)
		if errors.IsNotFound(err) {
			api.HandleNotFound(response, request, err)
			return
		}
		if errors.IsBadRequest(err) {
			api.HandleBadRequest(response, request, err)
			return
		}
		api.HandleInternalError(response, request, err)
		return
	}

	response.WriteEntity(updated)
}

func (h *tenantHandler) PatchNamespace(request *restful.Request, response *restful.Response) {
	workspaceName := request.PathParameter("workspace")
	namespaceName := request.PathParameter("namespace")

	var namespace corev1.Namespace
	err := request.ReadEntity(&namespace)
	if err != nil {
		klog.Error(err)
		api.HandleBadRequest(response, request, err)
		return
	}

	namespace.Name = namespaceName

	patched, err := h.tenant.PatchNamespace(workspaceName, &namespace)

	if err != nil {
		klog.Error(err)
		if errors.IsNotFound(err) {
			api.HandleNotFound(response, request, err)
			return
		}
		if errors.IsBadRequest(err) {
			api.HandleBadRequest(response, request, err)
			return
		}
		api.HandleInternalError(response, request, err)
		return
	}

	response.WriteEntity(patched)
}

func (h *tenantHandler) PatchWorkspace(request *restful.Request, response *restful.Response) {
	workspaceName := request.PathParameter("workspace")
	var data json.RawMessage
	err := request.ReadEntity(&data)
	if err != nil {
		klog.Error(err)
		api.HandleBadRequest(response, request, err)
		return
	}

	patched, err := h.tenant.PatchWorkspace(workspaceName, data)

	if err != nil {
		klog.Error(err)
		if errors.IsNotFound(err) {
			api.HandleNotFound(response, request, err)
			return
		}
		if errors.IsBadRequest(err) {
			api.HandleBadRequest(response, request, err)
			return
		}
		api.HandleInternalError(response, request, err)
		return
	}

	response.WriteEntity(patched)
}

func (h *tenantHandler) ListClusters(r *restful.Request, response *restful.Response) {
	user, ok := request.UserFrom(r.Request.Context())

	if !ok {
		response.WriteEntity([]interface{}{})
		return
	}

	result, err := h.tenant.ListClusters(user)

	if err != nil {
		klog.Error(err)
		if errors.IsNotFound(err) {
			api.HandleNotFound(response, r, err)
			return
		}
		api.HandleInternalError(response, r, err)
		return
	}

	response.WriteEntity(result)
}

func (h *tenantHandler) CreateWorkspaceResourceQuota(r *restful.Request, response *restful.Response) {
	workspaceName := r.PathParameter("workspace")
	resourceQuota := &quotav1alpha2.ResourceQuota{}
	err := r.ReadEntity(resourceQuota)
	if err != nil {
		api.HandleBadRequest(response, r, err)
		return
	}
	result, err := h.tenant.CreateWorkspaceResourceQuota(workspaceName, resourceQuota)
	if err != nil {
		api.HandleInternalError(response, r, err)
		return
	}
	response.WriteEntity(result)
}

func (h *tenantHandler) DeleteWorkspaceResourceQuota(r *restful.Request, response *restful.Response) {
	workspace := r.PathParameter("workspace")
	resourceQuota := r.PathParameter("resourcequota")

	if err := h.tenant.DeleteWorkspaceResourceQuota(workspace, resourceQuota); err != nil {
		if errors.IsNotFound(err) {
			api.HandleNotFound(response, r, err)
			return
		}
		api.HandleInternalError(response, r, err)
		return
	}

	response.WriteEntity(servererr.None)
}

func (h *tenantHandler) UpdateWorkspaceResourceQuota(r *restful.Request, response *restful.Response) {
	workspaceName := r.PathParameter("workspace")
	resourceQuotaName := r.PathParameter("resourcequota")
	resourceQuota := &quotav1alpha2.ResourceQuota{}
	err := r.ReadEntity(resourceQuota)
	if err != nil {
		api.HandleBadRequest(response, r, err)
		return
	}

	if resourceQuotaName != resourceQuota.Name {
		err := fmt.Errorf("the name of the object (%s) does not match the name on the URL (%s)", resourceQuota.Name, resourceQuotaName)
		klog.Errorf("%+v", err)
		api.HandleBadRequest(response, r, err)
		return
	}

	result, err := h.tenant.UpdateWorkspaceResourceQuota(workspaceName, resourceQuota)
	if err != nil {
		api.HandleInternalError(response, r, err)
		return
	}

	response.WriteEntity(result)
}

func (h *tenantHandler) DescribeWorkspaceResourceQuota(r *restful.Request, response *restful.Response) {
	workspaceName := r.PathParameter("workspace")
	resourceQuotaName := r.PathParameter("resourcequota")

	resourceQuota, err := h.tenant.DescribeWorkspaceResourceQuota(workspaceName, resourceQuotaName)
	if err != nil {
		if errors.IsNotFound(err) {
			api.HandleNotFound(response, r, err)
			return
		}
		api.HandleInternalError(response, r, err)
		return
	}

	response.WriteEntity(resourceQuota)
}
