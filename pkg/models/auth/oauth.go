/*

 Copyright 2021 The KubeSphere Authors.

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

package auth

import (
	"context"
	"encoding/json"
	"fmt"
	"io/ioutil"
	optenantv1alpha1 "kubesphere.io/api/optenant/v1alpha1"
	"kubesphere.io/kubesphere/pkg/models/iam/am"
	"kubesphere.io/kubesphere/pkg/models/optenant"
	"net/http"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	kubesphere "kubesphere.io/kubesphere/pkg/client/clientset/versioned"

	"kubesphere.io/kubesphere/pkg/apiserver/authentication"

	"k8s.io/apimachinery/pkg/api/errors"
	authuser "k8s.io/apiserver/pkg/authentication/user"
	"k8s.io/klog"
	iamv1alpha2 "kubesphere.io/api/iam/v1alpha2"

	"kubesphere.io/kubesphere/pkg/apiserver/authentication/identityprovider"
	"kubesphere.io/kubesphere/pkg/apiserver/authentication/oauth"
	iamv1alpha2listers "kubesphere.io/kubesphere/pkg/client/listers/iam/v1alpha2"
)

//const MainInfoUrl = "http://induscore.ftzq.internal.virtueit.net:81/v4-snapshot/portalcustomer/v1.0.0/maininfo/"
const MainInfoUrl = "http://coreop.ftzq.internal.virtueit.net:81/v4-snapshot/portalcustomer/v1.0.0/maininfo/"

//const QueryUserInfoUrl = "http://induscore.ftzq.internal.virtueit.net:81/v4-snapshot/portalcustomer/v1.0.0/user-center/userinfo/details"
const QueryUserInfoUrl = "http://coreop.ftzq.internal.virtueit.net:81/v4-snapshot/portalcustomer/v1.0.0/user-center/userinfo/details"
const IsAdmin = 1

type oauthAuthenticator struct {
	ksClient      kubesphere.Interface
	userGetter    *userGetter
	options       *authentication.Options
	opTenantGroup optenant.OpTenantOperator
	am            am.AccessManagementInterface
}

func NewOAuthAuthenticator(am am.AccessManagementInterface, opTenantGroup optenant.OpTenantOperator, ksClient kubesphere.Interface, userLister iamv1alpha2listers.UserLister, options *authentication.Options) OAuthAuthenticator {
	authenticator := &oauthAuthenticator{
		am:            am,
		opTenantGroup: opTenantGroup,
		ksClient:      ksClient,
		userGetter:    &userGetter{userLister: userLister},
		options:       options,
	}
	return authenticator
}

func (o *oauthAuthenticator) Authenticate(_ context.Context, provider string, req *http.Request) (authuser.Info, string, error) {
	providerOptions, err := o.options.OAuthOptions.IdentityProviderOptions(provider)
	// identity provider not registered
	if err != nil {
		klog.Error(err)
		return nil, "", err
	}
	oauthIdentityProvider, err := identityprovider.GetOAuthProvider(providerOptions.Name)
	if err != nil {
		klog.Error(err)
		return nil, "", err
	}
	authenticated, err := oauthIdentityProvider.IdentityExchangeCallback(req)
	if err != nil {
		klog.Error(err)
		return nil, "", err
	}

	klog.V(0).Infof("========当前登录用户名AccountName为:", authenticated.GetUsername(), "==========")
	user, err := o.userGetter.findUser(authenticated.GetUsername())
	if user != nil {
		klog.V(0).Infof("========查询etcd的信息为:邮件:", user.Spec.Email, "姓名:", user.ObjectMeta.Name, "===========")
	} else {
		klog.V(0).Infof("========查询etcd用户信息为空===========")
	}
	//user, err := o.userGetter.findMappedUser(providerOptions.Name, authenticated.GetUserID())
	if user == nil && providerOptions.MappingMethod == oauth.MappingMethodLookup {
		klog.Error(err)
		return nil, "", err
	}

	// the user will automatically create and mapping when login successful.
	if user == nil && providerOptions.MappingMethod == oauth.MappingMethodAuto {
		//if !providerOptions.DisableLoginConfirmation {
		//	return preRegistrationUser(providerOptions.Name, authenticated), providerOptions.Name, nil
		//}
		klog.V(0).Infof("========当前用户AccountName:", authenticated.GetUsername(), "在系统不存在==========")
		user, err = o.ksClient.IamV1alpha2().Users().Create(context.Background(), mappedUser(providerOptions.Name, authenticated), metav1.CreateOptions{})
		if err != nil {
			return nil, providerOptions.Name, err
		}
		byte, err := json.Marshal(user)
		klog.V(0).Infof("==========新增用户信息为", string(byte), "========")
		if err != nil {
			return nil, providerOptions.Name, err
		}
		klog.V(0).Infof("=============>>新增用户成功<<==========")
	} else {
		//更新用户opAccessToken
		klog.V(0).Infof("=============>>编辑用户开始<<==========")
		klog.V(0).Infof("==========old opAccessToken为:", user.Spec.OpAccessToken, "========")
		user.Spec.OpAccessToken = authenticated.GetOpAccessToken()
		user.Spec.Opuid = authenticated.GetOpuid()
		user.Spec.OpCustomerId = authenticated.GetUserID()
		user.Spec.OpDeptId = authenticated.GetDeptid()
		user.Spec.OpTenantId = authenticated.GetTenantId()

		klog.V(0).Infof("==========编辑用户信息前user为", user, "========")
		user, err = o.ksClient.IamV1alpha2().Users().Update(context.Background(), user, metav1.UpdateOptions{})
		klog.V(0).Infof("==========new opAccessToken为:", user.Spec.OpAccessToken, "========")
		byte, err := json.Marshal(user)
		if err != nil {
			return nil, providerOptions.Name, err
		}
		klog.V(0).Infof("==========编辑用户信息为", string(byte), "========")
		queryUser, err := o.ksClient.IamV1alpha2().Users().Get(context.Background(), user.Name, metav1.GetOptions{})
		byte, err = json.Marshal(queryUser)
		if err != nil {
			return nil, providerOptions.Name, err
		}
		klog.V(0).Infof("==========编辑后查询用户信息为", string(byte), "========")
		klog.V(0).Infof("=============>>编辑用户结束<<==========")

	}
	//绑定角色
	globalRoleBindings, err := o.am.ListGlobalRoleBindings(user.Name)
	if len(globalRoleBindings) == 0 {
		//没绑定角色则需要根据查询的信息 绑定角色
		if user.Spec.OpCustomerId != "" && user.Spec.OpTenantId != "" {
			opUserInfoReq, err := http.NewRequest("GET", QueryUserInfoUrl+"/"+user.Spec.OpCustomerId, nil)
			if err != nil {
				return nil, providerOptions.Name, err
			}
			opUserInfoReq.Header.Set("Content-Type", "application/json")
			opUserInfoReq.Header.Set("customer_id", user.Spec.OpCustomerId)
			opUserInfoReq.Header.Set("tenant_id", user.Spec.OpTenantId)

			client := http.Client{}
			opResp, err := client.Do(opUserInfoReq) //Do 方法发送请求，返回 HTTP 回复
			if err != nil {
				klog.Error("=========调用op查询用户接口异常======", err.Error())
				return nil, providerOptions.Name, err
			}
			data, err := ioutil.ReadAll(opResp.Body)
			if err != nil {
				return nil, providerOptions.Name, err
			}
			defer opResp.Body.Close()
			var userCenterResp UserCenterResp
			err = json.Unmarshal(data, &userCenterResp)
			if userCenterResp.Success == false {
				var errorMessage string
				if userCenterResp.Message != "" {
					errorMessage = userCenterResp.Message
				} else {
					jsonByte, _ := json.Marshal(userCenterResp.Data)
					errorMessage = string(jsonByte)
				}
				klog.Error("调用op查询用户信息接口失败:", errorMessage)

				err = errors.NewInternalError(fmt.Errorf(errorMessage))
				return nil, providerOptions.Name, err
			} else {
				isMain := userCenterResp.Data.IsAdmin
				klog.Error("调用op查询用户信息接口返回isMain:", isMain)
				globalRole := ""
				if isMain == IsAdmin {
					//绑定租户管理员
					globalRole = "tenant-admin"
				} else {
					//绑定普通用户
					globalRole = "platform-regular"
				}
				if globalRole != "" {
					if err := o.am.CreateGlobalRoleBinding(user.Name, globalRole); err != nil {
						return nil, providerOptions.Name, err
					}
				}

			}

		}
	}

	//查询租户信息
	if user != nil && user.Spec.OpTenantId != "" && user.Spec.OpCustomerId != "" {
		opMainInfoReq, err := http.NewRequest("GET", MainInfoUrl+"/"+user.Spec.OpTenantId, nil)
		if err != nil {
			return nil, providerOptions.Name, err
		}
		opMainInfoReq.Header.Set("Content-Type", "application/json")
		opMainInfoReq.Header.Set("customer_id", user.Spec.OpCustomerId)
		opMainInfoReq.Header.Set("tenant_id", user.Spec.OpTenantId)

		client := http.Client{}
		opResp, err := client.Do(opMainInfoReq) //Do 方法发送请求，返回 HTTP 回复
		if err != nil {
			klog.Error("=========调用op查询租户接口异常======", err.Error())
			return nil, providerOptions.Name, err
		}
		data, err := ioutil.ReadAll(opResp.Body)
		if err != nil {
			klog.Error("=========解析op查询租户信息异常======", err.Error())
			return nil, providerOptions.Name, err
		}
		defer opResp.Body.Close()
		var userCenterResp UserCenterResp
		err = json.Unmarshal(data, &userCenterResp)
		if userCenterResp.Success == false {
			var errorMessage string
			if userCenterResp.Message != "" {
				errorMessage = userCenterResp.Message
			} else {
				jsonByte, _ := json.Marshal(userCenterResp.Data)
				errorMessage = string(jsonByte)
			}
			klog.Error("调用op查询租户信息接口失败:", errorMessage)

			err = errors.NewInternalError(fmt.Errorf(errorMessage))
			return nil, providerOptions.Name, err
		} else {
			//如果成功获取到对应的id赋值给user\
			//管理员名称
			userName := userCenterResp.Data.UserName
			//租户名称
			mainName := userCenterResp.Data.MainName
			mainId := userCenterResp.Data.MainId
			klog.Error("调用op查询租户信息接口数据为userName:", userName, ",mainName:", mainName, ",mainId:", mainId)
			opTenantInfo, err := o.opTenantGroup.DescribeOpTenant(mainId)
			if opTenantInfo == nil {
				//新增
				objectMeta := metav1.ObjectMeta{
					Name:         mainId,
					GenerateName: mainId,
				}
				opTenantSpec := optenantv1alpha1.OpTenantSpec{TenantName: mainName, TenantAdmin: userName}
				opTenantInfo := &optenantv1alpha1.OpTenant{
					Spec:       opTenantSpec,
					ObjectMeta: objectMeta,
				}
				_, err = o.opTenantGroup.CreateOpTenant(opTenantInfo)
				if err != nil {
					klog.Error("=========创建租户信息异常======", err.Error())
					return nil, providerOptions.Name, err
				}
			} else {
				//更新
				objectMeta := metav1.ObjectMeta{
					Name:            mainId,
					ResourceVersion: opTenantInfo.ResourceVersion,
				}
				opTenantSpec := optenantv1alpha1.OpTenantSpec{TenantName: mainName, TenantAdmin: userName}
				opTenantInfo := &optenantv1alpha1.OpTenant{
					Spec:       opTenantSpec,
					ObjectMeta: objectMeta,
				}
				_, err = o.opTenantGroup.UpdateOpTenant(opTenantInfo)
				if err != nil {
					klog.Error("=========更新租户信息异常======", err.Error())
					return nil, providerOptions.Name, err
				}
			}
		}

	}

	klog.Error("===========>登录跳转成功结束<=========")

	if user != nil {
		return &authuser.DefaultInfo{Name: user.GetName()}, providerOptions.Name, nil
	}

	return nil, "", errors.NewNotFound(iamv1alpha2.Resource("user"), authenticated.GetUsername())
}

type UserCenterResp struct {
	Code    string             `json:"code"`
	Message string             `json:"msg"`
	Data    UserCenterRespData `json:"data"`
	Success bool               `json:"success"`
}

type UserCenterRespData struct {
	MainId      string `json:"mainId"`
	Sex         string `json:"sex"`
	AccountName string `json:"accountName"`
	UserName    string `json:"userName"`
	Cellphone   string `json:"cellphone"`
	IsAdmin     int8   `json:"isAdmin"`
	Status      string `json:"Status"`
	MainName    string `json:"mainName"`
	//onepower中的id
	OnepowerID string `json:"id"`
	//租户ID
	TenantId string `json:"tenantId"`
}
