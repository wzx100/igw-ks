package hellokubesphere

import (
	"github.com/emicklei/go-restful"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"kubesphere.io/kubesphere/pkg/api"
	"kubesphere.io/kubesphere/pkg/apiserver/runtime"
	"net/http"
)

const (
	GroupName = "example.kubesphere.io"
)

var GroupVersion = schema.GroupVersion{Group: GroupName, Version: "v1alpha1"}

func AddToContainer(container *restful.Container) error {
	webservice := runtime.NewWebService(GroupVersion)
	handler := newHandler()

	webservice.Route(webservice.GET("/hello-kubesphere").Reads("").To(handler.HelloKubeSphere).Returns(http.StatusOK, api.StatusOK, HelloResponse{})).
		Doc("Api for hello-kubesphere")

	container.Add(webservice)

	return nil
}
