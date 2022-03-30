package hellokubesphere

import "github.com/emicklei/go-restful"

type handler struct{}

func newHandler() handler {
	return handler{}
}

func (h handler) HelloKubeSphere(req *restful.Request, resp *restful.Response) {
	resp.WriteAsJson(HelloResponse{
		Message: "hello kubesphere",
	})
}

type HelloResponse struct {
	Message string `json:"message"`
}
