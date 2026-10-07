package hcore

import (
	"context"

	"github.com/ne-tort/pathology-core/v2/hcommon"
	"github.com/ne-tort/pathology-core/v2/service_manager"
)

var (
	sWorkingPath          string
	sTempPath             string
	sUserID               int
	sGroupID              int
	statusPropagationPort int64
)

func InitPathologyService() error {
	return service_manager.StartServices()
}

func (s *CoreService) Setup(ctx context.Context, req *SetupRequest) (*hcommon.Response, error) {
	if hasGrpcServer(req.Mode) {
		return &hcommon.Response{Code: hcommon.ResponseCode_OK, Message: ""}, nil
	}
	err := Setup(req, nil)
	code := hcommon.ResponseCode_OK
	message := ""
	if err != nil {
		code = hcommon.ResponseCode_FAILED
		message = err.Error()
	}
	return &hcommon.Response{Code: code, Message: message}, err
}
