package action

import (
	bosherr "github.com/cloudfoundry/bosh-agent/errors"

	"github.com/frodenas/bosh-google-cpi/api"
	"github.com/frodenas/bosh-google-cpi/google/instance_service"
)

type SetVMMetadata struct {
	vmService instance.Service
}

func NewSetVMMetadata(
	vmService instance.Service,
) SetVMMetadata {
	return SetVMMetadata{
		vmService: vmService,
	}
}

func (svm SetVMMetadata) Run(vmCID VMCID, vmMetadata VMMetadata) (interface{}, error) {
	err := svm.vmService.SetMetadata(string(vmCID), instance.Metadata(vmMetadata))
	if err != nil {
		if _, ok := err.(api.CloudError); ok {
			return nil, err
		}
		return nil, bosherr.WrapErrorf(err, "Setting metadata for vm '%s'", vmCID)
	}

	return nil, nil
}
