package action

import (
	bosherr "github.com/cloudfoundry/bosh-agent/errors"

	"github.com/frodenas/bosh-google-cpi/api"
	"github.com/frodenas/bosh-google-cpi/google/address_service"
	"github.com/frodenas/bosh-google-cpi/google/instance_service"
	"github.com/frodenas/bosh-google-cpi/google/network_service"
	"github.com/frodenas/bosh-google-cpi/google/target_pool_service"

	"github.com/frodenas/bosh-registry/client"
)

type DeleteVM struct {
	vmService         instance.Service
	addressService    address.Service
	networkService    network.Service
	targetPoolService targetpool.Service
	registryClient    registry.Client
}

func NewDeleteVM(
	vmService instance.Service,
	addressService address.Service,
	networkService network.Service,
	targetPoolService targetpool.Service,
	registryClient registry.Client,
) DeleteVM {
	return DeleteVM{
		vmService:         vmService,
		addressService:    addressService,
		networkService:    networkService,
		targetPoolService: targetPoolService,
		registryClient:    registryClient,
	}
}

func (dv DeleteVM) Run(vmCID VMCID) (interface{}, error) {
	// Delete VM networks
	var networks Networks
	vmNetworks := networks.AsInstanceServiceNetworks()
	instanceNetworks := instance.NewGoogleInstanceNetworks(vmNetworks, dv.addressService, dv.networkService, dv.targetPoolService)

	err := dv.vmService.DeleteNetworkConfiguration(string(vmCID), instanceNetworks)
	if err != nil {
		if _, ok := err.(api.CloudError); ok {
			return nil, err
		}
		return nil, bosherr.WrapErrorf(err, "Deleting vm '%s'", vmCID)
	}

	// Delete the VM
	err = dv.vmService.Delete(string(vmCID))
	if err != nil {
		if _, ok := err.(api.CloudError); ok {
			return nil, err
		}
		return nil, bosherr.WrapErrorf(err, "Deleting vm '%s'", vmCID)
	}

	// Delete the VM agent settings
	err = dv.registryClient.Delete(string(vmCID))
	if err != nil {
		return nil, bosherr.WrapErrorf(err, "Deleting vm '%s'", vmCID)
	}

	return nil, nil
}
