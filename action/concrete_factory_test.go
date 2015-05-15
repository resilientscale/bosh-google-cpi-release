package action_test

import (
	boshlog "github.com/cloudfoundry/bosh-agent/logger"
	fakeuuid "github.com/cloudfoundry/bosh-agent/uuid/fakes"
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"

	. "github.com/frodenas/bosh-google-cpi/action"

	"github.com/frodenas/bosh-google-cpi/google/address_service"
	"github.com/frodenas/bosh-google-cpi/google/client"
	"github.com/frodenas/bosh-google-cpi/google/disk_service"
	"github.com/frodenas/bosh-google-cpi/google/disk_type_service"
	"github.com/frodenas/bosh-google-cpi/google/image_service"
	"github.com/frodenas/bosh-google-cpi/google/instance_service"
	"github.com/frodenas/bosh-google-cpi/google/machine_type_service"
	"github.com/frodenas/bosh-google-cpi/google/network_service"
	"github.com/frodenas/bosh-google-cpi/google/operation_service"
	"github.com/frodenas/bosh-google-cpi/google/snapshot_service"
	"github.com/frodenas/bosh-google-cpi/google/target_pool_service"

	"github.com/frodenas/bosh-registry/client"

	"google.golang.org/api/compute/v1"
	"google.golang.org/api/storage/v1"
)

var _ = Describe("ConcreteFactory", func() {
	var (
		project        string
		defaultZone    string
		uuidGen        *fakeuuid.FakeGenerator
		computeService *compute.Service
		storageService *storage.Service
		googleClient   gclient.GoogleClient
		logger         boshlog.Logger

		options = ConcreteFactoryOptions{
			Registry: registry.ClientOptions{
				Protocol: "http",
				Host:     "fake-host",
				Port:     5555,
				Username: "fake-username",
				Password: "fake-password",
			},
		}

		factory Factory
	)

	var (
		operationService goperation.GoogleOperationService
	)

	BeforeEach(func() {
		//googleClient = fakewrdnclient.New()
		uuidGen = &fakeuuid.FakeGenerator{}
		logger = boshlog.NewLogger(boshlog.LevelNone)

		factory = NewConcreteFactory(
			googleClient,
			uuidGen,
			options,
			logger,
		)
	})

	BeforeEach(func() {
		operationService = goperation.NewGoogleOperationService(
			project,
			computeService,
			logger,
		)
	})

	It("returns error if action cannot be created", func() {
		action, err := factory.Create("fake-unknown-action")
		Expect(err).To(HaveOccurred())
		Expect(action).To(BeNil())
	})

	It("create_disk", func() {
		diskService := disk.NewGoogleDiskService(
			project,
			computeService,
			operationService,
			uuidGen,
			logger,
		)

		diskTypeService := disktype.NewGoogleDiskTypeService(
			project,
			computeService,
			logger,
		)

		vmService := instance.NewGoogleInstanceService(
			project,
			computeService,
			operationService,
			uuidGen,
			logger,
		)

		action, err := factory.Create("create_disk")
		Expect(err).ToNot(HaveOccurred())
		Expect(action).To(Equal(NewCreateDisk(
			diskService,
			diskTypeService,
			vmService,
			defaultZone,
		)))
	})

	It("delete_disk", func() {
		diskService := disk.NewGoogleDiskService(
			project,
			computeService,
			operationService,
			uuidGen,
			logger,
		)

		action, err := factory.Create("delete_disk")
		Expect(err).ToNot(HaveOccurred())
		Expect(action).To(Equal(NewDeleteDisk(diskService)))
	})

	It("attach_disk", func() {
		diskService := disk.NewGoogleDiskService(
			project,
			computeService,
			operationService,
			uuidGen,
			logger,
		)

		vmService := instance.NewGoogleInstanceService(
			project,
			computeService,
			operationService,
			uuidGen,
			logger,
		)

		registryClient := registry.NewHTTPClient(
			options.Registry,
			logger,
		)

		action, err := factory.Create("attach_disk")
		Expect(err).ToNot(HaveOccurred())
		Expect(action).To(Equal(NewAttachDisk(diskService, vmService, registryClient)))
	})

	It("detach_disk", func() {
		vmService := instance.NewGoogleInstanceService(
			project,
			computeService,
			operationService,
			uuidGen,
			logger,
		)

		registryClient := registry.NewHTTPClient(
			options.Registry,
			logger,
		)

		action, err := factory.Create("detach_disk")
		Expect(err).ToNot(HaveOccurred())
		Expect(action).To(Equal(NewDetachDisk(vmService, registryClient)))
	})

	It("snapshot_disk", func() {
		snapshotService := snapshot.NewGoogleSnapshotService(
			project,
			computeService,
			operationService,
			uuidGen,
			logger,
		)

		diskService := disk.NewGoogleDiskService(
			project,
			computeService,
			operationService,
			uuidGen,
			logger,
		)

		action, err := factory.Create("snapshot_disk")
		Expect(err).ToNot(HaveOccurred())
		Expect(action).To(Equal(NewSnapshotDisk(snapshotService, diskService)))
	})

	It("delete_snapshot", func() {
		snapshotService := snapshot.NewGoogleSnapshotService(
			project,
			computeService,
			operationService,
			uuidGen,
			logger,
		)

		action, err := factory.Create("delete_snapshot")
		Expect(err).ToNot(HaveOccurred())
		Expect(action).To(Equal(NewDeleteSnapshot(snapshotService)))
	})

	It("create_stemcell", func() {
		stemcellService := image.NewGoogleImageService(
			project,
			computeService,
			storageService,
			operationService,
			uuidGen,
			logger,
		)

		action, err := factory.Create("create_stemcell")
		Expect(err).ToNot(HaveOccurred())
		Expect(action).To(Equal(NewCreateStemcell(stemcellService)))
	})

	It("delete_stemcell", func() {
		stemcellService := image.NewGoogleImageService(
			project,
			computeService,
			storageService,
			operationService,
			uuidGen,
			logger,
		)

		action, err := factory.Create("delete_stemcell")
		Expect(err).ToNot(HaveOccurred())
		Expect(action).To(Equal(NewDeleteStemcell(stemcellService)))
	})

	It("create_vm", func() {
		vmService := instance.NewGoogleInstanceService(
			project,
			computeService,
			operationService,
			uuidGen,
			logger,
		)

		addressService := address.NewGoogleAddressService(
			project,
			computeService,
			logger,
		)

		diskService := disk.NewGoogleDiskService(
			project,
			computeService,
			operationService,
			uuidGen,
			logger,
		)

		diskTypeService := disktype.NewGoogleDiskTypeService(
			project,
			computeService,
			logger,
		)

		machineTypeService := machinetype.NewGoogleMachineTypeService(
			project,
			computeService,
			logger,
		)

		networkService := network.NewGoogleNetworkService(
			project,
			computeService,
			logger,
		)

		stemcellService := image.NewGoogleImageService(
			project,
			computeService,
			storageService,
			operationService,
			uuidGen,
			logger,
		)

		targetPoolService := targetpool.NewGoogleTargetPoolService(
			project,
			computeService,
			operationService,
			logger,
		)

		registryClient := registry.NewHTTPClient(
			options.Registry,
			logger,
		)

		action, err := factory.Create("create_vm")
		Expect(err).ToNot(HaveOccurred())
		Expect(action).To(Equal(NewCreateVM(
			vmService,
			addressService,
			diskService,
			diskTypeService,
			machineTypeService,
			networkService,
			stemcellService,
			targetPoolService,
			registryClient,
			options.Registry,
			options.Agent,
			defaultZone,
		)))
	})

	It("configure_networks", func() {
		vmService := instance.NewGoogleInstanceService(
			project,
			computeService,
			operationService,
			uuidGen,
			logger,
		)

		addressService := address.NewGoogleAddressService(
			project,
			computeService,
			logger,
		)

		networkService := network.NewGoogleNetworkService(
			project,
			computeService,
			logger,
		)

		targetPoolService := targetpool.NewGoogleTargetPoolService(
			project,
			computeService,
			operationService,
			logger,
		)

		registryClient := registry.NewHTTPClient(
			options.Registry,
			logger,
		)

		action, err := factory.Create("configure_networks")
		Expect(err).ToNot(HaveOccurred())
		Expect(action).To(Equal(NewConfigureNetworks(
			vmService,
			addressService,
			networkService,
			targetPoolService,
			registryClient,
		)))
	})

	It("delete_vm", func() {
		vmService := instance.NewGoogleInstanceService(
			project,
			computeService,
			operationService,
			uuidGen,
			logger,
		)

		addressService := address.NewGoogleAddressService(
			project,
			computeService,
			logger,
		)

		networkService := network.NewGoogleNetworkService(
			project,
			computeService,
			logger,
		)

		targetPoolService := targetpool.NewGoogleTargetPoolService(
			project,
			computeService,
			operationService,
			logger,
		)

		registryClient := registry.NewHTTPClient(
			options.Registry,
			logger,
		)

		action, err := factory.Create("delete_vm")
		Expect(err).ToNot(HaveOccurred())
		Expect(action).To(Equal(NewDeleteVM(
			vmService,
			addressService,
			networkService,
			targetPoolService,
			registryClient,
		)))
	})

	It("reboot_vm", func() {
		vmService := instance.NewGoogleInstanceService(
			project,
			computeService,
			operationService,
			uuidGen,
			logger,
		)

		action, err := factory.Create("reboot_vm")
		Expect(err).ToNot(HaveOccurred())
		Expect(action).To(Equal(NewRebootVM(vmService)))
	})

	It("set_vm_metadata", func() {
		vmService := instance.NewGoogleInstanceService(
			project,
			computeService,
			operationService,
			uuidGen,
			logger,
		)

		action, err := factory.Create("set_vm_metadata")
		Expect(err).ToNot(HaveOccurred())
		Expect(action).To(Equal(NewSetVMMetadata(vmService)))
	})

	It("has_vm", func() {
		vmService := instance.NewGoogleInstanceService(
			project,
			computeService,
			operationService,
			uuidGen,
			logger,
		)

		action, err := factory.Create("has_vm")
		Expect(err).ToNot(HaveOccurred())
		Expect(action).To(Equal(NewHasVM(vmService)))
	})

	It("get_disks", func() {
		vmService := instance.NewGoogleInstanceService(
			project,
			computeService,
			operationService,
			uuidGen,
			logger,
		)

		action, err := factory.Create("get_disks")
		Expect(err).ToNot(HaveOccurred())
		Expect(action).To(Equal(NewGetDisks(vmService)))
	})

	It("ping", func() {
		action, err := factory.Create("ping")
		Expect(err).ToNot(HaveOccurred())
		Expect(action).To(Equal(NewPing()))
	})

	It("when action is current_vm_id returns an error because this CPI does not implement the method", func() {
		action, err := factory.Create("current_vm_id")
		Expect(err).To(HaveOccurred())
		Expect(action).To(BeNil())
	})

	It("when action is wrong returns an error because it is not an official CPI method", func() {
		action, err := factory.Create("wrong")
		Expect(err).To(HaveOccurred())
		Expect(action).To(BeNil())
	})
})
