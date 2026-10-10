package cli

import (
	"fmt"
	"strings"
	"time"
)

type Config struct {
	Profile                       string
	Provider                      string
	providerSelectionSource       providerSelectionSource
	externalDesktopCredentialName string
	externalDesktopCredential     transientSecret
	externalDesktopEnvDenylist    []string
	providerExplicit              bool
	providerDefaultsApplied       string
	TargetOS                      string
	targetExplicit                bool
	targetFlagExplicit            bool
	inferredTargetProvider        string
	Architecture                  string
	architectureExplicit          bool
	OSImage                       string
	osImageExplicit               bool
	osImageProviderDefaults       string
	WindowsMode                   string
	explicitWindowsMode           string
	windowsModeFlagExplicit       bool
	Desktop                       bool
	DesktopEnv                    string
	Browser                       bool
	imageRequirements             imageRequirements
	Code                          bool
	Network                       NetworkMode
	Class                         string
	classFlagExplicit             bool
	classExplicitOrder            uint64
	explicitSelectionOrder        uint64
	Pond                          string
	ExposedPorts                  []string
	ServerType                    string
	ServerTypeExplicit            bool
	Coordinator                   string
	BrokerMode                    BrokerMode
	brokerProvider                string
	BrokerLoginRedirectOrigins    []string
	BrokerAutoWebVNC              bool
	macOSPortalAuto               bool
	macOSPortalCoordinator        string
	CoordToken                    string
	CoordTokenCommand             []string
	CoordAdminToken               string
	credentialProvenance          credentialDestinationProvenance
	HostID                        string
	Access                        AccessConfig
	Location                      string
	locationExplicit              bool
	Image                         string
	imageExplicit                 bool
	AWSRegion                     string
	AWSAMI                        string
	AWSSnapshot                   string
	AWSSGID                       string
	AWSSubnetID                   string
	AWSProfile                    string
	AWSRootGB                     int32
	AWSSSHCIDRs                   []string
	AWSSSHCIDRsPinned             bool
	AWSMacHostID                  string
	AWSLambdaMicroVM              AWSLambdaMicroVMConfig
	AzureSubscription             string
	AzureTenant                   string
	AzureClientID                 string
	AzureLocation                 string
	AzureBackend                  string
	AzureResourceGroup            string
	AzureImage                    string
	azureImageExplicit            bool
	AzureSnapshot                 string
	AzureSnapshotSKU              string
	AzureOSDisk                   string
	AzureOSDiskExplicit           bool
	AzureOSDiskSKU                string
	AzureVNet                     string
	AzureSubnet                   string
	AzureNSG                      string
	AzureSSHCIDRs                 []string
	AzureNetwork                  string
	AzureDynamicSessions          AzureDynamicSessionsConfig
	GCPProject                    string
	gcpProjectExplicit            bool
	GCPZone                       string
	gcpZoneExplicit               bool
	GCPImage                      string
	gcpImageExplicit              bool
	GCPMachineImage               string
	GCPSnapshot                   string
	GCPNetwork                    string
	gcpNetworkExplicit            bool
	GCPSubnet                     string
	GCPTags                       []string
	gcpTagsExplicit               bool
	GCPSSHCIDRs                   []string
	GCPRootGB                     int64
	gcpRootGBExplicit             bool
	GCPServiceAccount             string
	DigitalOcean                  DigitalOceanConfig
	digitalOceanImageExplicit     bool
	Vultr                         VultrConfig
	Linode                        LinodeConfig
	linodeImageExplicit           bool
	linodeTypeExplicit            bool
	GitHubCodespaces              GitHubCodespacesConfig
	githubCodespacesRetentionSet  bool
	Lambda                        LambdaConfig
	lambdaImageExplicit           bool
	lambdaImageFamilyExplicit     bool
	lambdaTypeExplicit            bool
	Nebius                        NebiusConfig
	OVH                           OVHConfig
	ovhImageExplicit              bool
	Scaleway                      ScalewayConfig
	scalewayRegionExplicit        bool
	scalewayZoneExplicit          bool
	scalewayImageExplicit         bool
	scalewayTypeExplicit          bool
	TencentCloud                  TencentCloudConfig
	tencentCloudRegionExplicit    bool
	tencentCloudZoneExplicit      bool
	tencentCloudImageExplicit     bool
	tencentCloudTypeExplicit      bool
	Incus                         IncusConfig
	Proxmox                       ProxmoxConfig
	Firecracker                   FirecrackerConfig
	XCPNg                         XCPNgConfig
	Parallels                     ParallelsConfig
	parallelsTemplateApplied      bool
	SSHUser                       string
	explicitSSHUser               string
	SSHKey                        string
	explicitSSHKey                string
	SSHPort                       string
	explicitSSHPort               string
	SSHFallbackPorts              []string
	sshFallbackPortsExplicit      bool
	explicitSSHFallbackPorts      []string
	ProviderKey                   string
	WorkRoot                      string
	explicitWorkRoot              string
	TTL                           time.Duration
	IdleTimeout                   time.Duration
	Sync                          SyncConfig
	Run                           RunConfig
	EnvAllow                      []string
	envAllowOverriddenByEnv       bool
	Capacity                      CapacityConfig
	capacityMarketExplicit        bool
	Actions                       ActionsConfig
	Blacksmith                    BlacksmithConfig
	KubeVirt                      KubeVirtConfig
	SealosDevbox                  SealosDevboxConfig
	sealosDevboxWorkRootExplicit  bool
	AgentSandbox                  AgentSandboxConfig
	deleteOnReleaseExplicit       map[string]bool
	External                      ExternalConfig
	Namespace                     NamespaceConfig
	NamespaceInstance             NamespaceInstanceConfig
	Phala                         PhalaConfig
	phalaTypeExplicitOrder        uint64
	Boxd                          BoxdConfig
	boxdWorkRootExplicit          bool
	Coder                         CoderConfig
	Morph                         MorphConfig
	Daytona                       DaytonaConfig
	E2B                           E2BConfig
	CubeSandbox                   CubeSandboxConfig
	ExeDev                        ExeDevConfig
	Railway                       RailwayConfig
	FastAPICloud                  FastAPICloudConfig
	UnikraftCloud                 UnikraftCloudConfig
	Runpod                        RunpodConfig
	Vast                          VastConfig
	vastWorkRootExplicit          bool
	NvidiaBrev                    NvidiaBrevConfig
	nvidiaBrevWorkRootExplicit    bool
	Hostinger                     HostingerConfig
	hostingerUserExplicit         bool
	hostingerWorkRootExplicit     bool
	Wandb                         WandbConfig
	Orgo                          OrgoConfig
	Islo                          IsloConfig
	isloImageExplicit             bool
	isloVCPUsExplicit             bool
	isloMemoryMBExplicit          bool
	isloDiskGBExplicit            bool
	Freestyle                     FreestyleConfig
	Tenki                         TenkiConfig
	Tensorlake                    TensorlakeConfig
	Cua                           CuaConfig
	OpenComputer                  OpenComputerConfig
	CodeSandbox                   CodeSandboxConfig
	OpenSandbox                   OpenSandboxConfig
	Nomad                         NomadConfig
	Blaxel                        BlaxelConfig
	VercelSandbox                 VercelSandboxConfig
	CloudflareSandbox             CloudflareSandboxConfig
	Superserve                    SuperserveConfig
	Crownest                      CrownestConfig
	DockerSandbox                 DockerSandboxConfig
	AnthropicSRT                  AnthropicSRTConfig
	CloudRunSandbox               CloudRunSandboxConfig
	Modal                         ModalConfig
	UpstashBox                    UpstashBoxConfig
	Smolvm                        SmolvmConfig
	AsciiBox                      AsciiBoxConfig
	Cloudflare                    CloudflareConfig
	CloudflareDynamicWorkers      CloudflareDynamicWorkersConfig
	Semaphore                     SemaphoreConfig
	Sprites                       SpritesConfig
	LocalContainer                LocalContainerConfig
	localContainerRuntimeExplicit bool
	localContainerImageExplicit   bool
	localContainerRootExplicit    bool
	AppleContainer                AppleContainerConfig
	appleContainerImageExplicit   bool
	AppleVM                       AppleVMConfig
	appleVMImageExplicit          bool
	appleVMImageSHA256Explicit    bool
	appleVMCPUsExplicit           bool
	appleVMMemoryExplicit         bool
	appleVMDiskExplicit           bool
	MXC                           MXCConfig
	Multipass                     MultipassConfig
	multipassImageExplicit        bool
	Machine0                      Machine0Config
	Tart                          TartConfig
	tartImageExplicit             bool
	tartDiskExplicit              bool
	tartCPUsExplicit              bool
	tartMemoryExplicit            bool
	Lume                          LumeConfig
	HyperV                        HyperVConfig
	WindowsSandbox                WindowsSandboxConfig
	Tailscale                     TailscaleConfig
	Static                        StaticConfig
	Results                       ResultsConfig
	Shard                         ShardConfig
	Cache                         CacheConfig
	Profiles                      map[string]ProfileConfig
	Presets                       map[string]PresetConfig
	ProofTemplates                map[string]ProofTemplateConfig
	Jobs                          map[string]JobConfig
}

type SyncConfig struct {
	Excludes    []string
	Includes    []string
	Delete      bool
	Checksum    bool
	GitSeed     bool
	GitOverlay  bool
	Fingerprint bool
	BaseRef     string
	Timeout     time.Duration
	WarnFiles   int
	WarnBytes   int64
	FailFiles   int
	FailBytes   int64
	AllowLarge  bool
}

type RunConfig struct {
	PreflightTools []string
}

type CapacityConfig struct {
	Market            string
	Strategy          string
	Fallback          string
	Regions           []string
	AvailabilityZones []string
	Hints             bool
}

type AWSLambdaMicroVMConfig struct {
	Image             string
	ImageVersion      string
	ExecutionRoleARN  string
	Workdir           string
	IngressConnectors []string
	EgressConnectors  []string
	ForgetMissing     bool
}

type DigitalOceanConfig struct {
	Region   string
	Image    string
	VPCUUID  string
	SSHCIDRs []string
}

type VultrConfig struct {
	Region        string
	OS            string
	Image         string
	Snapshot      string
	FirewallGroup string
	VPCIDs        []string
	SSHCIDRs      []string
	UserScheme    string
}

type LinodeConfig struct {
	Region     string
	Image      string
	Type       string
	FirewallID string
	SSHCIDRs   []string
}

// GitHubCodespacesConfig is intentionally token-free. Authentication comes
// from the GitHub CLI credential store or GitHub's standard environment
// variables at the point of use, never from Crabbox config or argv.

// GitHubCodespacesConfig is intentionally token-free. Authentication comes
// from the GitHub CLI credential store or GitHub's standard environment
// variables at the point of use, never from Crabbox config or argv.
type GitHubCodespacesConfig struct {
	APIURL           string
	GHPath           string
	Repo             string
	Ref              string
	Machine          string
	DevcontainerPath string
	WorkingDirectory string
	Geo              string
	IdleTimeout      time.Duration
	RetentionPeriod  time.Duration
	DeleteOnRelease  bool
	WorkRoot         string
}

type LambdaConfig struct {
	Region           string
	Type             string
	Image            string
	ImageFamily      string
	FirewallRuleset  string
	SSHCIDRs         []string
	FilesystemNames  []string
	FilesystemMounts []LambdaFilesystemMount
}

type LambdaFilesystemMount struct {
	Name      string `yaml:"name,omitempty" json:"name,omitempty"`
	MountPath string `yaml:"mountPath,omitempty" json:"mountPath,omitempty"`
}

// NebiusConfig is intentionally non-secret. Authentication stays in the
// Nebius CLI profile store and is never accepted as Crabbox config or argv.

// NebiusConfig is intentionally non-secret. Authentication stays in the
// Nebius CLI profile store and is never accepted as Crabbox config or argv.
type NebiusConfig struct {
	CLI              string
	Profile          string
	ParentID         string
	SubnetID         string
	Platform         string
	Preset           string
	ImageFamily      string
	DiskType         string
	DiskSizeGiB      int
	User             string
	PublicIP         string
	SecurityGroupIDs []string
	ServiceAccountID string
	RecoveryPolicy   string
}

// OVHConfig contains non-secret OVHcloud Public Cloud settings. OVH
// application credentials are intentionally read from environment variables by
// the provider client and are not persisted in Crabbox config.

// OVHConfig contains non-secret OVHcloud Public Cloud settings. OVH
// application credentials are intentionally read from environment variables by
// the provider client and are not persisted in Crabbox config.
type OVHConfig struct {
	Endpoint  string
	ProjectID string
	Region    string
	Image     string
	Flavor    string
}

// ScalewayConfig contains non-secret Scaleway Instances settings. Scaleway
// credentials are intentionally loaded by the provider client from the official
// SDK environment/config surfaces and are not persisted in Crabbox config.

// ScalewayConfig contains non-secret Scaleway Instances settings. Scaleway
// credentials are intentionally loaded by the provider client from the official
// SDK environment/config surfaces and are not persisted in Crabbox config.
type ScalewayConfig struct {
	Region         string
	Zone           string
	Image          string
	Type           string
	ProjectID      string
	OrganizationID string
	SecurityGroup  string
	SSHCIDRs       []string
}

// TencentCloudConfig contains non-secret Tencent Cloud CVM settings. Tencent
// Cloud API credentials are intentionally read from TENCENTCLOUD_SECRET_ID and
// TENCENTCLOUD_SECRET_KEY by the provider client and are not persisted in
// Crabbox config.

// TencentCloudConfig contains non-secret Tencent Cloud CVM settings. Tencent
// Cloud API credentials are intentionally read from TENCENTCLOUD_SECRET_ID and
// TENCENTCLOUD_SECRET_KEY by the provider client and are not persisted in
// Crabbox config.
type TencentCloudConfig struct {
	Region                  string
	Zone                    string
	Image                   string
	Type                    string
	VPCID                   string
	SubnetID                string
	SecurityGroupID         string
	SSHCIDRs                []string
	RootGB                  int64
	InternetChargeType      string
	InternetMaxBandwidthOut int64
	APIEndpoint             string
}

type ActionsConfig struct {
	Repo          string
	Workflow      string
	Job           string
	Ref           string
	Fields        []string
	RunnerLabels  []string
	RunnerVersion string
	Ephemeral     bool
}

type BlacksmithConfig struct {
	Org         string
	Workflow    string
	Job         string
	Ref         string
	IdleTimeout time.Duration
	Debug       bool
}

type KubeVirtConfig struct {
	Kubectl         string
	Virtctl         string
	Kubeconfig      string
	Context         string
	Namespace       string
	Template        string
	SSHUser         string
	SSHKey          string
	SSHPublicKey    string
	SSHPort         string
	WorkRoot        string
	DeleteOnRelease bool
}

type SealosDevboxConfig struct {
	Kubectl         string
	Kubeconfig      string
	Context         string
	Namespace       string
	Image           string
	TemplateID      string
	CPU             string
	Memory          string
	StorageLimit    string
	Network         string
	SSHGatewayHost  string
	SSHGatewayPort  string
	SSHUser         string
	WorkRoot        string
	NodeHost        string
	DeleteOnRelease bool
}

type AgentSandboxConfig struct {
	Kubectl             string
	Kubeconfig          string
	Context             string
	Namespace           string
	WarmPool            string
	Container           string
	Workdir             string
	SandboxReadyTimeout time.Duration
	PodReadyTimeout     time.Duration
	ExecTimeoutSecs     int
	DeleteOnRelease     bool
	ForgetMissing       bool
}

type ExternalConfig struct {
	Command                  string
	Args                     []string
	Config                   map[string]any
	Capabilities             ExternalCapabilitiesConfig
	Lifecycle                ExternalLifecycleConfig
	Connection               ExternalConnectionConfig
	WorkRoot                 string
	RoutingFile              string
	routingLoaded            bool
	routingCredentialVersion int
	routingDigest            string
	routingGeneration        string
	routingTargetOS          string
	routingWindowsMode       string
	routingArchitecture      string
}

type ExternalCapabilitiesConfig struct {
	IdempotentLeaseID bool `yaml:"idempotentLeaseId,omitempty" json:"idempotentLeaseId,omitempty"`
}

type ExternalLifecycleConfig struct {
	Doctor  ExternalLifecycleOperation `yaml:"doctor,omitempty" json:"doctor,omitempty"`
	Acquire ExternalLifecycleOperation `yaml:"acquire,omitempty" json:"acquire,omitempty"`
	Resolve ExternalLifecycleOperation `yaml:"resolve,omitempty" json:"resolve,omitempty"`
	List    ExternalLifecycleOperation `yaml:"list,omitempty" json:"list,omitempty"`
	Release ExternalLifecycleOperation `yaml:"release,omitempty" json:"release,omitempty"`
	Touch   ExternalLifecycleOperation `yaml:"touch,omitempty" json:"touch,omitempty"`
	Cleanup ExternalLifecycleOperation `yaml:"cleanup,omitempty" json:"cleanup,omitempty"`
}

type ExternalLifecycleOperation struct {
	Argv              []string          `yaml:"argv,omitempty" json:"argv,omitempty"`
	Steps             [][]string        `yaml:"steps,omitempty" json:"steps,omitempty"`
	Env               map[string]string `yaml:"env,omitempty" json:"env,omitempty"`
	AllowEnvArgv      bool              `yaml:"allowEnvArgv,omitempty" json:"allowEnvArgv,omitempty"`
	AllowConfigArgv   bool              `yaml:"allowConfigArgv,omitempty" json:"allowConfigArgv,omitempty"`
	Output            string            `yaml:"output,omitempty" json:"output,omitempty"`
	NamePrefix        string            `yaml:"namePrefix,omitempty" json:"namePrefix,omitempty"`
	RollbackOnFailure bool              `yaml:"rollbackOnFailure,omitempty" json:"rollbackOnFailure,omitempty"`
}

type ExternalConnectionConfig struct {
	ResourceName         string                      `yaml:"resourceName,omitempty" json:"resourceName,omitempty"`
	AllowEnvResourceName bool                        `yaml:"allowEnvResourceName,omitempty" json:"allowEnvResourceName,omitempty"`
	CloudID              string                      `yaml:"cloudId,omitempty" json:"cloudId,omitempty"`
	ServerType           string                      `yaml:"serverType,omitempty" json:"serverType,omitempty"`
	Labels               map[string]string           `yaml:"labels,omitempty" json:"labels,omitempty"`
	SSH                  ExternalSSHConnectionConfig `yaml:"ssh,omitempty" json:"ssh,omitempty"`
	Desktop              ExternalDesktopConfig       `yaml:"desktop,omitempty" json:"desktop,omitzero"`
}

type ExternalSSHConnectionConfig struct {
	User                string   `yaml:"user,omitempty" json:"user,omitempty"`
	Host                string   `yaml:"host,omitempty" json:"host,omitempty"`
	Key                 string   `yaml:"key,omitempty" json:"key,omitempty"`
	Port                string   `yaml:"port,omitempty" json:"port,omitempty"`
	FallbackPorts       []string `yaml:"fallbackPorts,omitempty" json:"fallbackPorts,omitempty"`
	ReadyCheck          string   `yaml:"readyCheck,omitempty" json:"readyCheck,omitempty"`
	AuthSecret          bool     `yaml:"authSecret,omitempty" json:"authSecret,omitempty"`
	NoControlMaster     bool     `yaml:"noControlMaster,omitempty" json:"noControlMaster,omitempty"`
	SSHConfigProxy      bool     `yaml:"sshConfigProxy,omitempty" json:"sshConfigProxy,omitempty"`
	ProxyCommand        string   `yaml:"proxyCommand,omitempty" json:"proxyCommand,omitempty"`
	AllowEnv            bool     `yaml:"allowEnv,omitempty" json:"allowEnv,omitempty"`
	TrustProviderOutput bool     `yaml:"trustProviderOutput,omitempty" json:"trustProviderOutput,omitempty"`
}

type ExternalDesktopConfig struct {
	Username    string `yaml:"username,omitempty" json:"username,omitempty"`
	PasswordEnv string `yaml:"passwordEnv,omitempty" json:"passwordEnv,omitempty"`
}

type NamespaceConfig struct {
	Image               string
	Size                string
	Repository          string
	Site                string
	VolumeSizeGB        int
	AutoStopIdleTimeout time.Duration
	WorkRoot            string
	DeleteOnRelease     bool
}

type NamespaceInstanceConfig struct {
	CLIPath     string
	MachineType string
	Duration    time.Duration
	Region      string
	Endpoint    string
	Keychain    string
	TenantID    string
	Volumes     []string
	WorkRoot    string
	Bare        bool
}

// PhalaConfig configures the Phala Cloud confidential TDX CVM provider. Phala
// authenticates through its own stored credentials (device flow or
// PHALA_CLOUD_API_KEY), so no API key is held here.

// PhalaConfig configures the Phala Cloud confidential TDX CVM provider. Phala
// authenticates through its own stored credentials (device flow or
// PHALA_CLOUD_API_KEY), so no API key is held here.
type PhalaConfig struct {
	CLIPath      string
	InstanceType string
	WorkRoot     string
	NodeID       string
	Compose      string
	// Attest gates the TDX remote-attestation check the Phala backend runs after
	// a leased CVM becomes reachable. nil means "default" (attestation ON); the
	// backend treats nil as true. A non-nil false value (set only by the local
	// --phala-skip-attestation flag or CRABBOX_PHALA_ATTEST=false env) opts out.
	Attest *bool
}

type CoderConfig struct {
	CLIPath              string
	Template             string
	Preset               string
	WorkspacePrefix      string
	WorkRoot             string
	DeleteOnRelease      bool
	Wait                 string
	UseParameterDefaults bool
	Parameters           []string
	RichParameterFile    string
}

type MorphConfig struct {
	APIKey          string
	APIURL          string
	Snapshot        string
	SSHGatewayHost  string
	WorkRoot        string
	DeleteOnRelease bool
	WakeOnSSH       bool
}

type DaytonaConfig struct {
	APIKey           string
	JWTToken         string
	OrganizationID   string
	APIURL           string
	Snapshot         string
	Target           string
	User             string
	WorkRoot         string
	SSHGatewayHost   string
	SSHAccessMinutes int
}

type E2BConfig struct {
	APIKey   string
	APIURL   string
	Domain   string
	Template string
	Workdir  string
	User     string
}

type CubeSandboxConfig struct {
	APIKey        string
	APIURL        string
	Domain        string
	Template      string
	Workdir       string
	User          string
	ProxyNodeIP   string
	ProxyPortHTTP int
	ProxyScheme   string
}

type AzureDynamicSessionsConfig struct {
	Endpoint    string
	Pool        string
	APIVersion  string
	Workdir     string
	TimeoutSecs int
}

const (
	AzureBackendVM              = "vm"
	AzureBackendDynamicSessions = "dynamic-sessions"
)

func NormalizeAzureBackend(backend string) (string, error) {
	switch strings.ToLower(strings.TrimSpace(backend)) {
	case "", "vm", "vms", "virtual-machine", "virtual-machines":
		return AzureBackendVM, nil
	case "dynamic-sessions", "dynamic-session", "sessions", "azds":
		return AzureBackendDynamicSessions, nil
	default:
		return "", fmt.Errorf("azure backend must be vm or dynamic-sessions")
	}
}

type ExeDevConfig struct {
	ControlHost string
	Image       string
	CPUs        int
	Memory      string
	Disk        string
	Command     string
	User        string
	WorkRoot    string
	NoEmail     bool
}

type RailwayConfig struct {
	APIToken      string
	APIURL        string
	ProjectID     string
	EnvironmentID string
}

type FastAPICloudConfig struct {
	Token  string
	APIURL string
	AppID  string
	TeamID string
}

type UnikraftCloudConfig struct {
	APIKey   string
	APIURL   string
	Metro    string
	Image    string
	MemoryMB int
}

type RunpodConfig struct {
	APIKey     string
	APIURL     string
	CloudType  string
	InstanceID string
	Image      string
	TemplateID string
	DiskGB     int
	User       string
	WorkRoot   string
}

// VastConfig contains Vast.ai provider settings. APIKey is populated only from
// CRABBOX_VAST_API_KEY / VAST_API_KEY and must not be persisted or printed.

// VastConfig contains Vast.ai provider settings. APIKey is populated only from
// CRABBOX_VAST_API_KEY / VAST_API_KEY and must not be persisted or printed.
type VastConfig struct {
	APIKey         string
	APIURL         string
	InstanceType   string
	GPUName        string
	GPUCount       int
	Image          string
	TemplateID     string
	Runtype        string
	DiskGB         int
	MaxDphTotal    float64
	MinReliability float64
	Order          string
	User           string
	WorkRoot       string
	ReleaseAction  string
}

// NvidiaBrevConfig is intentionally non-secret. Authentication stays in the
// NVIDIA Brev CLI's own credential store and is never accepted as Crabbox
// config or argv.

// NvidiaBrevConfig is intentionally non-secret. Authentication stays in the
// NVIDIA Brev CLI's own credential store and is never accepted as Crabbox
// config or argv.
type NvidiaBrevConfig struct {
	CLI           string
	Org           string
	Type          string
	GPUName       string
	Provider      string
	Mode          string
	Launchable    string
	StartupScript string
	ReleaseAction string
	Target        string
	User          string
	WorkRoot      string
}

type HostingerConfig struct {
	APIToken        string
	APIURL          string
	ItemID          string
	PaymentMethodID string
	TemplateID      string
	DataCenterID    string
	HostnamePrefix  string
	User            string
	WorkRoot        string
	AllowPurchase   bool
	ReleaseAction   string
}

// WandbConfig drives the W&B Sandboxes (CoreWeave Sandboxes) provider. The
// API key is the same one `wandb login` writes to ~/.netrc — the value
// proposition of this provider is that AI researchers already have it.

// WandbConfig drives the W&B Sandboxes (CoreWeave Sandboxes) provider. The
// API key is the same one `wandb login` writes to ~/.netrc — the value
// proposition of this provider is that AI researchers already have it.
type WandbConfig struct {
	APIKey             string
	DefaultImage       string
	MaxLifetimeSeconds int
}

// OrgoConfig drives the Orgo delegated-run provider. The API key is resolved
// from env/config only; it must not be passed on the command line.

// OrgoConfig drives the Orgo delegated-run provider. The API key is resolved
// from env/config only; it must not be passed on the command line.
type OrgoConfig struct {
	APIKey      string
	APIBase     string
	WorkspaceID string
	RAMGB       int
	CPUs        int
	DiskGB      int
	Resolution  string
}

type IsloConfig struct {
	APIKey         string
	BaseURL        string
	Image          string
	Workdir        string
	GatewayProfile string
	SnapshotName   string
	VCPUs          int
	MemoryMB       int
	DiskGB         int
}

type FreestyleConfig struct {
	APIKey   string
	APIURL   string
	Workdir  string
	VCPUs    int
	MemoryGB int
}

type TenkiConfig struct {
	CLIPath   string
	Endpoint  string
	Gateway   string
	Workspace string
	Project   string
	Image     string
	Snapshot  string
	WorkRoot  string
	CPUs      int
	MemoryMB  int
	DiskGB    int
}

type TensorlakeConfig struct {
	APIKey         string
	APIURL         string
	CLIPath        string
	Image          string
	Snapshot       string
	OrganizationID string
	ProjectID      string
	Namespace      string
	Workdir        string
	CPUs           float64
	MemoryMB       int
	DiskMB         int
	TimeoutSecs    int
	NoInternet     bool
}

// CuaConfig configures the read-only CUA diagnostics provider. API keys are intentionally
// absent: later bridge code resolves CUA_API_KEY / credential-store auth at
// runtime and must pass credentials only through environment or SDK stores.
// APIURL is trusted local input only and is never loaded from repository YAML.

// CuaConfig configures the read-only CUA diagnostics provider. API keys are intentionally
// absent: later bridge code resolves CUA_API_KEY / credential-store auth at
// runtime and must pass credentials only through environment or SDK stores.
// APIURL is trusted local input only and is never loaded from repository YAML.
type CuaConfig struct {
	APIURL             string
	Image              string
	Kind               string
	Region             string
	Workdir            string
	VCPUs              int
	MemoryMB           int
	DiskGB             int
	StartupTimeoutSecs int
	ExecTimeoutSecs    int
	BridgeCommand      string
	SDKPackage         string
	SDKImport          string
	SDKFallbackImport  string
}

// OpenComputerConfig configures the delegated OpenComputer provider, which
// talks to the OpenComputer REST API. The API key is intentionally absent: it
// is read at runtime from CRABBOX_OPENCOMPUTER_API_KEY / OPENCOMPUTER_API_KEY
// or the `oc` CLI config (`oc config set api-key`), and sent only in the
// X-API-Key header — never persisted in Crabbox config or placed on argv.

// OpenComputerConfig configures the delegated OpenComputer provider, which
// talks to the OpenComputer REST API. The API key is intentionally absent: it
// is read at runtime from CRABBOX_OPENCOMPUTER_API_KEY / OPENCOMPUTER_API_KEY
// or the `oc` CLI config (`oc config set api-key`), and sent only in the
// X-API-Key header — never persisted in Crabbox config or placed on argv.
type OpenComputerConfig struct {
	APIURL          string
	Workdir         string
	CPU             int
	MemoryMB        int
	TimeoutSecs     int
	ExecTimeoutSecs int
	Burst           bool
	ForgetMissing   bool
}

// CodeSandboxConfig configures the delegated CodeSandbox provider. The API key
// is intentionally absent: it is read at runtime from
// CRABBOX_CODESANDBOX_API_KEY / CSB_API_KEY and passed to the SDK bridge through
// environment only, never persisted in Crabbox config or placed on argv.

// CodeSandboxConfig configures the delegated CodeSandbox provider. The API key
// is intentionally absent: it is read at runtime from
// CRABBOX_CODESANDBOX_API_KEY / CSB_API_KEY and passed to the SDK bridge through
// environment only, never persisted in Crabbox config or placed on argv.
type CodeSandboxConfig struct {
	TemplateID               string
	Workdir                  string
	VMTier                   string
	Privacy                  string
	HibernationTimeoutSecs   int
	AutomaticWakeupHTTP      bool
	AutomaticWakeupWebSocket bool
	BridgeCommand            string
	SDKPackage               string
	DoctorListLimit          int
	OperationTimeoutSecs     int
}

// OpenSandboxConfig configures the delegated OpenSandbox provider. The API key
// is intentionally absent: it is read at runtime from
// CRABBOX_OPENSANDBOX_API_KEY / OPEN_SANDBOX_API_KEY and sent only in request
// headers, never persisted in Crabbox config or placed on argv.

// OpenSandboxConfig configures the delegated OpenSandbox provider. The API key
// is intentionally absent: it is read at runtime from
// CRABBOX_OPENSANDBOX_API_KEY / OPEN_SANDBOX_API_KEY and sent only in request
// headers, never persisted in Crabbox config or placed on argv.
type OpenSandboxConfig struct {
	APIURL          string
	Image           string
	Workdir         string
	CPU             string
	Memory          string
	TimeoutSecs     int
	ExecTimeoutSecs int
	PlatformOS      string
	PlatformArch    string
	SecureAccess    bool
	UseServerProxy  bool
	ForgetMissing   bool
}

// NomadConfig configures the delegated Nomad provider. The ACL token is
// intentionally absent: it is read at runtime from NOMAD_TOKEN or TokenEnv and
// is never persisted in Crabbox config or placed on argv.

// NomadConfig configures the delegated Nomad provider. The ACL token is
// intentionally absent: it is read at runtime from NOMAD_TOKEN or TokenEnv and
// is never persisted in Crabbox config or placed on argv.
type NomadConfig struct {
	Address           string
	Region            string
	Namespace         string
	TokenEnv          string
	CACert            string
	CAPath            string
	ClientCert        string
	ClientKey         string
	TLSServerName     string
	SkipVerify        bool
	Task              string
	Driver            string
	Image             string
	Workdir           string
	JobSpecTemplate   string
	NodePool          string
	Datacenters       []string
	CPU               int
	MemoryMB          int
	DiskMB            int
	AllocReadyTimeout time.Duration
	EvalTimeout       time.Duration
	ExecTimeoutSecs   int
}

// BlaxelConfig configures the delegated Blaxel provider. API keys are read
// from environment variables, never persisted in repository config or argv.

// BlaxelConfig configures the delegated Blaxel provider. API keys are read
// from environment variables, never persisted in repository config or argv.
type BlaxelConfig struct {
	APIKey          string
	APIURL          string
	Workspace       string
	Region          string
	Image           string
	MemoryMB        int
	TTL             string
	IdleTTL         string
	Workdir         string
	ExecTimeoutSecs int
	ForgetMissing   bool
}

// CloudflareSandboxConfig configures the delegated Cloudflare Sandbox bridge
// provider. The token may be loaded from trusted user config or environment,
// but it is never exposed as a CLI flag and must be redacted in display output.

// CloudflareSandboxConfig configures the delegated Cloudflare Sandbox bridge
// provider. The token may be loaded from trusted user config or environment,
// but it is never exposed as a CLI flag and must be redacted in display output.
type CloudflareSandboxConfig struct {
	BridgeURL       string
	Token           string
	Workdir         string
	ExecTimeoutSecs int
	ForgetMissing   bool
}

// SuperserveConfig configures the delegated Superserve provider. The API key is
// intentionally absent: it is read at runtime from
// CRABBOX_SUPERSERVE_API_KEY / SUPERSERVE_API_KEY and sent only in request
// headers, never persisted in Crabbox config or placed on argv.

// SuperserveConfig configures the delegated Superserve provider. The API key is
// intentionally absent: it is read at runtime from
// CRABBOX_SUPERSERVE_API_KEY / SUPERSERVE_API_KEY and sent only in request
// headers, never persisted in Crabbox config or placed on argv.
type SuperserveConfig struct {
	BaseURL         string
	Template        string
	Snapshot        string
	Workdir         string
	TimeoutSecs     int
	ExecTimeoutSecs int
	NetworkAllowOut []string
	NetworkDenyOut  []string
	ForgetMissing   bool
}

// CrownestConfig configures the delegated CrowNest provider. The API key is
// intentionally absent: it is read at runtime from
// CRABBOX_CROWNEST_API_KEY / CROWNEST_API_KEY and sent only in request headers,
// never persisted in Crabbox config or placed on argv.

// CrownestConfig configures the delegated CrowNest provider. The API key is
// intentionally absent: it is read at runtime from
// CRABBOX_CROWNEST_API_KEY / CROWNEST_API_KEY and sent only in request headers,
// never persisted in Crabbox config or placed on argv.
type CrownestConfig struct {
	APIURL        string
	ProjectID     string
	Template      string
	TimeoutSecs   int
	ForgetMissing bool
}

type DockerSandboxConfig struct {
	CLIPath         string
	Agent           string
	Template        string
	CPUs            float64
	Memory          string
	Clone           bool
	Workdir         string
	ExtraWorkspaces []string
	MCP             []string
	Kit             []string
}

type AnthropicSRTConfig struct {
	CLIPath  string
	Settings string
	Debug    bool
}

// CloudRunSandboxConfig configures the Google Cloud Run sandboxes provider.
// Secrets (CLOUD_RUN_SANDBOX_SECRET / CLOUD_RUN_AUTH_TOKEN) are intentionally
// absent: they are read at runtime from the environment only and never
// persisted in Crabbox config or placed on argv.
// GatewayURL is also not accepted from repository YAML; use flags or env so a
// checked-in config cannot redirect a local secret to an untrusted endpoint.

// CloudRunSandboxConfig configures the Google Cloud Run sandboxes provider.
// Secrets (CLOUD_RUN_SANDBOX_SECRET / CLOUD_RUN_AUTH_TOKEN) are intentionally
// absent: they are read at runtime from the environment only and never
// persisted in Crabbox config or placed on argv.
// GatewayURL is also not accepted from repository YAML; use flags or env so a
// checked-in config cannot redirect a local secret to an untrusted endpoint.
type CloudRunSandboxConfig struct {
	GatewayURL  string
	CLIPath     string
	Workdir     string
	AllowEgress bool
	Write       bool
	Rootfs      string
}

type ModalConfig struct {
	App         string
	Image       string
	Workdir     string
	Python      string
	Environment string
	Secrets     []string
}

type UpstashBoxConfig struct {
	APIKey    string
	BaseURL   string
	Runtime   string
	Size      string
	Workdir   string
	KeepAlive bool
}

type SmolvmConfig struct {
	APIKey   string
	BaseURL  string
	Image    string
	Workdir  string
	CPUs     int
	MemoryMB int
	Network  string
	Keep     bool
}

type AsciiBoxConfig struct {
	APIKey  string
	BaseURL string
	CLIPath string
	Workdir string
}

type CloudflareConfig struct {
	APIURL  string
	Token   string
	Workdir string
}

const DefaultCloudflareDynamicWorkersCompatibilityDate = "2026-06-12"

type CloudflareDynamicWorkersConfig struct {
	LoaderURL                      string
	Token                          string
	CompatibilityDate              string
	CompatibilityFlags             []string
	CacheMode                      string
	Egress                         string
	CPUMs                          int
	Subrequests                    int
	TimeoutSecs                    int
	Metadata                       map[string]string
	repositoryCPUMsCap             int
	repositoryCPUMsCapActive       bool
	repositorySubrequestsCap       int
	repositorySubrequestsCapActive bool
	repositoryTimeoutSecsCap       int
	repositoryTimeoutSecsCapActive bool
}

type ProxmoxConfig struct {
	APIURL      string
	TokenID     string
	TokenSecret string
	Node        string
	TemplateID  int
	Storage     string
	Pool        string
	Bridge      string
	User        string
	WorkRoot    string
	FullClone   bool
	InsecureTLS bool
}

type FirecrackerConfig struct {
	Binary          string
	Jailer          string
	Kernel          string
	RootFS          string
	User            string
	WorkRoot        string
	CPUs            int
	MemoryMiB       int
	DiskMiB         int
	Network         string
	CNINetwork      string
	CNIConfDir      string
	CNIBinDir       string
	LaunchTimeout   time.Duration
	DeleteOnRelease bool
}

type XCPNgConfig struct {
	APIURL       string
	Username     string
	Password     string
	Template     string
	TemplateUUID string
	SR           string
	SRUUID       string
	Network      string
	NetworkUUID  string
	Host         string
	User         string
	WorkRoot     string
	InsecureTLS  bool
}

type IncusConfig struct {
	CheckpointMetadata map[string]string `yaml:"-" json:"-"`
	Remote             string
	Project            string
	Address            string
	Socket             string
	InstanceType       string
	Image              string
	Profile            string
	User               string
	WorkRoot           string
	DeleteOnRelease    bool
	StartTimeout       time.Duration
	LaunchPort         string
	ProxyListenHost    string
	ProxyListenPort    string
	ProxyDevice        string
	TLSServerCert      string
	InsecureTLS        bool
	RemoteImageServer  string
}

type ParallelsConfig struct {
	Template         string
	Source           string
	SourceID         string
	SourceSnapshot   string
	SourceSnapshotID string
	CloneMode        string
	Host             string
	HostUser         string
	HostKey          string
	VMRoot           string
	User             string
	WorkRoot         string
	StartupTimeout   time.Duration
	Templates        map[string]ParallelsTemplateConfig
	Hosts            []ParallelsHostConfig
	SelectedHost     string
}

type ParallelsTemplateConfig struct {
	Source           string
	SourceID         string
	SourceSnapshot   string
	SourceSnapshotID string
	TargetOS         string
	WindowsMode      string
	CloneMode        string
	Host             string
	HostUser         string
	HostKey          string
	VMRoot           string
	User             string
	WorkRoot         string
	hostSource       credentialValueSource
	hostKeySource    credentialValueSource
}

type ParallelsHostConfig struct {
	Name       string
	Host       string
	User       string
	Key        string
	VMRoot     string
	Targets    []string
	MaxVMs     int
	hostSource credentialValueSource
	keySource  credentialValueSource
}

type SemaphoreConfig struct {
	Host        string
	Token       string
	Project     string
	Machine     string
	OSImage     string
	IdleTimeout string
}

type SpritesConfig struct {
	Token    string
	APIURL   string
	WorkRoot string
}

type LocalContainerConfig struct {
	Runtime            string
	Image              string
	User               string
	WorkRoot           string
	CPUs               int
	Memory             string
	Network            string
	DockerSocket       bool
	Volumes            []string
	CheckpointMetadata map[string]string `yaml:"-" json:"-"`
}

type AppleContainerConfig struct {
	CLIPath      string
	Image        string
	User         string
	WorkRoot     string
	CPUs         int
	Memory       string
	ExtraRunArgs []string
}

type AppleVMConfig struct {
	HelperPath  string
	Image       string
	ImageSHA256 string
	User        string
	WorkRoot    string
	CPUs        int
	MemoryMiB   int
	DiskGiB     int
}

type MXCConfig struct {
	CLIPath           string
	Version           string
	Containment       string
	Network           string
	ReadOnlyPaths     []string
	ReadWritePaths    []string
	AllowedHosts      []string
	BlockedHosts      []string
	AllowDACLMutation bool
	AllowWindowsUI    bool
	Experimental      bool
}

type MultipassConfig struct {
	CLIPath       string
	Image         string
	User          string
	WorkRoot      string
	CPUs          int
	Memory        string
	Disk          string
	LaunchTimeout time.Duration
}

type Machine0Config struct {
	CLIPath       string
	Image         string
	ImageVersion  int
	DesktopImage  string
	Size          string
	SizeExplicit  bool
	Region        string
	Key           string
	WorkRoot      string
	ReleasePolicy string
	CreateTimeout time.Duration
	PollInterval  time.Duration
}

// DefaultTartImage is the immutable built-in image; the Tart adapter verifies its contents.

// DefaultTartImage is the immutable built-in image; the Tart adapter verifies its contents.
const DefaultTartImage = "ghcr.io/cirruslabs/macos-sequoia-base@sha256:785c3acb40fa5af6dd5aab96cd60408372c26125e173c14ea417498d086f829c"

type TartConfig struct {
	Image    string
	User     string
	Password string
	WorkRoot string
	CPUs     int
	Memory   int
	Disk     int
}

type LumeConfig struct {
	CLIPath  string
	Base     string
	Storage  string
	User     string
	WorkRoot string
}

type HyperVConfig struct {
	Image         string
	User          string
	WorkRoot      string
	CPUs          int
	Memory        int
	Switch        string
	GuestPassword string
	InitPassword  bool
}

type WindowsSandboxConfig struct {
	Workdir            string
	TempRoot           string
	Networking         string
	VGPU               string
	Clipboard          string
	ProtectedClient    string
	AudioInput         string
	VideoInput         string
	PrinterRedirection string
	MemoryMB           int
}

type StaticConfig struct {
	ID       string
	Name     string
	Host     string
	User     string
	Port     string
	WorkRoot string
}

type ResultsConfig struct {
	JUnit          []string
	Auto           bool
	FailOnFailures bool
}

type ShardConfig struct {
	MaxCount int
}

type CacheConfig struct {
	Pnpm           bool
	Npm            bool
	Docker         bool
	Git            bool
	MaxGB          int
	PurgeOnRelease bool
	Volumes        []CacheVolumeConfig
}

type CacheVolumeConfig struct {
	Name     string `json:"name,omitempty"`
	Key      string `json:"key"`
	Path     string `json:"path"`
	SizeGB   int    `json:"sizeGB,omitempty"`
	Required bool   `json:"required,omitempty"`
}

type ProfileConfig struct {
	Env            map[string]string
	EnvAllow       []string
	ArtifactGlobs  []string
	Doctor         DoctorProfileConfig
	Presets        map[string]PresetConfig
	ProofTemplates map[string]ProofTemplateConfig
}

type DoctorProfileConfig struct {
	Enabled        bool
	Tools          []string
	NodeMajor      int
	MinDiskGB      int
	RequireDocker  bool
	RequireCompose bool
}

type PresetConfig struct {
	Command       string
	Shell         bool
	Env           map[string]string
	Preflight     bool
	ArtifactGlobs []string
	ProofTemplate string
}

type ProofTemplateConfig struct {
	BehaviorAddressed     string
	RealEnvironmentTested string
	ExactSteps            string
	ObservedResult        string
	NotTested             string
}

type JobConfig struct {
	Provider          string
	Target            string
	WindowsMode       string
	Profile           string
	Class             string
	Architecture      string
	ServerType        string
	Market            string
	TTL               time.Duration
	IdleTimeout       time.Duration
	Desktop           *bool
	DesktopEnv        string
	Browser           *bool
	Code              *bool
	Network           string
	Hydrate           JobHydrateConfig
	Actions           JobActionsConfig
	Shell             bool
	Command           string
	NoSync            bool
	SyncOnly          bool
	Checksum          *bool
	ForceSyncLarge    bool
	JUnit             []string
	Label             string
	ArtifactGlobs     []string
	RequiredArtifacts []string
	Downloads         []string
	Stop              string
}

type JobHydrateConfig struct {
	Actions          bool
	GitHubRunner     bool
	WaitTimeout      time.Duration
	KeepAliveMinutes int
}

type JobActionsConfig struct {
	Repo     string
	Workflow string
	Job      string
	Ref      string
	Fields   []string
}

type AccessConfig struct {
	ClientID     string
	ClientSecret string
	Token        string
}
