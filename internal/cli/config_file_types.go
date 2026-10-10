package cli

import (
	"fmt"
	"sort"
	"strings"

	"gopkg.in/yaml.v3"
)

type fileConfig struct {
	Profile                  string                              `yaml:"profile,omitempty"`
	Provider                 string                              `yaml:"provider,omitempty"`
	Target                   string                              `yaml:"target,omitempty"`
	TargetOS                 string                              `yaml:"targetOS,omitempty"`
	Architecture             string                              `yaml:"architecture,omitempty"`
	OSImage                  string                              `yaml:"os,omitempty"`
	Windows                  *fileWindowsConfig                  `yaml:"windows,omitempty"`
	Desktop                  *bool                               `yaml:"desktop,omitempty"`
	DesktopEnv               string                              `yaml:"desktopEnv,omitempty"`
	Browser                  *bool                               `yaml:"browser,omitempty"`
	Code                     *bool                               `yaml:"code,omitempty"`
	Network                  string                              `yaml:"network,omitempty"`
	Class                    string                              `yaml:"class,omitempty"`
	ServerType               string                              `yaml:"serverType,omitempty"`
	Coordinator              string                              `yaml:"coordinator,omitempty"`
	CoordinatorToken         string                              `yaml:"coordinatorToken,omitempty"`
	HostID                   string                              `yaml:"hostId,omitempty"`
	Broker                   *fileBrokerConfig                   `yaml:"broker,omitempty"`
	Hetzner                  *fileHetznerConfig                  `yaml:"hetzner,omitempty"`
	DigitalOcean             *fileDigitalOceanConfig             `yaml:"digitalocean,omitempty"`
	Vultr                    *fileVultrConfig                    `yaml:"vultr,omitempty"`
	Linode                   *fileLinodeConfig                   `yaml:"linode,omitempty"`
	GitHubCodespaces         *fileGitHubCodespacesConfig         `yaml:"githubCodespaces,omitempty"`
	Lambda                   *fileLambdaConfig                   `yaml:"lambda,omitempty"`
	Nebius                   *fileNebiusConfig                   `yaml:"nebius,omitempty"`
	OVH                      *fileOVHConfig                      `yaml:"ovh,omitempty"`
	Scaleway                 *fileScalewayConfig                 `yaml:"scaleway,omitempty"`
	TencentCloud             *fileTencentCloudConfig             `yaml:"tencentcloud,omitempty"`
	AWS                      *fileAWSConfig                      `yaml:"aws,omitempty"`
	AWSLambdaMicroVM         *fileAWSLambdaMicroVMConfig         `yaml:"awsLambdaMicroVM,omitempty"`
	Azure                    *fileAzureConfig                    `yaml:"azure,omitempty"`
	AzureDynamicSessions     *fileAzureDynamicSessionsConfig     `yaml:"azureDynamicSessions,omitempty"`
	GCP                      *fileGCPConfig                      `yaml:"gcp,omitempty"`
	Incus                    *fileIncusConfig                    `yaml:"incus,omitempty"`
	Proxmox                  *fileProxmoxConfig                  `yaml:"proxmox,omitempty"`
	Firecracker              *fileFirecrackerConfig              `yaml:"firecracker,omitempty"`
	XCPNg                    *fileXCPNgConfig                    `yaml:"xcpNg,omitempty"`
	Parallels                *fileParallelsConfig                `yaml:"parallels,omitempty"`
	SSH                      *fileSSHConfig                      `yaml:"ssh,omitempty"`
	Sync                     *fileSyncConfig                     `yaml:"sync,omitempty"`
	Run                      *fileRunConfig                      `yaml:"run,omitempty"`
	Env                      *fileEnvConfig                      `yaml:"env,omitempty"`
	Capacity                 *fileCapacityConfig                 `yaml:"capacity,omitempty"`
	Actions                  *fileActionsConfig                  `yaml:"actions,omitempty"`
	Blacksmith               *fileBlacksmithConfig               `yaml:"blacksmith,omitempty"`
	KubeVirt                 *fileKubeVirtConfig                 `yaml:"kubevirt,omitempty"`
	SealosDevbox             *fileSealosDevboxConfig             `yaml:"sealosDevbox,omitempty"`
	AgentSandbox             *fileAgentSandboxConfig             `yaml:"agentSandbox,omitempty"`
	External                 *fileExternalConfig                 `yaml:"external,omitempty"`
	Namespace                *fileNamespaceConfig                `yaml:"namespace,omitempty"`
	NamespaceInstance        *fileNamespaceInstanceConfig        `yaml:"namespaceInstance,omitempty"`
	Phala                    *filePhalaConfig                    `yaml:"phala,omitempty"`
	Boxd                     *fileBoxdConfig                     `yaml:"boxd,omitempty"`
	Coder                    *fileCoderConfig                    `yaml:"coder,omitempty"`
	Morph                    *fileMorphConfig                    `yaml:"morph,omitempty"`
	Daytona                  *fileDaytonaConfig                  `yaml:"daytona,omitempty"`
	E2B                      *fileE2BConfig                      `yaml:"e2b,omitempty"`
	CubeSandbox              *fileCubeSandboxConfig              `yaml:"cubeSandbox,omitempty"`
	ExeDev                   *fileExeDevConfig                   `yaml:"exeDev,omitempty"`
	Railway                  *fileRailwayConfig                  `yaml:"railway,omitempty"`
	FastAPICloud             *fileFastAPICloudConfig             `yaml:"fastapiCloud,omitempty"`
	UnikraftCloud            *fileUnikraftCloudConfig            `yaml:"unikraftCloud,omitempty"`
	Runpod                   *fileRunpodConfig                   `yaml:"runpod,omitempty"`
	Vast                     *fileVastConfig                     `yaml:"vast,omitempty"`
	NvidiaBrev               *fileNvidiaBrevConfig               `yaml:"nvidiaBrev,omitempty"`
	Hostinger                *fileHostingerConfig                `yaml:"hostinger,omitempty"`
	Wandb                    *fileWandbConfig                    `yaml:"wandb,omitempty"`
	Orgo                     *fileOrgoConfig                     `yaml:"orgo,omitempty"`
	Islo                     *fileIsloConfig                     `yaml:"islo,omitempty"`
	Freestyle                *fileFreestyleConfig                `yaml:"freestyle,omitempty"`
	Tenki                    *fileTenkiConfig                    `yaml:"tenki,omitempty"`
	Tensorlake               *fileTensorlakeConfig               `yaml:"tensorlake,omitempty"`
	Cua                      *fileCuaConfig                      `yaml:"cua,omitempty"`
	OpenComputer             *fileOpenComputerConfig             `yaml:"openComputer,omitempty"`
	CodeSandbox              *fileCodeSandboxConfig              `yaml:"codeSandbox,omitempty"`
	OpenSandbox              *fileOpenSandboxConfig              `yaml:"openSandbox,omitempty"`
	Nomad                    *fileNomadConfig                    `yaml:"nomad,omitempty"`
	Blaxel                   *fileBlaxelConfig                   `yaml:"blaxel,omitempty"`
	VercelSandbox            *fileVercelSandboxConfig            `yaml:"vercelSandbox,omitempty"`
	CloudflareSandbox        *fileCloudflareSandboxConfig        `yaml:"cloudflareSandbox,omitempty"`
	Superserve               *fileSuperserveConfig               `yaml:"superserve,omitempty"`
	Crownest                 *fileCrownestConfig                 `yaml:"crownest,omitempty"`
	DockerSandbox            *fileDockerSandboxConfig            `yaml:"dockerSandbox,omitempty"`
	AnthropicSRT             *fileAnthropicSRTConfig             `yaml:"anthropicSandboxRuntime,omitempty"`
	CloudRunSandbox          *fileCloudRunSandboxConfig          `yaml:"cloudRunSandbox,omitempty"`
	Modal                    *fileModalConfig                    `yaml:"modal,omitempty"`
	UpstashBox               *fileUpstashBoxConfig               `yaml:"upstashBox,omitempty"`
	Smolvm                   *fileSmolvmConfig                   `yaml:"smolvm,omitempty"`
	AsciiBox                 *fileAsciiBoxConfig                 `yaml:"asciiBox,omitempty"`
	Cloudflare               *fileCloudflareConfig               `yaml:"cloudflare,omitempty"`
	CloudflareDynamicWorkers *fileCloudflareDynamicWorkersConfig `yaml:"cloudflareDynamicWorkers,omitempty"`
	Semaphore                *fileSemaphoreConfig                `yaml:"semaphore,omitempty"`
	Sprites                  *fileSpritesConfig                  `yaml:"sprites,omitempty"`
	LocalContainer           *fileLocalContainerConfig           `yaml:"localContainer,omitempty"`
	AppleContainer           *fileAppleContainerConfig           `yaml:"appleContainer,omitempty"`
	AppleVM                  *fileAppleVMConfig                  `yaml:"appleVM,omitempty"`
	AppleVZLegacy            *fileAppleVMConfig                  `yaml:"appleVZ,omitempty"`
	MXC                      *fileMXCConfig                      `yaml:"mxc,omitempty"`
	Multipass                *fileMultipassConfig                `yaml:"multipass,omitempty"`
	Machine0                 *fileMachine0Config                 `yaml:"machine0,omitempty"`
	Tart                     *fileTartConfig                     `yaml:"tart,omitempty"`
	Lume                     *fileLumeConfig                     `yaml:"lume,omitempty"`
	HyperV                   *fileHyperVConfig                   `yaml:"hyperv,omitempty"`
	WindowsSandbox           *fileWindowsSandboxConfig           `yaml:"windowsSandbox,omitempty"`
	Tailscale                *fileTailscaleConfig                `yaml:"tailscale,omitempty"`
	Static                   *fileStaticConfig                   `yaml:"static,omitempty"`
	Results                  *fileResultsConfig                  `yaml:"results,omitempty"`
	Shard                    *fileShardConfig                    `yaml:"shard,omitempty"`
	Cache                    *fileCacheConfig                    `yaml:"cache,omitempty"`
	Lease                    *fileLeaseConfig                    `yaml:"lease,omitempty"`
	Profiles                 map[string]fileProfileConfig        `yaml:"profiles,omitempty"`
	Presets                  map[string]filePresetConfig         `yaml:"presets,omitempty"`
	ProofTemplates           map[string]fileProofTemplateConfig  `yaml:"proofTemplates,omitempty"`
	Jobs                     map[string]fileJobConfig            `yaml:"jobs,omitempty"`
	TTL                      string                              `yaml:"ttl,omitempty"`
	IdleTimeout              string                              `yaml:"idleTimeout,omitempty"`
	WorkRoot                 string                              `yaml:"workRoot,omitempty"`
}

type fileWindowsConfig struct {
	Mode string `yaml:"mode,omitempty"`
}

type fileBrokerConfig struct {
	URL                  string            `yaml:"url,omitempty"`
	Mode                 string            `yaml:"mode,omitempty"`
	AutoWebVNC           *bool             `yaml:"autoWebVNC,omitempty"`
	LoginRedirectOrigins []string          `yaml:"loginRedirectOrigins,omitempty"`
	Token                string            `yaml:"token,omitempty"`
	AdminToken           string            `yaml:"adminToken,omitempty"`
	Provider             string            `yaml:"provider,omitempty"`
	Access               *fileAccessConfig `yaml:"access,omitempty"`
}

type fileAccessConfig struct {
	ClientID     string `yaml:"clientId,omitempty"`
	ClientSecret string `yaml:"clientSecret,omitempty"`
	Token        string `yaml:"token,omitempty"`
}

type fileHetznerConfig struct {
	Location string `yaml:"location,omitempty"`
	Image    string `yaml:"image,omitempty"`
	SSHKey   string `yaml:"sshKey,omitempty"`
}

type fileDigitalOceanConfig struct {
	Region   string   `yaml:"region,omitempty"`
	Image    string   `yaml:"image,omitempty"`
	VPCUUID  string   `yaml:"vpc,omitempty"`
	SSHCIDRs []string `yaml:"sshCIDRs,omitempty"`
}

type fileVultrConfig struct {
	Region        string   `yaml:"region,omitempty"`
	OS            string   `yaml:"os,omitempty"`
	Image         string   `yaml:"image,omitempty"`
	Snapshot      string   `yaml:"snapshot,omitempty"`
	FirewallGroup string   `yaml:"firewallGroup,omitempty"`
	VPCIDs        []string `yaml:"vpcIds,omitempty"`
	SSHCIDRs      []string `yaml:"sshCIDRs,omitempty"`
	UserScheme    string   `yaml:"userScheme,omitempty"`
}

type fileLinodeConfig struct {
	Region     string   `yaml:"region,omitempty"`
	Image      string   `yaml:"image,omitempty"`
	Type       string   `yaml:"type,omitempty"`
	FirewallID string   `yaml:"firewall,omitempty"`
	SSHCIDRs   []string `yaml:"sshCIDRs,omitempty"`
}

type fileGitHubCodespacesConfig struct {
	APIURL           string `yaml:"apiUrl,omitempty"`
	GHPath           string `yaml:"ghPath,omitempty"`
	Repo             string `yaml:"repo,omitempty"`
	Ref              string `yaml:"ref,omitempty"`
	Machine          string `yaml:"machine,omitempty"`
	DevcontainerPath string `yaml:"devcontainerPath,omitempty"`
	WorkingDirectory string `yaml:"workingDirectory,omitempty"`
	Geo              string `yaml:"geo,omitempty"`
	IdleTimeout      string `yaml:"idleTimeout,omitempty"`
	RetentionPeriod  string `yaml:"retentionPeriod,omitempty"`
	DeleteOnRelease  *bool  `yaml:"deleteOnRelease,omitempty"`
	WorkRoot         string `yaml:"workRoot,omitempty"`
}

type fileLambdaConfig struct {
	Region           string                  `yaml:"region,omitempty"`
	Type             string                  `yaml:"type,omitempty"`
	Image            string                  `yaml:"image,omitempty"`
	ImageFamily      string                  `yaml:"imageFamily,omitempty"`
	FirewallRuleset  string                  `yaml:"firewallRuleset,omitempty"`
	SSHCIDRs         []string                `yaml:"sshCIDRs,omitempty"`
	FilesystemNames  []string                `yaml:"filesystemNames,omitempty"`
	FilesystemMounts []LambdaFilesystemMount `yaml:"filesystemMounts,omitempty"`
}

type fileNebiusConfig struct {
	CLI              string   `yaml:"cli,omitempty"`
	Profile          string   `yaml:"profile,omitempty"`
	ParentID         string   `yaml:"parentId,omitempty"`
	SubnetID         string   `yaml:"subnetId,omitempty"`
	Platform         string   `yaml:"platform,omitempty"`
	Preset           string   `yaml:"preset,omitempty"`
	ImageFamily      string   `yaml:"imageFamily,omitempty"`
	DiskType         string   `yaml:"diskType,omitempty"`
	DiskSizeGiB      int      `yaml:"diskSizeGiB,omitempty"`
	User             string   `yaml:"user,omitempty"`
	PublicIP         string   `yaml:"publicIP,omitempty"`
	SecurityGroupIDs []string `yaml:"securityGroupIds,omitempty"`
	ServiceAccountID string   `yaml:"serviceAccountId,omitempty"`
	RecoveryPolicy   string   `yaml:"recoveryPolicy,omitempty"`
}

type fileOVHConfig struct {
	Endpoint  string `yaml:"endpoint,omitempty"`
	ProjectID string `yaml:"projectId,omitempty"`
	Region    string `yaml:"region,omitempty"`
	Image     string `yaml:"image,omitempty"`
	Flavor    string `yaml:"flavor,omitempty"`
}

type fileScalewayConfig struct {
	Region         string   `yaml:"region,omitempty"`
	Zone           string   `yaml:"zone,omitempty"`
	Image          string   `yaml:"image,omitempty"`
	Type           string   `yaml:"type,omitempty"`
	ProjectID      string   `yaml:"projectId,omitempty"`
	OrganizationID string   `yaml:"organizationId,omitempty"`
	SecurityGroup  string   `yaml:"securityGroup,omitempty"`
	SSHCIDRs       []string `yaml:"sshCIDRs,omitempty"`
}

type fileTencentCloudConfig struct {
	Region                  string   `yaml:"region,omitempty"`
	Zone                    string   `yaml:"zone,omitempty"`
	Image                   string   `yaml:"image,omitempty"`
	Type                    string   `yaml:"type,omitempty"`
	VPCID                   string   `yaml:"vpcId,omitempty"`
	SubnetID                string   `yaml:"subnetId,omitempty"`
	SecurityGroupID         string   `yaml:"securityGroupId,omitempty"`
	SSHCIDRs                []string `yaml:"sshCIDRs,omitempty"`
	RootGB                  int64    `yaml:"rootGB,omitempty"`
	InternetChargeType      string   `yaml:"internetChargeType,omitempty"`
	InternetMaxBandwidthOut int64    `yaml:"internetMaxBandwidthOut,omitempty"`
	APIEndpoint             string   `yaml:"apiEndpoint,omitempty"`
}

type fileAWSConfig struct {
	Region          string   `yaml:"region,omitempty"`
	AMI             string   `yaml:"ami,omitempty"`
	SecurityGroupID string   `yaml:"securityGroupId,omitempty"`
	SubnetID        string   `yaml:"subnetId,omitempty"`
	InstanceProfile string   `yaml:"instanceProfile,omitempty"`
	RootGB          int32    `yaml:"rootGB,omitempty"`
	SSHCIDRs        []string `yaml:"sshCIDRs,omitempty"`
	MacHostID       string   `yaml:"macHostId,omitempty"`
}

type fileAWSLambdaMicroVMConfig struct {
	Image             string    `yaml:"image,omitempty"`
	ImageVersion      string    `yaml:"imageVersion,omitempty"`
	ExecutionRoleARN  string    `yaml:"executionRoleArn,omitempty"`
	Workdir           string    `yaml:"workdir,omitempty"`
	IngressConnectors *[]string `yaml:"ingressConnectors,omitempty"`
	EgressConnectors  *[]string `yaml:"egressConnectors,omitempty"`
	ForgetMissing     *bool     `yaml:"forgetMissing,omitempty"`
}

type fileAzureConfig struct {
	SubscriptionID string   `yaml:"subscriptionId,omitempty"`
	TenantID       string   `yaml:"tenantId,omitempty"`
	ClientID       string   `yaml:"clientId,omitempty"`
	Backend        string   `yaml:"backend,omitempty"`
	Location       string   `yaml:"location,omitempty"`
	ResourceGroup  string   `yaml:"resourceGroup,omitempty"`
	Image          string   `yaml:"image,omitempty"`
	OSDisk         string   `yaml:"osDisk,omitempty"`
	SnapshotSKU    string   `yaml:"snapshotSKU,omitempty"`
	OSDiskSKU      string   `yaml:"osDiskSKU,omitempty"`
	VNet           string   `yaml:"vnet,omitempty"`
	Subnet         string   `yaml:"subnet,omitempty"`
	NSG            string   `yaml:"nsg,omitempty"`
	SSHCIDRs       []string `yaml:"sshCIDRs,omitempty"`
	Network        string   `yaml:"network,omitempty"`
}

type fileGCPConfig struct {
	Project        string   `yaml:"project,omitempty"`
	Zone           string   `yaml:"zone,omitempty"`
	Image          string   `yaml:"image,omitempty"`
	Network        string   `yaml:"network,omitempty"`
	Subnet         string   `yaml:"subnet,omitempty"`
	Tags           []string `yaml:"tags,omitempty"`
	SSHCIDRs       []string `yaml:"sshCIDRs,omitempty"`
	RootGB         int64    `yaml:"rootGB,omitempty"`
	ServiceAccount string   `yaml:"serviceAccount,omitempty"`
}

type fileIncusConfig struct {
	Remote            string `yaml:"remote,omitempty"`
	Project           string `yaml:"project,omitempty"`
	Address           string `yaml:"address,omitempty"`
	Socket            string `yaml:"socket,omitempty"`
	InstanceType      string `yaml:"instanceType,omitempty"`
	Image             string `yaml:"image,omitempty"`
	Profile           string `yaml:"profile,omitempty"`
	User              string `yaml:"user,omitempty"`
	WorkRoot          string `yaml:"workRoot,omitempty"`
	DeleteOnRelease   *bool  `yaml:"deleteOnRelease,omitempty"`
	StartTimeout      string `yaml:"startTimeout,omitempty"`
	LaunchPort        string `yaml:"launchPort,omitempty"`
	ProxyListenHost   string `yaml:"proxyListenHost,omitempty"`
	ProxyListenPort   string `yaml:"proxyListenPort,omitempty"`
	ProxyDevice       string `yaml:"proxyDevice,omitempty"`
	TLSServerCert     string `yaml:"tlsServerCert,omitempty"`
	InsecureTLS       *bool  `yaml:"insecureTLS,omitempty"`
	RemoteImageServer string `yaml:"remoteImageServer,omitempty"`
}

type fileProxmoxConfig struct {
	APIURL      string `yaml:"apiUrl,omitempty"`
	TokenID     string `yaml:"tokenId,omitempty"`
	TokenSecret string `yaml:"tokenSecret,omitempty"`
	Node        string `yaml:"node,omitempty"`
	TemplateID  int    `yaml:"templateId,omitempty"`
	Storage     string `yaml:"storage,omitempty"`
	Pool        string `yaml:"pool,omitempty"`
	Bridge      string `yaml:"bridge,omitempty"`
	User        string `yaml:"user,omitempty"`
	WorkRoot    string `yaml:"workRoot,omitempty"`
	FullClone   *bool  `yaml:"fullClone,omitempty"`
	InsecureTLS *bool  `yaml:"insecureTLS,omitempty"`
}

type fileFirecrackerConfig struct {
	Binary          string `yaml:"binary,omitempty"`
	Jailer          string `yaml:"jailer,omitempty"`
	Kernel          string `yaml:"kernel,omitempty"`
	RootFS          string `yaml:"rootfs,omitempty"`
	User            string `yaml:"user,omitempty"`
	WorkRoot        string `yaml:"workRoot,omitempty"`
	CPUs            *int   `yaml:"cpus,omitempty"`
	MemoryMiB       *int   `yaml:"memoryMiB,omitempty"`
	DiskMiB         *int   `yaml:"diskMiB,omitempty"`
	Network         string `yaml:"network,omitempty"`
	CNINetwork      string `yaml:"cniNetwork,omitempty"`
	CNIConfDir      string `yaml:"cniConfDir,omitempty"`
	CNIBinDir       string `yaml:"cniBinDir,omitempty"`
	LaunchTimeout   string `yaml:"launchTimeout,omitempty"`
	DeleteOnRelease *bool  `yaml:"deleteOnRelease,omitempty"`
}

type fileXCPNgConfig struct {
	APIURL       string `yaml:"apiUrl,omitempty"`
	Username     string `yaml:"username,omitempty"`
	Password     string `yaml:"password,omitempty"`
	Template     string `yaml:"template,omitempty"`
	TemplateUUID string `yaml:"templateUuid,omitempty"`
	SR           string `yaml:"sr,omitempty"`
	SRUUID       string `yaml:"srUuid,omitempty"`
	Network      string `yaml:"network,omitempty"`
	NetworkUUID  string `yaml:"networkUuid,omitempty"`
	Host         string `yaml:"host,omitempty"`
	User         string `yaml:"user,omitempty"`
	WorkRoot     string `yaml:"workRoot,omitempty"`
	InsecureTLS  *bool  `yaml:"insecureTLS,omitempty"`
}

type fileParallelsConfig struct {
	Template         string                                 `yaml:"template,omitempty"`
	Source           string                                 `yaml:"source,omitempty"`
	SourceID         string                                 `yaml:"sourceId,omitempty"`
	SourceSnapshot   string                                 `yaml:"sourceSnapshot,omitempty"`
	SourceSnapshotID string                                 `yaml:"sourceSnapshotId,omitempty"`
	CloneMode        string                                 `yaml:"cloneMode,omitempty"`
	Host             string                                 `yaml:"host,omitempty"`
	HostUser         string                                 `yaml:"hostUser,omitempty"`
	HostKey          string                                 `yaml:"hostKey,omitempty"`
	VMRoot           string                                 `yaml:"vmRoot,omitempty"`
	User             string                                 `yaml:"user,omitempty"`
	WorkRoot         string                                 `yaml:"workRoot,omitempty"`
	StartupTimeout   string                                 `yaml:"startupTimeout,omitempty"`
	Templates        map[string]fileParallelsTemplateConfig `yaml:"templates,omitempty"`
	Hosts            []fileParallelsHostConfig              `yaml:"hosts,omitempty"`
}

type fileParallelsTemplateConfig struct {
	Source           string `yaml:"source,omitempty"`
	SourceID         string `yaml:"sourceId,omitempty"`
	SourceSnapshot   string `yaml:"sourceSnapshot,omitempty"`
	SourceSnapshotID string `yaml:"sourceSnapshotId,omitempty"`
	Target           string `yaml:"target,omitempty"`
	TargetOS         string `yaml:"targetOS,omitempty"`
	WindowsMode      string `yaml:"windowsMode,omitempty"`
	CloneMode        string `yaml:"cloneMode,omitempty"`
	Host             string `yaml:"host,omitempty"`
	HostUser         string `yaml:"hostUser,omitempty"`
	HostKey          string `yaml:"hostKey,omitempty"`
	VMRoot           string `yaml:"vmRoot,omitempty"`
	User             string `yaml:"user,omitempty"`
	WorkRoot         string `yaml:"workRoot,omitempty"`
}

type fileParallelsHostConfig struct {
	Name    string   `yaml:"name,omitempty"`
	Host    string   `yaml:"host,omitempty"`
	User    string   `yaml:"user,omitempty"`
	Key     string   `yaml:"key,omitempty"`
	VMRoot  string   `yaml:"vmRoot,omitempty"`
	Targets []string `yaml:"targets,omitempty"`
	MaxVMs  int      `yaml:"maxVMs,omitempty"`
}

type fileSSHConfig struct {
	User          string    `yaml:"user,omitempty"`
	Key           string    `yaml:"key,omitempty"`
	Port          string    `yaml:"port,omitempty"`
	FallbackPorts *[]string `yaml:"fallbackPorts,omitempty"`
}

type fileSyncConfig struct {
	Exclude     []string `yaml:"exclude,omitempty"`
	Excludes    []string `yaml:"excludes,omitempty"`
	Include     []string `yaml:"include,omitempty"`
	Includes    []string `yaml:"includes,omitempty"`
	Delete      *bool    `yaml:"delete,omitempty"`
	Checksum    *bool    `yaml:"checksum,omitempty"`
	GitSeed     *bool    `yaml:"gitSeed,omitempty"`
	GitOverlay  *bool    `yaml:"gitOverlay,omitempty"`
	Fingerprint *bool    `yaml:"fingerprint,omitempty"`
	BaseRef     string   `yaml:"baseRef,omitempty"`
	Timeout     string   `yaml:"timeout,omitempty"`
	WarnFiles   int      `yaml:"warnFiles,omitempty"`
	WarnBytes   int64    `yaml:"warnBytes,omitempty"`
	FailFiles   int      `yaml:"failFiles,omitempty"`
	FailBytes   int64    `yaml:"failBytes,omitempty"`
	AllowLarge  *bool    `yaml:"allowLarge,omitempty"`
}

type fileEnvConfig struct {
	Allow []string `yaml:"allow,omitempty"`
}

type fileRunConfig struct {
	PreflightTools []string `yaml:"preflightTools,omitempty"`
}

type fileCapacityConfig struct {
	Market            string   `yaml:"market,omitempty"`
	Strategy          string   `yaml:"strategy,omitempty"`
	Fallback          string   `yaml:"fallback,omitempty"`
	Regions           []string `yaml:"regions,omitempty"`
	AvailabilityZones []string `yaml:"availabilityZones,omitempty"`
	Hints             *bool    `yaml:"hints,omitempty"`
}

type fileActionsConfig struct {
	Repo          string   `yaml:"repo,omitempty"`
	Workflow      string   `yaml:"workflow,omitempty"`
	Job           string   `yaml:"job,omitempty"`
	Ref           string   `yaml:"ref,omitempty"`
	Fields        []string `yaml:"fields,omitempty"`
	RunnerLabels  []string `yaml:"runnerLabels,omitempty"`
	RunnerVersion string   `yaml:"runnerVersion,omitempty"`
	Ephemeral     *bool    `yaml:"ephemeral,omitempty"`
}

type fileBlacksmithConfig struct {
	Org         string `yaml:"org,omitempty"`
	Workflow    string `yaml:"workflow,omitempty"`
	Job         string `yaml:"job,omitempty"`
	Ref         string `yaml:"ref,omitempty"`
	IdleTimeout string `yaml:"idleTimeout,omitempty"`
	Debug       *bool  `yaml:"debug,omitempty"`
}

type fileKubeVirtConfig struct {
	Kubectl         string `yaml:"kubectl,omitempty"`
	Virtctl         string `yaml:"virtctl,omitempty"`
	Kubeconfig      string `yaml:"kubeconfig,omitempty"`
	Context         string `yaml:"context,omitempty"`
	Namespace       string `yaml:"namespace,omitempty"`
	Template        string `yaml:"template,omitempty"`
	SSHUser         string `yaml:"sshUser,omitempty"`
	SSHKey          string `yaml:"sshKey,omitempty"`
	SSHPublicKey    string `yaml:"sshPublicKey,omitempty"`
	SSHPort         string `yaml:"sshPort,omitempty"`
	WorkRoot        string `yaml:"workRoot,omitempty"`
	DeleteOnRelease *bool  `yaml:"deleteOnRelease,omitempty"`
}

type fileSealosDevboxConfig struct {
	Kubectl         string `yaml:"kubectl,omitempty"`
	Kubeconfig      string `yaml:"kubeconfig,omitempty"`
	Context         string `yaml:"context,omitempty"`
	Namespace       string `yaml:"namespace,omitempty"`
	Image           string `yaml:"image,omitempty"`
	TemplateID      string `yaml:"templateID,omitempty"`
	CPU             string `yaml:"cpu,omitempty"`
	Memory          string `yaml:"memory,omitempty"`
	StorageLimit    string `yaml:"storageLimit,omitempty"`
	Network         string `yaml:"network,omitempty"`
	SSHGatewayHost  string `yaml:"sshGatewayHost,omitempty"`
	SSHGatewayPort  string `yaml:"sshGatewayPort,omitempty"`
	SSHUser         string `yaml:"sshUser,omitempty"`
	WorkRoot        string `yaml:"workRoot,omitempty"`
	NodeHost        string `yaml:"nodeHost,omitempty"`
	DeleteOnRelease *bool  `yaml:"deleteOnRelease,omitempty"`
}

type fileAgentSandboxConfig struct {
	Kubectl             string `yaml:"kubectl,omitempty"`
	Kubeconfig          string `yaml:"kubeconfig,omitempty"`
	Context             string `yaml:"context,omitempty"`
	Namespace           string `yaml:"namespace,omitempty"`
	WarmPool            string `yaml:"warmPool,omitempty"`
	Container           string `yaml:"container,omitempty"`
	Workdir             string `yaml:"workdir,omitempty"`
	SandboxReadyTimeout string `yaml:"sandboxReadyTimeout,omitempty"`
	PodReadyTimeout     string `yaml:"podReadyTimeout,omitempty"`
	ExecTimeoutSecs     *int   `yaml:"execTimeoutSecs,omitempty"`
	DeleteOnRelease     *bool  `yaml:"deleteOnRelease,omitempty"`
	ForgetMissing       *bool  `yaml:"forgetMissing,omitempty"`
}

type fileExternalConfig struct {
	Command      string                      `yaml:"command,omitempty"`
	Args         []string                    `yaml:"args,omitempty"`
	Config       map[string]any              `yaml:"config,omitempty"`
	Capabilities *ExternalCapabilitiesConfig `yaml:"capabilities,omitempty"`
	Lifecycle    *ExternalLifecycleConfig    `yaml:"lifecycle,omitempty"`
	Connection   *ExternalConnectionConfig   `yaml:"connection,omitempty"`
	WorkRoot     string                      `yaml:"workRoot,omitempty"`
	RoutingFile  string                      `yaml:"routingFile,omitempty"`
}

type fileNamespaceConfig struct {
	Image               string `yaml:"image,omitempty"`
	Size                string `yaml:"size,omitempty"`
	Repository          string `yaml:"repository,omitempty"`
	Site                string `yaml:"site,omitempty"`
	VolumeSizeGB        int    `yaml:"volumeSizeGB,omitempty"`
	AutoStopIdleTimeout string `yaml:"autoStopIdleTimeout,omitempty"`
	WorkRoot            string `yaml:"workRoot,omitempty"`
	DeleteOnRelease     *bool  `yaml:"deleteOnRelease,omitempty"`
}

type fileNamespaceInstanceConfig struct {
	CLIPath     string   `yaml:"cli,omitempty"`
	MachineType string   `yaml:"machineType,omitempty"`
	Duration    string   `yaml:"duration,omitempty"`
	Region      string   `yaml:"region,omitempty"`
	Endpoint    string   `yaml:"endpoint,omitempty"`
	Keychain    string   `yaml:"keychain,omitempty"`
	Volumes     []string `yaml:"volumes,omitempty"`
	WorkRoot    string   `yaml:"workRoot,omitempty"`
	Bare        *bool    `yaml:"bare,omitempty"`
}

// BoxdConfig contains non-secret HTTPS console routing and lease settings.
// Interactive session tokens are read only from the environment by the provider.

// BoxdConfig contains non-secret HTTPS console routing and lease settings.
// Interactive session tokens are read only from the environment by the provider.
type BoxdConfig struct {
	APIURL          string
	Org             string // Empty selects the fixed personal account context.
	WorkRoot        string
	DeleteOnRelease bool
}

type fileBoxdConfig struct {
	APIURL          string `yaml:"apiUrl,omitempty"`
	Org             string `yaml:"org,omitempty"`
	WorkRoot        string `yaml:"workRoot,omitempty"`
	DeleteOnRelease *bool  `yaml:"deleteOnRelease,omitempty"`
}

type filePhalaConfig struct {
	CLIPath      string `yaml:"cli,omitempty"`
	InstanceType string `yaml:"instanceType,omitempty"`
	WorkRoot     string `yaml:"workRoot,omitempty"`
	NodeID       string `yaml:"nodeId,omitempty"`
	Compose      string `yaml:"compose,omitempty"`
	Attest       *bool  `yaml:"attest,omitempty"`
}

type fileCoderConfig struct {
	CLIPath              string   `yaml:"cliPath,omitempty"`
	Template             string   `yaml:"template,omitempty"`
	Preset               string   `yaml:"preset,omitempty"`
	WorkspacePrefix      string   `yaml:"workspacePrefix,omitempty"`
	WorkRoot             string   `yaml:"workRoot,omitempty"`
	DeleteOnRelease      *bool    `yaml:"deleteOnRelease,omitempty"`
	Wait                 string   `yaml:"wait,omitempty"`
	UseParameterDefaults *bool    `yaml:"useParameterDefaults,omitempty"`
	Parameters           []string `yaml:"parameters,omitempty"`
	RichParameterFile    string   `yaml:"richParameterFile,omitempty"`
}

func (c *fileCoderConfig) UnmarshalYAML(node *yaml.Node) error {
	type plain fileCoderConfig
	var out plain
	if err := node.Decode(&out); err != nil {
		return err
	}
	for i := 0; i+1 < len(node.Content); i += 2 {
		key := node.Content[i].Value
		value := node.Content[i+1]
		if key != "parameters" {
			continue
		}
		switch value.Kind {
		case yaml.SequenceNode:
			out.Parameters = out.Parameters[:0]
			for _, item := range value.Content {
				if strings.TrimSpace(item.Value) != "" {
					out.Parameters = append(out.Parameters, strings.TrimSpace(item.Value))
				}
			}
		case yaml.ScalarNode:
			out.Parameters = splitCommaList(value.Value)
		}
	}
	*c = fileCoderConfig(out)
	return nil
}

type fileMorphConfig struct {
	APIKey          string `yaml:"apiKey,omitempty"`
	APIURL          string `yaml:"apiUrl,omitempty"`
	Snapshot        string `yaml:"snapshot,omitempty"`
	SSHGatewayHost  string `yaml:"sshGatewayHost,omitempty"`
	WorkRoot        string `yaml:"workRoot,omitempty"`
	DeleteOnRelease *bool  `yaml:"deleteOnRelease,omitempty"`
	WakeOnSSH       *bool  `yaml:"wakeOnSSH,omitempty"`
}

type fileDaytonaConfig struct {
	APIURL           string `yaml:"apiUrl,omitempty"`
	Snapshot         string `yaml:"snapshot,omitempty"`
	Target           string `yaml:"target,omitempty"`
	User             string `yaml:"user,omitempty"`
	WorkRoot         string `yaml:"workRoot,omitempty"`
	SSHGatewayHost   string `yaml:"sshGatewayHost,omitempty"`
	SSHAccessMinutes int    `yaml:"sshAccessMinutes,omitempty"`
}

type fileE2BConfig struct {
	APIURL   string `yaml:"apiUrl,omitempty"`
	Domain   string `yaml:"domain,omitempty"`
	Template string `yaml:"template,omitempty"`
	Workdir  string `yaml:"workdir,omitempty"`
	User     string `yaml:"user,omitempty"`
}

type fileCubeSandboxConfig struct {
	APIURL        string `yaml:"apiUrl,omitempty"`
	Domain        string `yaml:"domain,omitempty"`
	Template      string `yaml:"template,omitempty"`
	Workdir       string `yaml:"workdir,omitempty"`
	User          string `yaml:"user,omitempty"`
	ProxyNodeIP   string `yaml:"proxyNodeIp,omitempty"`
	ProxyPortHTTP int    `yaml:"proxyPortHttp,omitempty"`
	ProxyScheme   string `yaml:"proxyScheme,omitempty"`
}

type fileAzureDynamicSessionsConfig struct {
	Endpoint    string `yaml:"endpoint,omitempty"`
	Pool        string `yaml:"pool,omitempty"`
	APIVersion  string `yaml:"apiVersion,omitempty"`
	Workdir     string `yaml:"workdir,omitempty"`
	TimeoutSecs int    `yaml:"timeoutSecs,omitempty"`
}

type fileFreestyleConfig struct {
	APIURL   string `yaml:"apiUrl,omitempty"`
	Workdir  string `yaml:"workdir,omitempty"`
	VCPUs    int    `yaml:"vcpus,omitempty"`
	MemoryGB int    `yaml:"memoryGB,omitempty"`
}

type fileExeDevConfig struct {
	ControlHost string `yaml:"controlHost,omitempty"`
	Image       string `yaml:"image,omitempty"`
	CPUs        int    `yaml:"cpus,omitempty"`
	Memory      string `yaml:"memory,omitempty"`
	Disk        string `yaml:"disk,omitempty"`
	Command     string `yaml:"command,omitempty"`
	User        string `yaml:"user,omitempty"`
	WorkRoot    string `yaml:"workRoot,omitempty"`
	NoEmail     *bool  `yaml:"noEmail,omitempty"`
}

type fileRailwayConfig struct {
	APIURL        string `yaml:"apiUrl,omitempty"`
	ProjectID     string `yaml:"projectId,omitempty"`
	EnvironmentID string `yaml:"environmentId,omitempty"`
}

type fileFastAPICloudConfig struct {
	APIURL string `yaml:"apiUrl,omitempty"`
	AppID  string `yaml:"appId,omitempty"`
	TeamID string `yaml:"teamId,omitempty"`
}

type fileUnikraftCloudConfig struct {
	APIKey   string `yaml:"apiKey,omitempty"`
	APIURL   string `yaml:"apiUrl,omitempty"`
	Metro    string `yaml:"metro,omitempty"`
	Image    string `yaml:"image,omitempty"`
	MemoryMB int    `yaml:"memoryMB,omitempty"`
}

type fileRunpodConfig struct {
	APIURL     string `yaml:"apiUrl,omitempty"`
	CloudType  string `yaml:"cloudType,omitempty"`
	InstanceID string `yaml:"instanceId,omitempty"`
	Image      string `yaml:"image,omitempty"`
	TemplateID string `yaml:"templateId,omitempty"`
	DiskGB     int    `yaml:"diskGB,omitempty"`
	User       string `yaml:"user,omitempty"`
	WorkRoot   string `yaml:"workRoot,omitempty"`
}

type fileVastConfig struct {
	APIURL         string   `yaml:"apiUrl,omitempty"`
	InstanceType   string   `yaml:"instanceType,omitempty"`
	GPUName        string   `yaml:"gpuName,omitempty"`
	GPUCount       int      `yaml:"gpuCount,omitempty"`
	Image          string   `yaml:"image,omitempty"`
	TemplateID     string   `yaml:"templateId,omitempty"`
	Runtype        string   `yaml:"runtype,omitempty"`
	DiskGB         int      `yaml:"diskGB,omitempty"`
	MaxDphTotal    *float64 `yaml:"maxDphTotal,omitempty"`
	MinReliability *float64 `yaml:"minReliability,omitempty"`
	Order          string   `yaml:"order,omitempty"`
	User           string   `yaml:"user,omitempty"`
	WorkRoot       string   `yaml:"workRoot,omitempty"`
	ReleaseAction  string   `yaml:"releaseAction,omitempty"`
}

type fileNvidiaBrevConfig struct {
	CLI           string `yaml:"cli,omitempty"`
	Org           string `yaml:"org,omitempty"`
	Type          string `yaml:"type,omitempty"`
	GPUName       string `yaml:"gpuName,omitempty"`
	Provider      string `yaml:"provider,omitempty"`
	Mode          string `yaml:"mode,omitempty"`
	Launchable    string `yaml:"launchable,omitempty"`
	StartupScript string `yaml:"startupScript,omitempty"`
	ReleaseAction string `yaml:"releaseAction,omitempty"`
	Target        string `yaml:"target,omitempty"`
	User          string `yaml:"user,omitempty"`
	WorkRoot      string `yaml:"workRoot,omitempty"`
}

type fileHostingerConfig struct {
	APIToken        string `yaml:"apiToken,omitempty"`
	APIURL          string `yaml:"apiUrl,omitempty"`
	ItemID          string `yaml:"itemId,omitempty"`
	PaymentMethodID string `yaml:"paymentMethodId,omitempty"`
	TemplateID      string `yaml:"templateId,omitempty"`
	DataCenterID    string `yaml:"dataCenterId,omitempty"`
	HostnamePrefix  string `yaml:"hostnamePrefix,omitempty"`
	User            string `yaml:"user,omitempty"`
	WorkRoot        string `yaml:"workRoot,omitempty"`
	AllowPurchase   *bool  `yaml:"allowPurchase,omitempty"`
	ReleaseAction   string `yaml:"releaseAction,omitempty"`
}

type fileWandbConfig struct {
	APIKey             string `yaml:"apiKey,omitempty"`
	DefaultImage       string `yaml:"defaultImage,omitempty"`
	MaxLifetimeSeconds int    `yaml:"maxLifetimeSeconds,omitempty"`
}

type fileOrgoConfig struct {
	APIKey      string `yaml:"apiKey,omitempty"`
	APIBase     string `yaml:"apiBase,omitempty"`
	WorkspaceID string `yaml:"workspaceID,omitempty"`
	RAMGB       int    `yaml:"ramGB,omitempty"`
	CPUs        int    `yaml:"cpus,omitempty"`
	DiskGB      int    `yaml:"diskGB,omitempty"`
	Resolution  string `yaml:"resolution,omitempty"`
}

type fileIsloConfig struct {
	BaseURL        string `yaml:"baseUrl,omitempty"`
	Image          string `yaml:"image,omitempty"`
	Workdir        string `yaml:"workdir,omitempty"`
	GatewayProfile string `yaml:"gatewayProfile,omitempty"`
	SnapshotName   string `yaml:"snapshotName,omitempty"`
	VCPUs          int    `yaml:"vcpus,omitempty"`
	MemoryMB       int    `yaml:"memoryMB,omitempty"`
	DiskGB         int    `yaml:"diskGB,omitempty"`
}

type fileTenkiConfig struct {
	CLIPath   string `yaml:"cliPath,omitempty"`
	Endpoint  string `yaml:"endpoint,omitempty"`
	Gateway   string `yaml:"gateway,omitempty"`
	Workspace string `yaml:"workspace,omitempty"`
	Project   string `yaml:"project,omitempty"`
	Image     string `yaml:"image,omitempty"`
	Snapshot  string `yaml:"snapshot,omitempty"`
	WorkRoot  string `yaml:"workRoot,omitempty"`
	CPUs      int    `yaml:"cpus,omitempty"`
	MemoryMB  int    `yaml:"memoryMB,omitempty"`
	DiskGB    int    `yaml:"diskGB,omitempty"`
}

type fileTensorlakeConfig struct {
	APIURL         string  `yaml:"apiUrl,omitempty"`
	CLIPath        string  `yaml:"cliPath,omitempty"`
	Image          string  `yaml:"image,omitempty"`
	Snapshot       string  `yaml:"snapshot,omitempty"`
	OrganizationID string  `yaml:"organizationId,omitempty"`
	ProjectID      string  `yaml:"projectId,omitempty"`
	Namespace      string  `yaml:"namespace,omitempty"`
	Workdir        string  `yaml:"workdir,omitempty"`
	CPUs           float64 `yaml:"cpus,omitempty"`
	MemoryMB       int     `yaml:"memoryMB,omitempty"`
	DiskMB         int     `yaml:"diskMB,omitempty"`
	TimeoutSecs    int     `yaml:"timeoutSecs,omitempty"`
	NoInternet     *bool   `yaml:"noInternet,omitempty"`
}

type fileCuaConfig struct {
	Image              *string `yaml:"image,omitempty"`
	Kind               *string `yaml:"kind,omitempty"`
	Region             *string `yaml:"region,omitempty"`
	Workdir            *string `yaml:"workdir,omitempty"`
	VCPUs              *int    `yaml:"vcpus,omitempty"`
	MemoryMB           *int    `yaml:"memoryMB,omitempty"`
	DiskGB             *int    `yaml:"diskGB,omitempty"`
	StartupTimeoutSecs *int    `yaml:"startupTimeoutSecs,omitempty"`
	ExecTimeoutSecs    *int    `yaml:"execTimeoutSecs,omitempty"`
	BridgeCommand      *string `yaml:"bridgeCommand,omitempty"`
	SDKPackage         *string `yaml:"sdkPackage,omitempty"`
	SDKImport          *string `yaml:"sdkImport,omitempty"`
	SDKFallbackImport  *string `yaml:"sdkFallbackImport,omitempty"`
}

type fileOpenComputerConfig struct {
	Workdir         string `yaml:"workdir,omitempty"`
	CPU             *int   `yaml:"cpu,omitempty"`
	MemoryMB        *int   `yaml:"memoryMB,omitempty"`
	TimeoutSecs     *int   `yaml:"timeoutSecs,omitempty"`
	ExecTimeoutSecs *int   `yaml:"execTimeoutSecs,omitempty"`
	Burst           *bool  `yaml:"burst,omitempty"`
}

type fileCodeSandboxConfig struct {
	TemplateID               *string `yaml:"templateId,omitempty"`
	Workdir                  *string `yaml:"workdir,omitempty"`
	VMTier                   *string `yaml:"vmTier,omitempty"`
	Privacy                  *string `yaml:"privacy,omitempty"`
	HibernationTimeoutSecs   *int    `yaml:"hibernationTimeoutSecs,omitempty"`
	AutomaticWakeupHTTP      *bool   `yaml:"automaticWakeupHTTP,omitempty"`
	AutomaticWakeupWebSocket *bool   `yaml:"automaticWakeupWebSocket,omitempty"`
	BridgeCommand            *string `yaml:"bridgeCommand,omitempty"`
	SDKPackage               *string `yaml:"sdkPackage,omitempty"`
	DoctorListLimit          *int    `yaml:"doctorListLimit,omitempty"`
	OperationTimeoutSecs     *int    `yaml:"operationTimeoutSecs,omitempty"`
}

type fileOpenSandboxConfig struct {
	Image           *string `yaml:"image,omitempty"`
	Workdir         *string `yaml:"workdir,omitempty"`
	CPU             *string `yaml:"cpu,omitempty"`
	Memory          *string `yaml:"memory,omitempty"`
	TimeoutSecs     *int    `yaml:"timeoutSecs,omitempty"`
	ExecTimeoutSecs *int    `yaml:"execTimeoutSecs,omitempty"`
	PlatformOS      *string `yaml:"platformOS,omitempty"`
	PlatformArch    *string `yaml:"platformArch,omitempty"`
	SecureAccess    *bool   `yaml:"secureAccess,omitempty"`
	UseServerProxy  *bool   `yaml:"useServerProxy,omitempty"`
}

type fileNomadConfig struct {
	Address           string   `yaml:"address,omitempty"`
	Region            string   `yaml:"region,omitempty"`
	Namespace         string   `yaml:"namespace,omitempty"`
	TokenEnv          string   `yaml:"tokenEnv,omitempty"`
	CACert            string   `yaml:"caCert,omitempty"`
	CAPath            string   `yaml:"caPath,omitempty"`
	ClientCert        string   `yaml:"clientCert,omitempty"`
	ClientKey         string   `yaml:"clientKey,omitempty"`
	TLSServerName     string   `yaml:"tlsServerName,omitempty"`
	SkipVerify        *bool    `yaml:"skipVerify,omitempty"`
	Task              *string  `yaml:"task,omitempty"`
	Driver            *string  `yaml:"driver,omitempty"`
	Image             *string  `yaml:"image,omitempty"`
	Workdir           *string  `yaml:"workdir,omitempty"`
	JobSpecTemplate   string   `yaml:"jobspecTemplate,omitempty"`
	NodePool          string   `yaml:"nodePool,omitempty"`
	Datacenters       []string `yaml:"datacenters,omitempty"`
	CPU               *int     `yaml:"cpu,omitempty"`
	MemoryMB          *int     `yaml:"memoryMB,omitempty"`
	DiskMB            *int     `yaml:"diskMB,omitempty"`
	AllocReadyTimeout string   `yaml:"allocReadyTimeout,omitempty"`
	EvalTimeout       string   `yaml:"evalTimeout,omitempty"`
	ExecTimeoutSecs   *int     `yaml:"execTimeoutSecs,omitempty"`
}

type fileBlaxelConfig struct {
	APIURL          string  `yaml:"apiUrl,omitempty"`
	Workspace       string  `yaml:"workspace,omitempty"`
	Region          string  `yaml:"region,omitempty"`
	Image           *string `yaml:"image,omitempty"`
	MemoryMB        *int    `yaml:"memoryMB,omitempty"`
	TTL             string  `yaml:"ttl,omitempty"`
	IdleTTL         string  `yaml:"idleTTL,omitempty"`
	Workdir         *string `yaml:"workdir,omitempty"`
	ExecTimeoutSecs *int    `yaml:"execTimeoutSecs,omitempty"`
	ForgetMissing   *bool   `yaml:"forgetMissing,omitempty"`
}

type fileCloudflareSandboxConfig struct {
	BridgeURL       *string `yaml:"bridgeUrl,omitempty"`
	URL             *string `yaml:"url,omitempty"`
	Token           *string `yaml:"token,omitempty"`
	Workdir         *string `yaml:"workdir,omitempty"`
	ExecTimeoutSecs *int    `yaml:"execTimeoutSecs,omitempty"`
	ForgetMissing   *bool   `yaml:"forgetMissing,omitempty"`
}

type fileSuperserveConfig struct {
	BaseURL         string   `yaml:"baseUrl,omitempty"`
	Template        *string  `yaml:"template,omitempty"`
	Snapshot        *string  `yaml:"snapshot,omitempty"`
	Workdir         *string  `yaml:"workdir,omitempty"`
	TimeoutSecs     *int     `yaml:"timeoutSecs,omitempty"`
	ExecTimeoutSecs *int     `yaml:"execTimeoutSecs,omitempty"`
	NetworkAllowOut []string `yaml:"networkAllowOut,omitempty"`
	NetworkDenyOut  []string `yaml:"networkDenyOut,omitempty"`
	ForgetMissing   *bool    `yaml:"forgetMissing,omitempty"`
}

type fileCrownestConfig struct {
	APIURL        string  `yaml:"apiUrl,omitempty"`
	ProjectID     *string `yaml:"projectId,omitempty"`
	Template      *string `yaml:"template,omitempty"`
	TimeoutSecs   *int    `yaml:"timeoutSecs,omitempty"`
	ForgetMissing *bool   `yaml:"forgetMissing,omitempty"`
}

type fileDockerSandboxConfig struct {
	CLIPath         string    `yaml:"cliPath,omitempty"`
	Agent           string    `yaml:"agent,omitempty"`
	Template        *string   `yaml:"template,omitempty"`
	CPUs            *float64  `yaml:"cpus,omitempty"`
	Memory          *string   `yaml:"memory,omitempty"`
	Clone           *bool     `yaml:"clone,omitempty"`
	Workdir         *string   `yaml:"workdir,omitempty"`
	ExtraWorkspaces *[]string `yaml:"extraWorkspaces,omitempty"`
	MCP             *[]string `yaml:"mcp,omitempty"`
	Kit             *[]string `yaml:"kit,omitempty"`
}

type fileAnthropicSRTConfig struct {
	CLIPath  string  `yaml:"cliPath,omitempty"`
	Settings *string `yaml:"settings,omitempty"`
	Debug    *bool   `yaml:"debug,omitempty"`
}

type fileCloudRunSandboxConfig struct {
	CLIPath     string `yaml:"cliPath,omitempty"`
	Workdir     string `yaml:"workdir,omitempty"`
	AllowEgress *bool  `yaml:"allowEgress,omitempty"`
	Write       *bool  `yaml:"write,omitempty"`
	Rootfs      string `yaml:"rootfs,omitempty"`
}

type fileModalConfig struct {
	App         string   `yaml:"app,omitempty"`
	Image       string   `yaml:"image,omitempty"`
	Workdir     string   `yaml:"workdir,omitempty"`
	Python      string   `yaml:"python,omitempty"`
	Environment string   `yaml:"environment,omitempty"`
	Secrets     []string `yaml:"secrets,omitempty"`
}

type fileUpstashBoxConfig struct {
	BaseURL   string `yaml:"baseUrl,omitempty"`
	Runtime   string `yaml:"runtime,omitempty"`
	Size      string `yaml:"size,omitempty"`
	Workdir   string `yaml:"workdir,omitempty"`
	KeepAlive *bool  `yaml:"keepAlive,omitempty"`
}

type fileSmolvmConfig struct {
	BaseURL  string `yaml:"baseUrl,omitempty"`
	Image    string `yaml:"image,omitempty"`
	Workdir  string `yaml:"workdir,omitempty"`
	CPUs     int    `yaml:"cpus,omitempty"`
	MemoryMB int    `yaml:"memoryMB,omitempty"`
	Network  string `yaml:"network,omitempty"`
	Keep     *bool  `yaml:"keep,omitempty"`
}

type fileAsciiBoxConfig struct {
	BaseURL string `yaml:"baseUrl,omitempty"`
	CLIPath string `yaml:"cliPath,omitempty"`
	Workdir string `yaml:"workdir,omitempty"`
}

type fileCloudflareConfig struct {
	APIURL  string `yaml:"apiUrl,omitempty"`
	Token   string `yaml:"token,omitempty"`
	Workdir string `yaml:"workdir,omitempty"`
}

type fileCloudflareDynamicWorkersConfig struct {
	LoaderURL          string            `yaml:"loaderUrl,omitempty"`
	URL                string            `yaml:"url,omitempty"`
	Token              string            `yaml:"token,omitempty"`
	CompatibilityDate  string            `yaml:"compatibilityDate,omitempty"`
	CompatibilityFlags []string          `yaml:"compatibilityFlags,omitempty"`
	CacheMode          string            `yaml:"cacheMode,omitempty"`
	Egress             string            `yaml:"egress,omitempty"`
	CPUMs              int               `yaml:"cpuMs,omitempty"`
	Subrequests        int               `yaml:"subrequests,omitempty"`
	TimeoutSecs        int               `yaml:"timeoutSecs,omitempty"`
	Metadata           map[string]string `yaml:"metadata,omitempty"`
}

type fileSemaphoreConfig struct {
	Host        string `yaml:"host,omitempty"`
	Token       string `yaml:"token,omitempty"`
	Project     string `yaml:"project,omitempty"`
	Machine     string `yaml:"machine,omitempty"`
	OSImage     string `yaml:"osImage,omitempty"`
	IdleTimeout string `yaml:"idleTimeout,omitempty"`
}

type fileSpritesConfig struct {
	APIURL   string `yaml:"apiUrl,omitempty"`
	WorkRoot string `yaml:"workRoot,omitempty"`
}

type fileLocalContainerConfig struct {
	Runtime      string `yaml:"runtime,omitempty"`
	Image        string `yaml:"image,omitempty"`
	User         string `yaml:"user,omitempty"`
	WorkRoot     string `yaml:"workRoot,omitempty"`
	CPUs         int    `yaml:"cpus,omitempty"`
	Memory       string `yaml:"memory,omitempty"`
	Network      string `yaml:"network,omitempty"`
	DockerSocket *bool  `yaml:"dockerSocket,omitempty"`
}

type fileAppleContainerConfig struct {
	CLIPath      string   `yaml:"cliPath,omitempty"`
	Image        string   `yaml:"image,omitempty"`
	User         string   `yaml:"user,omitempty"`
	WorkRoot     string   `yaml:"workRoot,omitempty"`
	CPUs         int      `yaml:"cpus,omitempty"`
	Memory       string   `yaml:"memory,omitempty"`
	ExtraRunArgs []string `yaml:"extraRunArgs,omitempty"`
}

type fileAppleVMConfig struct {
	HelperPath  string `yaml:"helperPath,omitempty"`
	Image       string `yaml:"image,omitempty"`
	ImageSHA256 string `yaml:"imageSHA256,omitempty"`
	User        string `yaml:"user,omitempty"`
	WorkRoot    string `yaml:"workRoot,omitempty"`
	CPUs        *int   `yaml:"cpus,omitempty"`
	MemoryMiB   *int   `yaml:"memoryMiB,omitempty"`
	DiskGiB     *int   `yaml:"diskGiB,omitempty"`
}

type fileMXCConfig struct {
	CLIPath           string   `yaml:"cliPath,omitempty"`
	Version           string   `yaml:"version,omitempty"`
	Containment       string   `yaml:"containment,omitempty"`
	Network           string   `yaml:"network,omitempty"`
	ReadOnlyPaths     []string `yaml:"readOnlyPaths,omitempty"`
	ReadWritePaths    []string `yaml:"readWritePaths,omitempty"`
	AllowedHosts      []string `yaml:"allowedHosts,omitempty"`
	BlockedHosts      []string `yaml:"blockedHosts,omitempty"`
	AllowDACLMutation *bool    `yaml:"allowDaclMutation,omitempty"`
	AllowWindowsUI    *bool    `yaml:"allowWindowsUI,omitempty"`
	Experimental      *bool    `yaml:"experimental,omitempty"`
}

type fileMultipassConfig struct {
	CLIPath       string `yaml:"cliPath,omitempty"`
	Image         string `yaml:"image,omitempty"`
	User          string `yaml:"user,omitempty"`
	WorkRoot      string `yaml:"workRoot,omitempty"`
	CPUs          int    `yaml:"cpus,omitempty"`
	Memory        string `yaml:"memory,omitempty"`
	Disk          string `yaml:"disk,omitempty"`
	LaunchTimeout string `yaml:"launchTimeout,omitempty"`
}

type fileMachine0Config struct {
	CLIPath       string `yaml:"cliPath,omitempty"`
	Image         string `yaml:"image,omitempty"`
	ImageVersion  *int   `yaml:"imageVersion,omitempty"`
	DesktopImage  string `yaml:"desktopImage,omitempty"`
	Size          string `yaml:"size,omitempty"`
	Region        string `yaml:"region,omitempty"`
	Key           string `yaml:"key,omitempty"`
	WorkRoot      string `yaml:"workRoot,omitempty"`
	ReleasePolicy string `yaml:"releasePolicy,omitempty"`
	CreateTimeout string `yaml:"createTimeout,omitempty"`
	PollInterval  string `yaml:"pollInterval,omitempty"`
}

type fileTartConfig struct {
	Image    string `yaml:"image,omitempty"`
	User     string `yaml:"user,omitempty"`
	Password string `yaml:"password,omitempty"`
	WorkRoot string `yaml:"workRoot,omitempty"`
	CPUs     *int   `yaml:"cpus,omitempty"`
	Memory   *int   `yaml:"memory,omitempty"`
	Disk     *int   `yaml:"disk,omitempty"`
}

type fileLumeConfig struct {
	CLIPath  string `yaml:"cliPath,omitempty"`
	Base     string `yaml:"base,omitempty"`
	Storage  string `yaml:"storage,omitempty"`
	User     string `yaml:"user,omitempty"`
	WorkRoot string `yaml:"workRoot,omitempty"`
}

type fileHyperVConfig struct {
	Image         string `yaml:"image,omitempty"`
	User          string `yaml:"user,omitempty"`
	WorkRoot      string `yaml:"workRoot,omitempty"`
	CPUs          int    `yaml:"cpus,omitempty"`
	Memory        int    `yaml:"memory,omitempty"`
	Switch        string `yaml:"switch,omitempty"`
	GuestPassword string `yaml:"guestPassword,omitempty"`
	InitPassword  *bool  `yaml:"initPassword,omitempty"`
}

type fileWindowsSandboxConfig struct {
	Workdir            string `yaml:"workdir,omitempty"`
	TempRoot           string `yaml:"tempRoot,omitempty"`
	Networking         string `yaml:"networking,omitempty"`
	VGPU               string `yaml:"vgpu,omitempty"`
	Clipboard          string `yaml:"clipboard,omitempty"`
	ProtectedClient    string `yaml:"protectedClient,omitempty"`
	AudioInput         string `yaml:"audioInput,omitempty"`
	VideoInput         string `yaml:"videoInput,omitempty"`
	PrinterRedirection string `yaml:"printerRedirection,omitempty"`
	MemoryMB           int    `yaml:"memoryMB,omitempty"`
}

type fileTailscaleConfig struct {
	Enabled                *bool    `yaml:"enabled,omitempty"`
	Network                string   `yaml:"network,omitempty"`
	Tags                   []string `yaml:"tags,omitempty"`
	HostnameTemplate       string   `yaml:"hostnameTemplate,omitempty"`
	AuthKeyEnv             string   `yaml:"authKeyEnv,omitempty"`
	ExitNode               string   `yaml:"exitNode,omitempty"`
	ExitNodeAllowLANAccess *bool    `yaml:"exitNodeAllowLanAccess,omitempty"`
}

type fileStaticConfig struct {
	ID       string `yaml:"id,omitempty"`
	Name     string `yaml:"name,omitempty"`
	Host     string `yaml:"host,omitempty"`
	User     string `yaml:"user,omitempty"`
	Port     string `yaml:"port,omitempty"`
	WorkRoot string `yaml:"workRoot,omitempty"`
}

type fileResultsConfig struct {
	JUnit          []string `yaml:"junit,omitempty"`
	Auto           *bool    `yaml:"auto,omitempty"`
	FailOnFailures *bool    `yaml:"failOnFailures,omitempty"`
}

type fileShardConfig struct {
	MaxCount *int `yaml:"maxCount,omitempty"`
}

type fileCacheConfig struct {
	Pnpm           *bool                    `yaml:"pnpm,omitempty"`
	Npm            *bool                    `yaml:"npm,omitempty"`
	Docker         *bool                    `yaml:"docker,omitempty"`
	Git            *bool                    `yaml:"git,omitempty"`
	MaxGB          int                      `yaml:"maxGB,omitempty"`
	PurgeOnRelease *bool                    `yaml:"purgeOnRelease,omitempty"`
	Volumes        *[]fileCacheVolumeConfig `yaml:"volumes,omitempty"`
}

type fileCacheVolumeConfig struct {
	Name     string `yaml:"name,omitempty"`
	Key      string `yaml:"key,omitempty"`
	Path     string `yaml:"path,omitempty"`
	SizeGB   int    `yaml:"sizeGB,omitempty"`
	Required *bool  `yaml:"required,omitempty"`
}

type fileProfileConfig struct {
	Env            fileProfileEnvConfig               `yaml:"env,omitempty"`
	EnvAllow       []string                           `yaml:"envAllow,omitempty"`
	ArtifactGlobs  []string                           `yaml:"artifactGlobs,omitempty"`
	Doctor         *fileDoctorProfileConfig           `yaml:"doctor,omitempty"`
	Presets        map[string]filePresetConfig        `yaml:"presets,omitempty"`
	ProofTemplates map[string]fileProofTemplateConfig `yaml:"proofTemplates,omitempty"`
}

type fileProfileEnvConfig struct {
	Values map[string]string
	Allow  []string
}

func (env fileProfileEnvConfig) IsZero() bool {
	return len(env.Values) == 0 && len(env.Allow) == 0
}

func (env *fileProfileEnvConfig) UnmarshalYAML(node *yaml.Node) error {
	if node == nil || node.Kind == 0 {
		return nil
	}
	if node.Kind != yaml.MappingNode {
		return fmt.Errorf("profile env must be a mapping")
	}
	values := map[string]string{}
	var allow []string
	for i := 0; i+1 < len(node.Content); i += 2 {
		key := strings.TrimSpace(node.Content[i].Value)
		valueNode := node.Content[i+1]
		if key == "" {
			continue
		}
		if key == "allow" {
			if err := valueNode.Decode(&allow); err != nil {
				return fmt.Errorf("profile env.allow: %w", err)
			}
			continue
		}
		var value string
		if err := valueNode.Decode(&value); err != nil {
			return fmt.Errorf("profile env.%s: %w", key, err)
		}
		values[key] = value
	}
	env.Values = values
	env.Allow = allow
	return nil
}

func (env fileProfileEnvConfig) MarshalYAML() (any, error) {
	node := &yaml.Node{Kind: yaml.MappingNode}
	keys := make([]string, 0, len(env.Values))
	for key := range env.Values {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	for _, key := range keys {
		node.Content = append(node.Content,
			&yaml.Node{Kind: yaml.ScalarNode, Tag: "!!str", Value: key},
			&yaml.Node{Kind: yaml.ScalarNode, Tag: "!!str", Value: env.Values[key]},
		)
	}
	if len(env.Allow) > 0 {
		seq := &yaml.Node{Kind: yaml.SequenceNode}
		for _, value := range env.Allow {
			seq.Content = append(seq.Content, &yaml.Node{Kind: yaml.ScalarNode, Tag: "!!str", Value: value})
		}
		node.Content = append(node.Content,
			&yaml.Node{Kind: yaml.ScalarNode, Tag: "!!str", Value: "allow"},
			seq,
		)
	}
	return node, nil
}

type fileDoctorProfileConfig struct {
	Enabled        *bool    `yaml:"enabled,omitempty"`
	Tools          []string `yaml:"tools,omitempty"`
	NodeMajor      int      `yaml:"nodeMajor,omitempty"`
	MinDiskGB      int      `yaml:"minDiskGB,omitempty"`
	RequireDocker  *bool    `yaml:"requireDocker,omitempty"`
	RequireCompose *bool    `yaml:"requireCompose,omitempty"`
}

type filePresetConfig struct {
	Command       string            `yaml:"command,omitempty"`
	Shell         *bool             `yaml:"shell,omitempty"`
	Env           map[string]string `yaml:"env,omitempty"`
	Preflight     *bool             `yaml:"preflight,omitempty"`
	ArtifactGlobs []string          `yaml:"artifactGlobs,omitempty"`
	ProofTemplate string            `yaml:"proofTemplate,omitempty"`
}

type fileProofTemplateConfig struct {
	BehaviorAddressed     string `yaml:"behaviorAddressed,omitempty"`
	RealEnvironmentTested string `yaml:"realEnvironmentTested,omitempty"`
	ExactSteps            string `yaml:"exactSteps,omitempty"`
	ObservedResult        string `yaml:"observedResult,omitempty"`
	NotTested             string `yaml:"notTested,omitempty"`
}

type fileLeaseConfig struct {
	TTL         string `yaml:"ttl,omitempty"`
	IdleTimeout string `yaml:"idleTimeout,omitempty"`
}

type fileJobConfig struct {
	Provider          string                `yaml:"provider,omitempty"`
	Target            string                `yaml:"target,omitempty"`
	TargetOS          string                `yaml:"targetOS,omitempty"`
	Windows           *fileWindowsConfig    `yaml:"windows,omitempty"`
	Profile           string                `yaml:"profile,omitempty"`
	Class             string                `yaml:"class,omitempty"`
	Architecture      string                `yaml:"architecture,omitempty"`
	ServerType        string                `yaml:"serverType,omitempty"`
	Type              string                `yaml:"type,omitempty"`
	Capacity          *fileCapacityConfig   `yaml:"capacity,omitempty"`
	Market            string                `yaml:"market,omitempty"`
	TTL               string                `yaml:"ttl,omitempty"`
	IdleTimeout       string                `yaml:"idleTimeout,omitempty"`
	Desktop           *bool                 `yaml:"desktop,omitempty"`
	DesktopEnv        string                `yaml:"desktopEnv,omitempty"`
	Browser           *bool                 `yaml:"browser,omitempty"`
	Code              *bool                 `yaml:"code,omitempty"`
	Network           string                `yaml:"network,omitempty"`
	Hydrate           *fileJobHydrateConfig `yaml:"hydrate,omitempty"`
	Actions           *fileJobActionsConfig `yaml:"actions,omitempty"`
	Shell             *bool                 `yaml:"shell,omitempty"`
	Command           string                `yaml:"command,omitempty"`
	NoSync            *bool                 `yaml:"noSync,omitempty"`
	SyncOnly          *bool                 `yaml:"syncOnly,omitempty"`
	Checksum          *bool                 `yaml:"checksum,omitempty"`
	ForceSyncLarge    *bool                 `yaml:"forceSyncLarge,omitempty"`
	JUnit             []string              `yaml:"junit,omitempty"`
	Label             string                `yaml:"label,omitempty"`
	ArtifactGlobs     []string              `yaml:"artifactGlobs,omitempty"`
	RequiredArtifacts []string              `yaml:"requiredArtifacts,omitempty"`
	Downloads         []string              `yaml:"downloads,omitempty"`
	Stop              string                `yaml:"stop,omitempty"`
}

type fileJobHydrateConfig struct {
	Actions          *bool  `yaml:"actions,omitempty"`
	GitHubRunner     *bool  `yaml:"githubRunner,omitempty"`
	WaitTimeout      string `yaml:"waitTimeout,omitempty"`
	KeepAliveMinutes int    `yaml:"keepAliveMinutes,omitempty"`
}

type fileJobActionsConfig struct {
	Repo     string   `yaml:"repo,omitempty"`
	Workflow string   `yaml:"workflow,omitempty"`
	Job      string   `yaml:"job,omitempty"`
	Ref      string   `yaml:"ref,omitempty"`
	Fields   []string `yaml:"fields,omitempty"`
}
