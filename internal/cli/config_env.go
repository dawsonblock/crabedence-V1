package cli

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

func applyEnv(cfg *Config) error {
	cfg.Profile = getenv("CRABBOX_PROFILE", cfg.Profile)
	if provider := os.Getenv("CRABBOX_PROVIDER"); provider != "" {
		setProviderSelection(cfg, provider, providerSelectionEnvironment)
		cfg.brokerProvider = ""
	}
	if t := os.Getenv("CRABBOX_TARGET"); t != "" {
		cfg.TargetOS = t
		cfg.targetExplicit = true
		cfg.credentialProvenance.externalDesktopTarget = credentialSourceEnvironment
	} else if t := os.Getenv("CRABBOX_TARGET_OS"); t != "" {
		cfg.TargetOS = t
		cfg.targetExplicit = true
		cfg.credentialProvenance.externalDesktopTarget = credentialSourceEnvironment
	}
	if arch := os.Getenv("CRABBOX_ARCH"); arch != "" {
		cfg.Architecture = arch
		cfg.architectureExplicit = true
	}
	if osImage := os.Getenv("CRABBOX_OS"); osImage != "" {
		cfg.OSImage = osImage
		cfg.osImageExplicit = true
		if normalized, err := normalizeOSImage(osImage); err == nil {
			cfg.OSImage = normalized
			applyOSImageProviderDefaults(cfg, false)
		}
	}
	if windowsMode := os.Getenv("CRABBOX_WINDOWS_MODE"); windowsMode != "" {
		cfg.WindowsMode = windowsMode
		cfg.explicitWindowsMode = windowsMode
		cfg.credentialProvenance.externalDesktopMode = credentialSourceEnvironment
	}
	if value, ok := getenvBool("CRABBOX_DESKTOP"); ok {
		cfg.Desktop = value
	}
	cfg.DesktopEnv = getenv("CRABBOX_DESKTOP_ENV", cfg.DesktopEnv)
	if value, ok := getenvBool("CRABBOX_BROWSER"); ok {
		cfg.Browser = value
	}
	if value, ok := getenvBool("CRABBOX_CODE"); ok {
		cfg.Code = value
	}
	if network := os.Getenv("CRABBOX_NETWORK"); network != "" {
		cfg.Network = NetworkMode(strings.ToLower(strings.TrimSpace(network)))
	}
	if value := os.Getenv("CRABBOX_DEFAULT_CLASS"); value != "" {
		cfg.Class = value
		MarkClassExplicit(cfg)
	}
	if os.Getenv("CRABBOX_SERVER_TYPE") != "" {
		cfg.ServerTypeExplicit = true
	}
	cfg.ServerType = getenv("CRABBOX_SERVER_TYPE", cfg.ServerType)
	if value := os.Getenv("CRABBOX_COORDINATOR"); value != "" {
		cfg.Coordinator = value
		cfg.credentialProvenance.coordinator = credentialSourceEnvironment
	}
	cfg.BrokerMode = BrokerMode(getenv("CRABBOX_COORDINATOR_MODE", string(cfg.BrokerMode)))
	if value, ok := getenvBool("CRABBOX_COORDINATOR_AUTO_WEBVNC"); ok {
		cfg.BrokerAutoWebVNC = value
	}
	if value := os.Getenv("CRABBOX_BROKER_LOGIN_REDIRECT_ORIGINS"); value != "" {
		cfg.BrokerLoginRedirectOrigins = splitCommaList(value)
	}
	if value := os.Getenv("CRABBOX_COORDINATOR_TOKEN"); value != "" {
		cfg.CoordToken = value
		cfg.credentialProvenance.coordToken = credentialSourceEnvironment
	}
	if raw := strings.TrimSpace(os.Getenv("CRABBOX_COORDINATOR_TOKEN_COMMAND")); raw != "" {
		var command []string
		if err := json.Unmarshal([]byte(raw), &command); err != nil {
			return fmt.Errorf("CRABBOX_COORDINATOR_TOKEN_COMMAND must be a JSON argv array: %w", err)
		}
		if len(command) == 0 {
			return errors.New("CRABBOX_COORDINATOR_TOKEN_COMMAND must contain an executable")
		}
		for _, arg := range command {
			if strings.TrimSpace(arg) == "" || strings.ContainsAny(arg, "\r\n\x00") {
				return errors.New("CRABBOX_COORDINATOR_TOKEN_COMMAND contains an invalid argv entry")
			}
		}
		cfg.CoordTokenCommand = append([]string(nil), command...)
		cfg.credentialProvenance.coordTokenCommand = credentialSourceEnvironment
	}
	if value, ok := firstNonEmptyEnv("CRABBOX_COORDINATOR_ADMIN_TOKEN", "CRABBOX_ADMIN_TOKEN"); ok {
		cfg.CoordAdminToken = value
		cfg.credentialProvenance.coordAdminToken = credentialSourceEnvironment
	}
	cfg.HostID = getenv("CRABBOX_HOST_ID", cfg.HostID)
	if value, ok := firstNonEmptyEnv("CRABBOX_ACCESS_CLIENT_ID", "CF_ACCESS_CLIENT_ID"); ok {
		cfg.Access.ClientID = value
		cfg.credentialProvenance.accessClientID = credentialSourceEnvironment
	}
	if value, ok := firstNonEmptyEnv("CRABBOX_ACCESS_CLIENT_SECRET", "CF_ACCESS_CLIENT_SECRET"); ok {
		cfg.Access.ClientSecret = value
		cfg.credentialProvenance.accessClientSecret = credentialSourceEnvironment
	}
	if value, ok := firstNonEmptyEnv("CRABBOX_ACCESS_TOKEN", "CF_ACCESS_TOKEN"); ok {
		cfg.Access.Token = value
		cfg.credentialProvenance.accessToken = credentialSourceEnvironment
	}
	if location := os.Getenv("CRABBOX_HETZNER_LOCATION"); location != "" {
		cfg.Location = location
		cfg.locationExplicit = true
	}
	if image := os.Getenv("CRABBOX_HETZNER_IMAGE"); image != "" {
		cfg.Image = image
		cfg.imageExplicit = true
	}
	cfg.AWSRegion = getenv("CRABBOX_AWS_REGION", getenv("AWS_REGION", cfg.AWSRegion))
	cfg.AWSAMI = getenv("CRABBOX_AWS_AMI", cfg.AWSAMI)
	cfg.AWSSGID = getenv("CRABBOX_AWS_SECURITY_GROUP_ID", cfg.AWSSGID)
	cfg.AWSSubnetID = getenv("CRABBOX_AWS_SUBNET_ID", cfg.AWSSubnetID)
	cfg.AWSProfile = getenv("CRABBOX_AWS_INSTANCE_PROFILE", cfg.AWSProfile)
	cfg.AWSRootGB = getenvInt32("CRABBOX_AWS_ROOT_GB", cfg.AWSRootGB)
	cfg.AWSMacHostID = getenv("CRABBOX_AWS_MAC_HOST_ID", cfg.AWSMacHostID)
	cfg.AWSLambdaMicroVM.Image = getenv("CRABBOX_AWS_LAMBDA_MICROVM_IMAGE", cfg.AWSLambdaMicroVM.Image)
	cfg.AWSLambdaMicroVM.ImageVersion = getenv("CRABBOX_AWS_LAMBDA_MICROVM_IMAGE_VERSION", cfg.AWSLambdaMicroVM.ImageVersion)
	cfg.AWSLambdaMicroVM.ExecutionRoleARN = getenv("CRABBOX_AWS_LAMBDA_MICROVM_EXECUTION_ROLE_ARN", cfg.AWSLambdaMicroVM.ExecutionRoleARN)
	cfg.AWSLambdaMicroVM.Workdir = getenv("CRABBOX_AWS_LAMBDA_MICROVM_WORKDIR", cfg.AWSLambdaMicroVM.Workdir)
	if value := os.Getenv("CRABBOX_AWS_LAMBDA_MICROVM_INGRESS_CONNECTORS"); value != "" {
		cfg.AWSLambdaMicroVM.IngressConnectors = splitCSV(value)
	}
	if value := os.Getenv("CRABBOX_AWS_LAMBDA_MICROVM_EGRESS_CONNECTORS"); value != "" {
		cfg.AWSLambdaMicroVM.EgressConnectors = splitCSV(value)
	}
	if value, ok := getenvBool("CRABBOX_AWS_LAMBDA_MICROVM_FORGET_MISSING"); ok {
		cfg.AWSLambdaMicroVM.ForgetMissing = value
	}
	if cfg.HostID == "" && cfg.AWSMacHostID != "" {
		cfg.HostID = cfg.AWSMacHostID
	}
	if cfg.AWSMacHostID == "" && cfg.Provider == "aws" && cfg.TargetOS == targetMacOS {
		cfg.AWSMacHostID = cfg.HostID
	}
	if cidrs := os.Getenv("CRABBOX_AWS_SSH_CIDRS"); cidrs != "" {
		cfg.AWSSSHCIDRs = splitCommaList(cidrs)
	}
	cfg.AzureSubscription = getenv("CRABBOX_AZURE_SUBSCRIPTION_ID", getenv("AZURE_SUBSCRIPTION_ID", cfg.AzureSubscription))
	cfg.AzureTenant = getenv("CRABBOX_AZURE_TENANT_ID", getenv("AZURE_TENANT_ID", cfg.AzureTenant))
	cfg.AzureClientID = getenv("CRABBOX_AZURE_CLIENT_ID", getenv("AZURE_CLIENT_ID", cfg.AzureClientID))
	cfg.AzureBackend = getenv("CRABBOX_AZURE_BACKEND", cfg.AzureBackend)
	cfg.AzureLocation = getenv("CRABBOX_AZURE_LOCATION", cfg.AzureLocation)
	cfg.AzureResourceGroup = getenv("CRABBOX_AZURE_RESOURCE_GROUP", cfg.AzureResourceGroup)
	if image := os.Getenv("CRABBOX_AZURE_IMAGE"); image != "" {
		cfg.AzureImage = image
		cfg.azureImageExplicit = true
	}
	if value := os.Getenv("CRABBOX_AZURE_OS_DISK"); value != "" {
		cfg.AzureOSDisk = value
		cfg.AzureOSDiskExplicit = true
	}
	cfg.AzureSnapshotSKU = getenv("CRABBOX_AZURE_SNAPSHOT_SKU", cfg.AzureSnapshotSKU)
	cfg.AzureOSDiskSKU = getenv("CRABBOX_AZURE_OS_DISK_SKU", cfg.AzureOSDiskSKU)
	cfg.AzureVNet = getenv("CRABBOX_AZURE_VNET", cfg.AzureVNet)
	cfg.AzureSubnet = getenv("CRABBOX_AZURE_SUBNET", cfg.AzureSubnet)
	cfg.AzureNSG = getenv("CRABBOX_AZURE_NSG", cfg.AzureNSG)
	if cidrs := os.Getenv("CRABBOX_AZURE_SSH_CIDRS"); cidrs != "" {
		cfg.AzureSSHCIDRs = splitCommaList(cidrs)
	}
	cfg.AzureNetwork = getenv("CRABBOX_AZURE_NETWORK", cfg.AzureNetwork)
	if value := os.Getenv("CRABBOX_AZURE_DYNAMIC_SESSIONS_ENDPOINT"); value != "" {
		cfg.AzureDynamicSessions.Endpoint = value
		cfg.credentialProvenance.azSessionsEndpoint = credentialSourceEnvironment
	}
	cfg.AzureDynamicSessions.Pool = getenv("CRABBOX_AZURE_DYNAMIC_SESSIONS_POOL", cfg.AzureDynamicSessions.Pool)
	cfg.AzureDynamicSessions.APIVersion = getenv("CRABBOX_AZURE_DYNAMIC_SESSIONS_API_VERSION", cfg.AzureDynamicSessions.APIVersion)
	cfg.AzureDynamicSessions.Workdir = getenv("CRABBOX_AZURE_DYNAMIC_SESSIONS_WORKDIR", cfg.AzureDynamicSessions.Workdir)
	cfg.AzureDynamicSessions.TimeoutSecs = getenvInt("CRABBOX_AZURE_DYNAMIC_SESSIONS_TIMEOUT_SECS", cfg.AzureDynamicSessions.TimeoutSecs)
	if project := os.Getenv("CRABBOX_GCP_PROJECT"); project != "" {
		cfg.GCPProject = project
		cfg.gcpProjectExplicit = true
	} else if cfg.GCPProject == "" {
		if project := os.Getenv("GOOGLE_CLOUD_PROJECT"); project != "" {
			cfg.GCPProject = project
			cfg.gcpProjectExplicit = false
		} else if project := os.Getenv("GCP_PROJECT_ID"); project != "" {
			cfg.GCPProject = project
			cfg.gcpProjectExplicit = false
		}
	}
	if zone := os.Getenv("CRABBOX_GCP_ZONE"); zone != "" {
		cfg.GCPZone = zone
		cfg.gcpZoneExplicit = true
	}
	if image := os.Getenv("CRABBOX_GCP_IMAGE"); image != "" {
		cfg.GCPImage = image
		cfg.gcpImageExplicit = true
	}
	if network := os.Getenv("CRABBOX_GCP_NETWORK"); network != "" {
		cfg.GCPNetwork = network
		cfg.gcpNetworkExplicit = true
	}
	cfg.GCPSubnet = getenv("CRABBOX_GCP_SUBNET", cfg.GCPSubnet)
	if rootGB := os.Getenv("CRABBOX_GCP_ROOT_GB"); rootGB != "" {
		cfg.GCPRootGB = int64(getenvInt("CRABBOX_GCP_ROOT_GB", int(cfg.GCPRootGB)))
		cfg.gcpRootGBExplicit = true
	}
	cfg.GCPServiceAccount = getenv("CRABBOX_GCP_SERVICE_ACCOUNT", cfg.GCPServiceAccount)
	cfg.Incus.Remote = getenv("CRABBOX_INCUS_REMOTE", cfg.Incus.Remote)
	cfg.Incus.Project = getenv("CRABBOX_INCUS_PROJECT", cfg.Incus.Project)
	cfg.Incus.Address = getenv("CRABBOX_INCUS_ADDRESS", cfg.Incus.Address)
	cfg.Incus.Socket = expandUserPath(getenv("CRABBOX_INCUS_SOCKET", cfg.Incus.Socket))
	cfg.Incus.InstanceType = getenv("CRABBOX_INCUS_INSTANCE_TYPE", cfg.Incus.InstanceType)
	cfg.Incus.Image = getenv("CRABBOX_INCUS_IMAGE", cfg.Incus.Image)
	cfg.Incus.Profile = getenv("CRABBOX_INCUS_PROFILE", cfg.Incus.Profile)
	cfg.Incus.User = getenv("CRABBOX_INCUS_USER", cfg.Incus.User)
	cfg.Incus.WorkRoot = getenv("CRABBOX_INCUS_WORK_ROOT", cfg.Incus.WorkRoot)
	if value, ok := getenvBool("CRABBOX_INCUS_DELETE_ON_RELEASE"); ok {
		cfg.Incus.DeleteOnRelease = value
		MarkDeleteOnReleaseExplicit(cfg, "incus")
	}
	if timeout := os.Getenv("CRABBOX_INCUS_START_TIMEOUT"); timeout != "" {
		applyLeaseDuration(&cfg.Incus.StartTimeout, timeout)
	}
	cfg.Incus.LaunchPort = getenv("CRABBOX_INCUS_LAUNCH_PORT", cfg.Incus.LaunchPort)
	cfg.Incus.ProxyListenHost = getenv("CRABBOX_INCUS_PROXY_LISTEN_HOST", cfg.Incus.ProxyListenHost)
	cfg.Incus.ProxyListenPort = getenv("CRABBOX_INCUS_PROXY_LISTEN_PORT", cfg.Incus.ProxyListenPort)
	cfg.Incus.ProxyDevice = getenv("CRABBOX_INCUS_PROXY_DEVICE", cfg.Incus.ProxyDevice)
	cfg.Incus.TLSServerCert = expandUserPath(getenv("CRABBOX_INCUS_TLS_SERVER_CERT", cfg.Incus.TLSServerCert))
	if value, ok := getenvBool("CRABBOX_INCUS_INSECURE_TLS"); ok {
		cfg.Incus.InsecureTLS = value
	}
	cfg.Incus.RemoteImageServer = getenv("CRABBOX_INCUS_REMOTE_IMAGE_SERVER", cfg.Incus.RemoteImageServer)
	if tags := os.Getenv("CRABBOX_GCP_TAGS"); tags != "" {
		cfg.GCPTags = splitCommaList(tags)
		cfg.gcpTagsExplicit = true
	}
	if cidrs := os.Getenv("CRABBOX_GCP_SSH_CIDRS"); cidrs != "" {
		cfg.GCPSSHCIDRs = splitCommaList(cidrs)
	}
	cfg.DigitalOcean.Region = getenv("CRABBOX_DIGITALOCEAN_REGION", cfg.DigitalOcean.Region)
	if image := os.Getenv("CRABBOX_DIGITALOCEAN_IMAGE"); image != "" {
		cfg.DigitalOcean.Image = image
		cfg.digitalOceanImageExplicit = true
	}
	cfg.DigitalOcean.VPCUUID = getenv("CRABBOX_DIGITALOCEAN_VPC", cfg.DigitalOcean.VPCUUID)
	if cidrs := os.Getenv("CRABBOX_DIGITALOCEAN_SSH_CIDRS"); cidrs != "" {
		cfg.DigitalOcean.SSHCIDRs = splitCommaList(cidrs)
	}
	cfg.Vultr.Region = getenv("CRABBOX_VULTR_REGION", cfg.Vultr.Region)
	cfg.Vultr.OS = getenv("CRABBOX_VULTR_OS", cfg.Vultr.OS)
	cfg.Vultr.Image = getenv("CRABBOX_VULTR_IMAGE", cfg.Vultr.Image)
	cfg.Vultr.Snapshot = getenv("CRABBOX_VULTR_SNAPSHOT", cfg.Vultr.Snapshot)
	cfg.Vultr.FirewallGroup = getenv("CRABBOX_VULTR_FIREWALL_GROUP", cfg.Vultr.FirewallGroup)
	if vpcs := os.Getenv("CRABBOX_VULTR_VPC_IDS"); vpcs != "" {
		cfg.Vultr.VPCIDs = splitCommaList(vpcs)
	}
	if cidrs := os.Getenv("CRABBOX_VULTR_SSH_CIDRS"); cidrs != "" {
		cfg.Vultr.SSHCIDRs = splitCommaList(cidrs)
	}
	cfg.Vultr.UserScheme = getenv("CRABBOX_VULTR_USER_SCHEME", cfg.Vultr.UserScheme)
	cfg.Linode.Region = getenv("CRABBOX_LINODE_REGION", cfg.Linode.Region)
	if image := os.Getenv("CRABBOX_LINODE_IMAGE"); image != "" {
		cfg.Linode.Image = image
		cfg.linodeImageExplicit = true
	}
	if linodeType := os.Getenv("CRABBOX_LINODE_TYPE"); linodeType != "" {
		cfg.Linode.Type = linodeType
		cfg.linodeTypeExplicit = true
	}
	cfg.Linode.FirewallID = getenv("CRABBOX_LINODE_FIREWALL", cfg.Linode.FirewallID)
	if cidrs := os.Getenv("CRABBOX_LINODE_SSH_CIDRS"); cidrs != "" {
		cfg.Linode.SSHCIDRs = splitCommaList(cidrs)
	}
	cfg.GitHubCodespaces.APIURL = getenv("CRABBOX_GITHUB_CODESPACES_API_URL", cfg.GitHubCodespaces.APIURL)
	cfg.GitHubCodespaces.GHPath = expandUserPath(getenv("CRABBOX_GITHUB_CODESPACES_GH_PATH", cfg.GitHubCodespaces.GHPath))
	cfg.GitHubCodespaces.Repo = getenv("CRABBOX_GITHUB_CODESPACES_REPO", cfg.GitHubCodespaces.Repo)
	cfg.GitHubCodespaces.Ref = getenv("CRABBOX_GITHUB_CODESPACES_REF", cfg.GitHubCodespaces.Ref)
	cfg.GitHubCodespaces.Machine = getenv("CRABBOX_GITHUB_CODESPACES_MACHINE", cfg.GitHubCodespaces.Machine)
	cfg.GitHubCodespaces.DevcontainerPath = getenv("CRABBOX_GITHUB_CODESPACES_DEVCONTAINER_PATH", cfg.GitHubCodespaces.DevcontainerPath)
	cfg.GitHubCodespaces.WorkingDirectory = getenv("CRABBOX_GITHUB_CODESPACES_WORKING_DIRECTORY", cfg.GitHubCodespaces.WorkingDirectory)
	cfg.GitHubCodespaces.Geo = getenv("CRABBOX_GITHUB_CODESPACES_GEO", cfg.GitHubCodespaces.Geo)
	if idleTimeout := os.Getenv("CRABBOX_GITHUB_CODESPACES_IDLE_TIMEOUT"); idleTimeout != "" {
		applyLeaseDuration(&cfg.GitHubCodespaces.IdleTimeout, idleTimeout)
	}
	if retentionPeriod := os.Getenv("CRABBOX_GITHUB_CODESPACES_RETENTION_PERIOD"); retentionPeriod != "" {
		if applyNonNegativeLeaseDuration(&cfg.GitHubCodespaces.RetentionPeriod, retentionPeriod) {
			MarkGitHubCodespacesRetentionExplicit(cfg)
		}
	}
	if value, ok := getenvBool("CRABBOX_GITHUB_CODESPACES_DELETE_ON_RELEASE"); ok {
		cfg.GitHubCodespaces.DeleteOnRelease = value
		MarkDeleteOnReleaseExplicit(cfg, "github-codespaces")
	}
	cfg.GitHubCodespaces.WorkRoot = getenv("CRABBOX_GITHUB_CODESPACES_WORK_ROOT", cfg.GitHubCodespaces.WorkRoot)
	cfg.Lambda.Region = getenv("CRABBOX_LAMBDA_REGION", cfg.Lambda.Region)
	if lambdaType := os.Getenv("CRABBOX_LAMBDA_TYPE"); lambdaType != "" {
		cfg.Lambda.Type = lambdaType
		cfg.lambdaTypeExplicit = true
	}
	if image := os.Getenv("CRABBOX_LAMBDA_IMAGE"); image != "" {
		cfg.Lambda.Image = image
		cfg.lambdaImageExplicit = true
		cfg.Lambda.ImageFamily = ""
	}
	if imageFamily := os.Getenv("CRABBOX_LAMBDA_IMAGE_FAMILY"); imageFamily != "" {
		cfg.Lambda.ImageFamily = imageFamily
		cfg.lambdaImageFamilyExplicit = true
		cfg.Lambda.Image = ""
	}
	cfg.Lambda.FirewallRuleset = getenv("CRABBOX_LAMBDA_FIREWALL_RULESET", cfg.Lambda.FirewallRuleset)
	if cidrs := os.Getenv("CRABBOX_LAMBDA_SSH_CIDRS"); cidrs != "" {
		cfg.Lambda.SSHCIDRs = splitCommaList(cidrs)
	}
	if names := os.Getenv("CRABBOX_LAMBDA_FILESYSTEM_NAMES"); names != "" {
		cfg.Lambda.FilesystemNames = splitCommaList(names)
	}
	if mounts := os.Getenv("CRABBOX_LAMBDA_FILESYSTEM_MOUNTS"); mounts != "" {
		cfg.Lambda.FilesystemMounts = parseLambdaFilesystemMounts(mounts)
	}
	cfg.Nebius.CLI = getenv("CRABBOX_NEBIUS_CLI", cfg.Nebius.CLI)
	cfg.Nebius.Profile = getenv("CRABBOX_NEBIUS_PROFILE", cfg.Nebius.Profile)
	cfg.Nebius.ParentID = getenv("CRABBOX_NEBIUS_PARENT_ID", cfg.Nebius.ParentID)
	cfg.Nebius.SubnetID = getenv("CRABBOX_NEBIUS_SUBNET_ID", cfg.Nebius.SubnetID)
	cfg.Nebius.Platform = getenv("CRABBOX_NEBIUS_PLATFORM", cfg.Nebius.Platform)
	cfg.Nebius.Preset = getenv("CRABBOX_NEBIUS_PRESET", cfg.Nebius.Preset)
	cfg.Nebius.ImageFamily = getenv("CRABBOX_NEBIUS_IMAGE_FAMILY", cfg.Nebius.ImageFamily)
	cfg.Nebius.DiskType = getenv("CRABBOX_NEBIUS_DISK_TYPE", cfg.Nebius.DiskType)
	cfg.Nebius.DiskSizeGiB = getenvInt("CRABBOX_NEBIUS_DISK_SIZE_GIB", cfg.Nebius.DiskSizeGiB)
	cfg.Nebius.User = getenv("CRABBOX_NEBIUS_USER", cfg.Nebius.User)
	cfg.Nebius.PublicIP = getenv("CRABBOX_NEBIUS_PUBLIC_IP", cfg.Nebius.PublicIP)
	if groups := os.Getenv("CRABBOX_NEBIUS_SECURITY_GROUP_IDS"); groups != "" {
		cfg.Nebius.SecurityGroupIDs = splitCommaList(groups)
	}
	cfg.Nebius.ServiceAccountID = getenv("CRABBOX_NEBIUS_SERVICE_ACCOUNT_ID", cfg.Nebius.ServiceAccountID)
	cfg.Nebius.RecoveryPolicy = getenv("CRABBOX_NEBIUS_RECOVERY_POLICY", cfg.Nebius.RecoveryPolicy)
	cfg.OVH.Endpoint = getenv("OVH_ENDPOINT", cfg.OVH.Endpoint)
	cfg.OVH.ProjectID = getenv("CRABBOX_OVH_PROJECT_ID", cfg.OVH.ProjectID)
	cfg.OVH.Region = getenv("CRABBOX_OVH_REGION", cfg.OVH.Region)
	if image := os.Getenv("CRABBOX_OVH_IMAGE"); image != "" {
		cfg.OVH.Image = image
		cfg.ovhImageExplicit = true
	}
	cfg.OVH.Flavor = getenv("CRABBOX_OVH_FLAVOR", cfg.OVH.Flavor)
	if region := os.Getenv("CRABBOX_SCALEWAY_REGION"); region != "" {
		cfg.Scaleway.Region = region
		cfg.scalewayRegionExplicit = true
	}
	if zone := os.Getenv("CRABBOX_SCALEWAY_ZONE"); zone != "" {
		cfg.Scaleway.Zone = zone
		cfg.scalewayZoneExplicit = true
	}
	if image := os.Getenv("CRABBOX_SCALEWAY_IMAGE"); image != "" {
		cfg.Scaleway.Image = image
		cfg.scalewayImageExplicit = true
	}
	if serverType := os.Getenv("CRABBOX_SCALEWAY_TYPE"); serverType != "" {
		cfg.Scaleway.Type = serverType
		cfg.scalewayTypeExplicit = true
	}
	cfg.Scaleway.ProjectID = getenv("CRABBOX_SCALEWAY_PROJECT_ID", cfg.Scaleway.ProjectID)
	cfg.Scaleway.OrganizationID = getenv("CRABBOX_SCALEWAY_ORGANIZATION_ID", cfg.Scaleway.OrganizationID)
	cfg.Scaleway.SecurityGroup = getenv("CRABBOX_SCALEWAY_SECURITY_GROUP", cfg.Scaleway.SecurityGroup)
	if cidrs := os.Getenv("CRABBOX_SCALEWAY_SSH_CIDRS"); cidrs != "" {
		cfg.Scaleway.SSHCIDRs = splitCommaList(cidrs)
	}
	if region := os.Getenv("CRABBOX_TENCENTCLOUD_REGION"); region != "" {
		cfg.TencentCloud.Region = region
		cfg.tencentCloudRegionExplicit = true
	}
	if zone := os.Getenv("CRABBOX_TENCENTCLOUD_ZONE"); zone != "" {
		cfg.TencentCloud.Zone = zone
		cfg.tencentCloudZoneExplicit = true
	}
	if image := os.Getenv("CRABBOX_TENCENTCLOUD_IMAGE"); image != "" {
		cfg.TencentCloud.Image = image
		cfg.tencentCloudImageExplicit = true
	}
	if serverType := os.Getenv("CRABBOX_TENCENTCLOUD_TYPE"); serverType != "" {
		cfg.TencentCloud.Type = serverType
		cfg.tencentCloudTypeExplicit = true
	}
	cfg.TencentCloud.VPCID = getenv("CRABBOX_TENCENTCLOUD_VPC_ID", cfg.TencentCloud.VPCID)
	cfg.TencentCloud.SubnetID = getenv("CRABBOX_TENCENTCLOUD_SUBNET_ID", cfg.TencentCloud.SubnetID)
	cfg.TencentCloud.SecurityGroupID = getenv("CRABBOX_TENCENTCLOUD_SECURITY_GROUP_ID", cfg.TencentCloud.SecurityGroupID)
	if cidrs := os.Getenv("CRABBOX_TENCENTCLOUD_SSH_CIDRS"); cidrs != "" {
		cfg.TencentCloud.SSHCIDRs = splitCommaList(cidrs)
	}
	cfg.TencentCloud.RootGB = getenvInt64("CRABBOX_TENCENTCLOUD_ROOT_GB", cfg.TencentCloud.RootGB)
	cfg.TencentCloud.InternetChargeType = getenv("CRABBOX_TENCENTCLOUD_INTERNET_CHARGE_TYPE", cfg.TencentCloud.InternetChargeType)
	cfg.TencentCloud.InternetMaxBandwidthOut = getenvInt64("CRABBOX_TENCENTCLOUD_INTERNET_MAX_BANDWIDTH_OUT", cfg.TencentCloud.InternetMaxBandwidthOut)
	cfg.TencentCloud.APIEndpoint = getenv("CRABBOX_TENCENTCLOUD_API_ENDPOINT", cfg.TencentCloud.APIEndpoint)
	if value := os.Getenv("CRABBOX_PROXMOX_API_URL"); value != "" {
		cfg.Proxmox.APIURL = value
		cfg.credentialProvenance.proxmoxAPIURL = credentialSourceEnvironment
	}
	if value := os.Getenv("CRABBOX_PROXMOX_TOKEN_ID"); value != "" {
		cfg.Proxmox.TokenID = value
		cfg.credentialProvenance.proxmoxTokenID = credentialSourceEnvironment
	}
	if value := os.Getenv("CRABBOX_PROXMOX_TOKEN_SECRET"); value != "" {
		cfg.Proxmox.TokenSecret = value
		cfg.credentialProvenance.proxmoxTokenSecret = credentialSourceEnvironment
	}
	cfg.Proxmox.Node = getenv("CRABBOX_PROXMOX_NODE", cfg.Proxmox.Node)
	cfg.Proxmox.TemplateID = getenvInt("CRABBOX_PROXMOX_TEMPLATE_ID", cfg.Proxmox.TemplateID)
	cfg.Proxmox.Storage = getenv("CRABBOX_PROXMOX_STORAGE", cfg.Proxmox.Storage)
	cfg.Proxmox.Pool = getenv("CRABBOX_PROXMOX_POOL", cfg.Proxmox.Pool)
	cfg.Proxmox.Bridge = getenv("CRABBOX_PROXMOX_BRIDGE", cfg.Proxmox.Bridge)
	cfg.Proxmox.User = getenv("CRABBOX_PROXMOX_USER", cfg.Proxmox.User)
	cfg.Proxmox.WorkRoot = getenv("CRABBOX_PROXMOX_WORK_ROOT", cfg.Proxmox.WorkRoot)
	if value, ok := getenvBool("CRABBOX_PROXMOX_FULL_CLONE"); ok {
		cfg.Proxmox.FullClone = value
	}
	if value, ok := getenvBool("CRABBOX_PROXMOX_INSECURE_TLS"); ok {
		cfg.Proxmox.InsecureTLS = value
		cfg.credentialProvenance.proxmoxInsecureTLS = credentialSourceEnvironment
	}
	cfg.Firecracker.Binary = expandUserPath(getenv("CRABBOX_FIRECRACKER_BINARY", cfg.Firecracker.Binary))
	cfg.Firecracker.Jailer = expandUserPath(getenv("CRABBOX_FIRECRACKER_JAILER", cfg.Firecracker.Jailer))
	cfg.Firecracker.Kernel = expandUserPath(getenv("CRABBOX_FIRECRACKER_KERNEL", cfg.Firecracker.Kernel))
	cfg.Firecracker.RootFS = expandUserPath(getenv("CRABBOX_FIRECRACKER_ROOTFS", cfg.Firecracker.RootFS))
	cfg.Firecracker.User = getenv("CRABBOX_FIRECRACKER_USER", cfg.Firecracker.User)
	cfg.Firecracker.WorkRoot = getenv("CRABBOX_FIRECRACKER_WORK_ROOT", cfg.Firecracker.WorkRoot)
	cfg.Firecracker.CPUs = getenvInt("CRABBOX_FIRECRACKER_CPUS", cfg.Firecracker.CPUs)
	cfg.Firecracker.MemoryMiB = getenvInt("CRABBOX_FIRECRACKER_MEMORY_MIB", cfg.Firecracker.MemoryMiB)
	cfg.Firecracker.DiskMiB = getenvInt("CRABBOX_FIRECRACKER_DISK_MIB", cfg.Firecracker.DiskMiB)
	cfg.Firecracker.Network = getenv("CRABBOX_FIRECRACKER_NETWORK", cfg.Firecracker.Network)
	cfg.Firecracker.CNINetwork = getenv("CRABBOX_FIRECRACKER_CNI_NETWORK", cfg.Firecracker.CNINetwork)
	cfg.Firecracker.CNIConfDir = expandUserPath(getenv("CRABBOX_FIRECRACKER_CNI_CONF_DIR", cfg.Firecracker.CNIConfDir))
	cfg.Firecracker.CNIBinDir = expandUserPath(getenv("CRABBOX_FIRECRACKER_CNI_BIN_DIR", cfg.Firecracker.CNIBinDir))
	if timeout := os.Getenv("CRABBOX_FIRECRACKER_LAUNCH_TIMEOUT"); timeout != "" {
		applyLeaseDuration(&cfg.Firecracker.LaunchTimeout, timeout)
	}
	if value, ok := getenvBool("CRABBOX_FIRECRACKER_DELETE_ON_RELEASE"); ok {
		cfg.Firecracker.DeleteOnRelease = value
		MarkDeleteOnReleaseExplicit(cfg, "firecracker")
	}
	cfg.XCPNg.APIURL = getenv("CRABBOX_XCP_NG_API_URL", cfg.XCPNg.APIURL)
	cfg.XCPNg.Username = getenv("CRABBOX_XCP_NG_USERNAME", cfg.XCPNg.Username)
	cfg.XCPNg.Password = getenv("CRABBOX_XCP_NG_PASSWORD", cfg.XCPNg.Password)
	xcpNgTemplate, xcpNgTemplateUUID := os.Getenv("CRABBOX_XCP_NG_TEMPLATE"), os.Getenv("CRABBOX_XCP_NG_TEMPLATE_UUID")
	if xcpNgTemplate != "" {
		cfg.XCPNg.Template = xcpNgTemplate
		if xcpNgTemplateUUID == "" {
			cfg.XCPNg.TemplateUUID = ""
		}
	}
	if xcpNgTemplateUUID != "" {
		cfg.XCPNg.TemplateUUID = xcpNgTemplateUUID
		if xcpNgTemplate == "" {
			cfg.XCPNg.Template = ""
		}
	}
	xcpNgSR, xcpNgSRUUID := os.Getenv("CRABBOX_XCP_NG_SR"), os.Getenv("CRABBOX_XCP_NG_SR_UUID")
	if xcpNgSR != "" {
		cfg.XCPNg.SR = xcpNgSR
		if xcpNgSRUUID == "" {
			cfg.XCPNg.SRUUID = ""
		}
	}
	if xcpNgSRUUID != "" {
		cfg.XCPNg.SRUUID = xcpNgSRUUID
		if xcpNgSR == "" {
			cfg.XCPNg.SR = ""
		}
	}
	xcpNgNetwork, xcpNgNetworkUUID := os.Getenv("CRABBOX_XCP_NG_NETWORK"), os.Getenv("CRABBOX_XCP_NG_NETWORK_UUID")
	if xcpNgNetwork != "" {
		cfg.XCPNg.Network = xcpNgNetwork
		if xcpNgNetworkUUID == "" {
			cfg.XCPNg.NetworkUUID = ""
		}
	}
	if xcpNgNetworkUUID != "" {
		cfg.XCPNg.NetworkUUID = xcpNgNetworkUUID
		if xcpNgNetwork == "" {
			cfg.XCPNg.Network = ""
		}
	}
	cfg.XCPNg.Host = getenv("CRABBOX_XCP_NG_HOST", cfg.XCPNg.Host)
	cfg.XCPNg.User = getenv("CRABBOX_XCP_NG_USER", cfg.XCPNg.User)
	cfg.XCPNg.WorkRoot = getenv("CRABBOX_XCP_NG_WORK_ROOT", cfg.XCPNg.WorkRoot)
	if value, ok := getenvBool("CRABBOX_XCP_NG_INSECURE_TLS"); ok {
		cfg.XCPNg.InsecureTLS = value
	}
	cfg.Parallels.Source = getenv("CRABBOX_PARALLELS_SOURCE", cfg.Parallels.Source)
	cfg.Parallels.SourceID = getenv("CRABBOX_PARALLELS_SOURCE_ID", cfg.Parallels.SourceID)
	cfg.Parallels.SourceSnapshot = getenv("CRABBOX_PARALLELS_SOURCE_SNAPSHOT", cfg.Parallels.SourceSnapshot)
	cfg.Parallels.SourceSnapshotID = getenv("CRABBOX_PARALLELS_SOURCE_SNAPSHOT_ID", cfg.Parallels.SourceSnapshotID)
	cfg.Parallels.Template = getenv("CRABBOX_PARALLELS_TEMPLATE", cfg.Parallels.Template)
	cfg.Parallels.CloneMode = getenv("CRABBOX_PARALLELS_CLONE_MODE", cfg.Parallels.CloneMode)
	if value := os.Getenv("CRABBOX_PARALLELS_HOST"); value != "" {
		cfg.Parallels.Host = value
		cfg.Parallels.Hosts = nil
		cfg.Parallels.SelectedHost = ""
		cfg.credentialProvenance.parallelsHost = credentialSourceEnvironment
	}
	cfg.Parallels.HostUser = getenv("CRABBOX_PARALLELS_HOST_USER", cfg.Parallels.HostUser)
	if value := os.Getenv("CRABBOX_PARALLELS_HOST_KEY"); value != "" {
		cfg.Parallels.HostKey = expandUserPath(value)
		cfg.credentialProvenance.parallelsHostKey = credentialSourceEnvironment
	}
	cfg.Parallels.VMRoot = expandUserPath(getenv("CRABBOX_PARALLELS_VM_ROOT", cfg.Parallels.VMRoot))
	cfg.Parallels.User = getenv("CRABBOX_PARALLELS_USER", cfg.Parallels.User)
	cfg.Parallels.WorkRoot = getenv("CRABBOX_PARALLELS_WORK_ROOT", cfg.Parallels.WorkRoot)
	if startupTimeout := os.Getenv("CRABBOX_PARALLELS_STARTUP_TIMEOUT"); startupTimeout != "" {
		applyLeaseDuration(&cfg.Parallels.StartupTimeout, startupTimeout)
	}
	if sshUser := os.Getenv("CRABBOX_SSH_USER"); sshUser != "" {
		cfg.SSHUser = sshUser
		MarkSSHUserExplicit(cfg)
	}
	if sshKey := os.Getenv("CRABBOX_SSH_KEY"); sshKey != "" {
		cfg.SSHKey = sshKey
		MarkSSHKeyExplicit(cfg)
		cfg.credentialProvenance.sshKey = credentialSourceEnvironment
	}
	if sshPort := os.Getenv("CRABBOX_SSH_PORT"); sshPort != "" {
		cfg.SSHPort = sshPort
		MarkSSHPortExplicit(cfg)
	}
	if ports, ok := getenvList("CRABBOX_SSH_FALLBACK_PORTS"); ok {
		cfg.SSHFallbackPorts = ports
		cfg.sshFallbackPortsExplicit = true
		cfg.explicitSSHFallbackPorts = append([]string(nil), ports...)
	}
	cfg.ProviderKey = getenv("CRABBOX_HETZNER_SSH_KEY", cfg.ProviderKey)
	if workRoot := os.Getenv("CRABBOX_WORK_ROOT"); workRoot != "" {
		cfg.WorkRoot = workRoot
		cfg.explicitWorkRoot = workRoot
	}
	if ttl := os.Getenv("CRABBOX_TTL"); ttl != "" {
		applyLeaseDuration(&cfg.TTL, ttl)
	}
	if idleTimeout := os.Getenv("CRABBOX_IDLE_TIMEOUT"); idleTimeout != "" {
		applyLeaseDuration(&cfg.IdleTimeout, idleTimeout)
	}
	if market := os.Getenv("CRABBOX_CAPACITY_MARKET"); market != "" {
		cfg.Capacity.Market = market
		MarkCapacityMarketExplicit(cfg)
	}
	cfg.Capacity.Strategy = getenv("CRABBOX_CAPACITY_STRATEGY", cfg.Capacity.Strategy)
	cfg.Capacity.Fallback = getenv("CRABBOX_CAPACITY_FALLBACK", cfg.Capacity.Fallback)
	if value, ok := getenvBool("CRABBOX_CAPACITY_HINTS"); ok {
		cfg.Capacity.Hints = value
	}
	cfg.Actions.Workflow = getenv("CRABBOX_ACTIONS_WORKFLOW", cfg.Actions.Workflow)
	cfg.Actions.Job = getenv("CRABBOX_ACTIONS_JOB", cfg.Actions.Job)
	cfg.Actions.Ref = getenv("CRABBOX_ACTIONS_REF", cfg.Actions.Ref)
	cfg.Actions.Repo = getenv("CRABBOX_ACTIONS_REPO", cfg.Actions.Repo)
	cfg.Actions.RunnerVersion = getenv("CRABBOX_ACTIONS_RUNNER_VERSION", cfg.Actions.RunnerVersion)
	cfg.Blacksmith.Org = getenv("CRABBOX_BLACKSMITH_ORG", cfg.Blacksmith.Org)
	cfg.Blacksmith.Workflow = getenv("CRABBOX_BLACKSMITH_WORKFLOW", cfg.Blacksmith.Workflow)
	cfg.Blacksmith.Job = getenv("CRABBOX_BLACKSMITH_JOB", cfg.Blacksmith.Job)
	cfg.Blacksmith.Ref = getenv("CRABBOX_BLACKSMITH_REF", cfg.Blacksmith.Ref)
	cfg.KubeVirt.Kubectl = expandUserPath(getenv("CRABBOX_KUBEVIRT_KUBECTL", cfg.KubeVirt.Kubectl))
	cfg.KubeVirt.Virtctl = expandUserPath(getenv("CRABBOX_KUBEVIRT_VIRTCTL", cfg.KubeVirt.Virtctl))
	cfg.KubeVirt.Kubeconfig = expandUserPath(getenv("CRABBOX_KUBEVIRT_KUBECONFIG", cfg.KubeVirt.Kubeconfig))
	cfg.KubeVirt.Context = getenv("CRABBOX_KUBEVIRT_CONTEXT", cfg.KubeVirt.Context)
	cfg.KubeVirt.Namespace = getenv("CRABBOX_KUBEVIRT_NAMESPACE", cfg.KubeVirt.Namespace)
	cfg.KubeVirt.Template = expandUserPath(getenv("CRABBOX_KUBEVIRT_TEMPLATE", cfg.KubeVirt.Template))
	cfg.KubeVirt.SSHUser = getenv("CRABBOX_KUBEVIRT_SSH_USER", cfg.KubeVirt.SSHUser)
	cfg.KubeVirt.SSHKey = expandUserPath(getenv("CRABBOX_KUBEVIRT_SSH_KEY", cfg.KubeVirt.SSHKey))
	cfg.KubeVirt.SSHPublicKey = expandUserPath(getenv("CRABBOX_KUBEVIRT_SSH_PUBLIC_KEY", cfg.KubeVirt.SSHPublicKey))
	cfg.KubeVirt.SSHPort = getenv("CRABBOX_KUBEVIRT_SSH_PORT", cfg.KubeVirt.SSHPort)
	cfg.KubeVirt.WorkRoot = getenv("CRABBOX_KUBEVIRT_WORK_ROOT", cfg.KubeVirt.WorkRoot)
	if value, ok := getenvBool("CRABBOX_KUBEVIRT_DELETE_ON_RELEASE"); ok {
		cfg.KubeVirt.DeleteOnRelease = value
		MarkDeleteOnReleaseExplicit(cfg, "kubevirt")
	}
	cfg.SealosDevbox.Kubectl = expandUserPath(getenv("CRABBOX_SEALOS_DEVBOX_KUBECTL", cfg.SealosDevbox.Kubectl))
	cfg.SealosDevbox.Kubeconfig = expandUserPath(getenv("CRABBOX_SEALOS_DEVBOX_KUBECONFIG", cfg.SealosDevbox.Kubeconfig))
	cfg.SealosDevbox.Context = getenv("CRABBOX_SEALOS_DEVBOX_CONTEXT", cfg.SealosDevbox.Context)
	cfg.SealosDevbox.Namespace = getenv("CRABBOX_SEALOS_DEVBOX_NAMESPACE", cfg.SealosDevbox.Namespace)
	cfg.SealosDevbox.Image = getenv("CRABBOX_SEALOS_DEVBOX_IMAGE", cfg.SealosDevbox.Image)
	cfg.SealosDevbox.TemplateID = getenv("CRABBOX_SEALOS_DEVBOX_TEMPLATE_ID", cfg.SealosDevbox.TemplateID)
	cfg.SealosDevbox.CPU = getenv("CRABBOX_SEALOS_DEVBOX_CPU", cfg.SealosDevbox.CPU)
	cfg.SealosDevbox.Memory = getenv("CRABBOX_SEALOS_DEVBOX_MEMORY", cfg.SealosDevbox.Memory)
	cfg.SealosDevbox.StorageLimit = getenv("CRABBOX_SEALOS_DEVBOX_STORAGE_LIMIT", cfg.SealosDevbox.StorageLimit)
	cfg.SealosDevbox.Network = getenv("CRABBOX_SEALOS_DEVBOX_NETWORK", cfg.SealosDevbox.Network)
	cfg.SealosDevbox.SSHGatewayHost = getenv("CRABBOX_SEALOS_DEVBOX_SSH_GATEWAY_HOST", cfg.SealosDevbox.SSHGatewayHost)
	cfg.SealosDevbox.SSHGatewayPort = getenv("CRABBOX_SEALOS_DEVBOX_SSH_GATEWAY_PORT", cfg.SealosDevbox.SSHGatewayPort)
	cfg.SealosDevbox.SSHUser = getenv("CRABBOX_SEALOS_DEVBOX_SSH_USER", cfg.SealosDevbox.SSHUser)
	if value := os.Getenv("CRABBOX_SEALOS_DEVBOX_WORK_ROOT"); value != "" {
		cfg.SealosDevbox.WorkRoot = value
		MarkSealosDevboxWorkRootExplicit(cfg)
	}
	cfg.SealosDevbox.NodeHost = getenv("CRABBOX_SEALOS_DEVBOX_NODE_HOST", cfg.SealosDevbox.NodeHost)
	if value, ok := getenvBool("CRABBOX_SEALOS_DEVBOX_DELETE_ON_RELEASE"); ok {
		cfg.SealosDevbox.DeleteOnRelease = value
		MarkDeleteOnReleaseExplicit(cfg, "sealos-devbox")
	}
	cfg.AgentSandbox.Kubectl = getenv("CRABBOX_AGENT_SANDBOX_KUBECTL", cfg.AgentSandbox.Kubectl)
	cfg.AgentSandbox.Kubeconfig = expandUserPath(getenv("CRABBOX_AGENT_SANDBOX_KUBECONFIG", cfg.AgentSandbox.Kubeconfig))
	cfg.AgentSandbox.Context = getenv("CRABBOX_AGENT_SANDBOX_CONTEXT", cfg.AgentSandbox.Context)
	cfg.AgentSandbox.Namespace = getenv("CRABBOX_AGENT_SANDBOX_NAMESPACE", cfg.AgentSandbox.Namespace)
	cfg.AgentSandbox.WarmPool = getenv("CRABBOX_AGENT_SANDBOX_WARM_POOL", cfg.AgentSandbox.WarmPool)
	cfg.AgentSandbox.Container = getenv("CRABBOX_AGENT_SANDBOX_CONTAINER", cfg.AgentSandbox.Container)
	cfg.AgentSandbox.Workdir = getenv("CRABBOX_AGENT_SANDBOX_WORKDIR", cfg.AgentSandbox.Workdir)
	if timeout := os.Getenv("CRABBOX_AGENT_SANDBOX_SANDBOX_READY_TIMEOUT"); timeout != "" {
		applyLeaseDuration(&cfg.AgentSandbox.SandboxReadyTimeout, timeout)
	}
	if timeout := os.Getenv("CRABBOX_AGENT_SANDBOX_POD_READY_TIMEOUT"); timeout != "" {
		applyLeaseDuration(&cfg.AgentSandbox.PodReadyTimeout, timeout)
	}
	var agentSandboxEnvErr error
	cfg.AgentSandbox.ExecTimeoutSecs, agentSandboxEnvErr = getenvNonNegativeInt("CRABBOX_AGENT_SANDBOX_EXEC_TIMEOUT_SECS", cfg.AgentSandbox.ExecTimeoutSecs)
	if agentSandboxEnvErr != nil {
		return agentSandboxEnvErr
	}
	if value, ok := getenvBool("CRABBOX_AGENT_SANDBOX_DELETE_ON_RELEASE"); ok {
		cfg.AgentSandbox.DeleteOnRelease = value
		MarkDeleteOnReleaseExplicit(cfg, "agent-sandbox")
	}
	if value, ok := getenvBool("CRABBOX_AGENT_SANDBOX_FORGET_MISSING"); ok {
		cfg.AgentSandbox.ForgetMissing = value
	}
	externalProviderOutputExplicit := false
	if value := os.Getenv("CRABBOX_EXTERNAL_COMMAND"); value != "" {
		cfg.External.Command = value
		externalProviderOutputExplicit = true
	}
	if arg := os.Getenv("CRABBOX_EXTERNAL_ARG"); arg != "" {
		cfg.External.Args = []string{arg}
		externalProviderOutputExplicit = true
	}
	if externalProviderOutputExplicit {
		markExternalProviderOutputExplicit(cfg, credentialSourceEnvironment)
	}
	cfg.External.WorkRoot = getenv("CRABBOX_EXTERNAL_WORK_ROOT", cfg.External.WorkRoot)
	if value := os.Getenv("CRABBOX_EXTERNAL_ROUTING_FILE"); value != "" {
		cfg.External.RoutingFile = value
		cfg.credentialProvenance.externalRouting = credentialSourceEnvironment
	}
	ApplyExternalDesktopEnvironmentOverrides(cfg)
	if value, ok := getenvBool("CRABBOX_EXTERNAL_IDEMPOTENT_LEASE_ID"); ok {
		cfg.External.Capabilities.IdempotentLeaseID = value
	}
	cfg.Namespace.Image = getenv("CRABBOX_NAMESPACE_IMAGE", cfg.Namespace.Image)
	cfg.Namespace.Size = getenv("CRABBOX_NAMESPACE_SIZE", cfg.Namespace.Size)
	cfg.Namespace.Repository = getenv("CRABBOX_NAMESPACE_REPOSITORY", cfg.Namespace.Repository)
	cfg.Namespace.Site = getenv("CRABBOX_NAMESPACE_SITE", cfg.Namespace.Site)
	cfg.Namespace.VolumeSizeGB = getenvInt("CRABBOX_NAMESPACE_VOLUME_SIZE_GB", cfg.Namespace.VolumeSizeGB)
	if idleTimeout := os.Getenv("CRABBOX_NAMESPACE_AUTO_STOP_IDLE_TIMEOUT"); idleTimeout != "" {
		applyLeaseDuration(&cfg.Namespace.AutoStopIdleTimeout, idleTimeout)
	}
	cfg.Namespace.WorkRoot = getenv("CRABBOX_NAMESPACE_WORK_ROOT", cfg.Namespace.WorkRoot)
	if value, ok := getenvBool("CRABBOX_NAMESPACE_DELETE_ON_RELEASE"); ok {
		cfg.Namespace.DeleteOnRelease = value
		MarkDeleteOnReleaseExplicit(cfg, "namespace-devbox")
	}
	cfg.NamespaceInstance.CLIPath = expandUserPath(getenv("CRABBOX_NAMESPACE_INSTANCE_CLI", cfg.NamespaceInstance.CLIPath))
	cfg.NamespaceInstance.MachineType = getenv("CRABBOX_NAMESPACE_INSTANCE_MACHINE_TYPE", cfg.NamespaceInstance.MachineType)
	if duration := os.Getenv("CRABBOX_NAMESPACE_INSTANCE_DURATION"); duration != "" {
		applyLeaseDuration(&cfg.NamespaceInstance.Duration, duration)
	}
	cfg.NamespaceInstance.Region = getenv("CRABBOX_NAMESPACE_INSTANCE_REGION", cfg.NamespaceInstance.Region)
	cfg.NamespaceInstance.Endpoint = getenv("CRABBOX_NAMESPACE_INSTANCE_ENDPOINT", cfg.NamespaceInstance.Endpoint)
	cfg.NamespaceInstance.Keychain = getenv("CRABBOX_NAMESPACE_INSTANCE_KEYCHAIN", cfg.NamespaceInstance.Keychain)
	if volumes, ok := getenvList("CRABBOX_NAMESPACE_INSTANCE_VOLUMES"); ok {
		cfg.NamespaceInstance.Volumes = volumes
	}
	cfg.NamespaceInstance.WorkRoot = getenv("CRABBOX_NAMESPACE_INSTANCE_WORK_ROOT", cfg.NamespaceInstance.WorkRoot)
	if value, ok := getenvBool("CRABBOX_NAMESPACE_INSTANCE_BARE"); ok {
		cfg.NamespaceInstance.Bare = value
	}
	cfg.Phala.CLIPath = expandUserPath(getenv("CRABBOX_PHALA_CLI", cfg.Phala.CLIPath))
	if value := os.Getenv("CRABBOX_PHALA_INSTANCE_TYPE"); value != "" {
		cfg.Phala.InstanceType = value
		MarkPhalaInstanceTypeExplicit(cfg)
	}
	cfg.Phala.WorkRoot = getenv("CRABBOX_PHALA_WORK_ROOT", cfg.Phala.WorkRoot)
	cfg.Phala.NodeID = getenv("CRABBOX_PHALA_NODE_ID", cfg.Phala.NodeID)
	cfg.Phala.Compose = expandUserPath(getenv("CRABBOX_PHALA_COMPOSE", cfg.Phala.Compose))
	if value, ok := getenvBool("CRABBOX_PHALA_ATTEST"); ok {
		cfg.Phala.Attest = &value
	}
	if value, ok := firstNonEmptyEnv("CRABBOX_MORPH_API_KEY", "MORPH_API_KEY"); ok {
		cfg.Morph.APIKey = value
		cfg.credentialProvenance.morphAPIKey = credentialSourceEnvironment
	}
	if value := os.Getenv("CRABBOX_MORPH_API_URL"); value != "" {
		cfg.Morph.APIURL = value
		cfg.credentialProvenance.morphAPIURL = credentialSourceEnvironment
	}
	if value, ok := os.LookupEnv("CRABBOX_BOXD_API_URL"); ok {
		cfg.Boxd.APIURL = value
	}
	if value, ok := os.LookupEnv("CRABBOX_BOXD_ORG"); ok {
		cfg.Boxd.Org = value
	}
	if value := os.Getenv("CRABBOX_BOXD_WORK_ROOT"); value != "" {
		cfg.Boxd.WorkRoot = value
		MarkBoxdWorkRootExplicit(cfg)
	}
	if value, ok := getenvBool("CRABBOX_BOXD_DELETE_ON_RELEASE"); ok {
		cfg.Boxd.DeleteOnRelease = value
		MarkDeleteOnReleaseExplicit(cfg, "boxd")
	}
	cfg.Coder.CLIPath = expandUserPath(getenv("CRABBOX_CODER_CLI", cfg.Coder.CLIPath))
	cfg.Coder.Template = getenv("CRABBOX_CODER_TEMPLATE", cfg.Coder.Template)
	cfg.Coder.Preset = getenv("CRABBOX_CODER_PRESET", cfg.Coder.Preset)
	cfg.Coder.WorkspacePrefix = getenv("CRABBOX_CODER_WORKSPACE_PREFIX", cfg.Coder.WorkspacePrefix)
	cfg.Coder.WorkRoot = getenv("CRABBOX_CODER_WORK_ROOT", cfg.Coder.WorkRoot)
	if value, ok := getenvBool("CRABBOX_CODER_DELETE_ON_RELEASE"); ok {
		cfg.Coder.DeleteOnRelease = value
	}
	cfg.Coder.Wait = getenv("CRABBOX_CODER_WAIT", cfg.Coder.Wait)
	if value, ok := getenvBool("CRABBOX_CODER_USE_PARAMETER_DEFAULTS"); ok {
		cfg.Coder.UseParameterDefaults = value
	}
	if paramsEnv := os.Getenv("CRABBOX_CODER_PARAMETERS"); strings.TrimSpace(paramsEnv) != "" {
		params := splitCommaList(paramsEnv)
		if strings.EqualFold(strings.TrimSpace(paramsEnv), "none") {
			params = []string{}
		}
		cfg.Coder.Parameters = params
	}
	cfg.Coder.RichParameterFile = expandUserPath(getenv("CRABBOX_CODER_RICH_PARAMETER_FILE", cfg.Coder.RichParameterFile))
	cfg.Morph.Snapshot = getenv("CRABBOX_MORPH_SNAPSHOT", cfg.Morph.Snapshot)
	if value := os.Getenv("CRABBOX_MORPH_SSH_GATEWAY_HOST"); value != "" {
		cfg.Morph.SSHGatewayHost = value
		cfg.credentialProvenance.morphSSHGatewayHost = credentialSourceEnvironment
	}
	cfg.Morph.WorkRoot = getenv("CRABBOX_MORPH_WORK_ROOT", cfg.Morph.WorkRoot)
	if value, ok := getenvBool("CRABBOX_MORPH_DELETE_ON_RELEASE"); ok {
		cfg.Morph.DeleteOnRelease = value
		MarkDeleteOnReleaseExplicit(cfg, "morph")
	}
	if value, ok := getenvBool("CRABBOX_MORPH_WAKE_ON_SSH"); ok {
		cfg.Morph.WakeOnSSH = value
	}
	if value, ok := firstNonEmptyEnv("CRABBOX_DAYTONA_API_KEY", "DAYTONA_API_KEY"); ok {
		cfg.Daytona.APIKey = value
		cfg.credentialProvenance.daytonaAPIKey = credentialSourceEnvironment
	}
	if value, ok := firstNonEmptyEnv("CRABBOX_DAYTONA_JWT_TOKEN", "DAYTONA_JWT_TOKEN"); ok {
		cfg.Daytona.JWTToken = value
		cfg.credentialProvenance.daytonaJWTToken = credentialSourceEnvironment
	}
	cfg.Daytona.OrganizationID = getenv("CRABBOX_DAYTONA_ORGANIZATION_ID", getenv("DAYTONA_ORGANIZATION_ID", cfg.Daytona.OrganizationID))
	if value, ok := firstNonEmptyEnv("CRABBOX_DAYTONA_API_URL", "DAYTONA_API_URL"); ok {
		cfg.Daytona.APIURL = value
		cfg.credentialProvenance.daytonaAPIURL = credentialSourceEnvironment
	}
	cfg.Daytona.Snapshot = getenv("CRABBOX_DAYTONA_SNAPSHOT", getenv("DAYTONA_SNAPSHOT", cfg.Daytona.Snapshot))
	cfg.Daytona.Target = getenv("CRABBOX_DAYTONA_TARGET", getenv("DAYTONA_TARGET", cfg.Daytona.Target))
	cfg.Daytona.User = getenv("CRABBOX_DAYTONA_USER", cfg.Daytona.User)
	cfg.Daytona.WorkRoot = getenv("CRABBOX_DAYTONA_WORK_ROOT", cfg.Daytona.WorkRoot)
	if value := os.Getenv("CRABBOX_DAYTONA_SSH_GATEWAY_HOST"); value != "" {
		cfg.Daytona.SSHGatewayHost = value
		cfg.credentialProvenance.daytonaSSHGateway = credentialSourceEnvironment
	}
	cfg.Daytona.SSHAccessMinutes = getenvInt("CRABBOX_DAYTONA_SSH_ACCESS_MINUTES", cfg.Daytona.SSHAccessMinutes)
	if value, ok := firstNonEmptyEnv("CRABBOX_E2B_API_KEY", "E2B_API_KEY"); ok {
		cfg.E2B.APIKey = value
		cfg.credentialProvenance.e2bAPIKey = credentialSourceEnvironment
	}
	if value, ok := firstNonEmptyEnv("CRABBOX_E2B_API_URL", "E2B_API_URL"); ok {
		cfg.E2B.APIURL = value
		cfg.credentialProvenance.e2bAPIURL = credentialSourceEnvironment
	}
	if value, ok := firstNonEmptyEnv("CRABBOX_E2B_DOMAIN", "E2B_DOMAIN"); ok {
		cfg.E2B.Domain = value
		cfg.credentialProvenance.e2bDomain = credentialSourceEnvironment
	}
	cfg.E2B.Template = getenv("CRABBOX_E2B_TEMPLATE", cfg.E2B.Template)
	cfg.E2B.Workdir = getenv("CRABBOX_E2B_WORKDIR", cfg.E2B.Workdir)
	cfg.E2B.User = getenv("CRABBOX_E2B_USER", cfg.E2B.User)
	if value, ok := firstNonEmptyEnv("CRABBOX_CUBESANDBOX_API_KEY", "CUBE_API_KEY", "E2B_API_KEY"); ok {
		cfg.CubeSandbox.APIKey = value
	}
	if value, ok := firstNonEmptyEnv("CRABBOX_CUBESANDBOX_API_URL", "CUBE_API_URL", "E2B_API_URL"); ok {
		cfg.CubeSandbox.APIURL = value
		cfg.credentialProvenance.cubeSandboxAPIURL = credentialSourceEnvironment
	}
	if value, ok := firstNonEmptyEnv("CRABBOX_CUBESANDBOX_DOMAIN", "CUBE_SANDBOX_DOMAIN"); ok {
		cfg.CubeSandbox.Domain = value
		cfg.credentialProvenance.cubeSandboxDomain = credentialSourceEnvironment
	}
	cfg.CubeSandbox.Template = getenv("CRABBOX_CUBESANDBOX_TEMPLATE", getenv("CUBE_TEMPLATE_ID", cfg.CubeSandbox.Template))
	cfg.CubeSandbox.Workdir = getenv("CRABBOX_CUBESANDBOX_WORKDIR", cfg.CubeSandbox.Workdir)
	cfg.CubeSandbox.User = getenv("CRABBOX_CUBESANDBOX_USER", cfg.CubeSandbox.User)
	if value, ok := firstNonEmptyEnv("CRABBOX_CUBESANDBOX_PROXY_NODE_IP", "CUBE_PROXY_NODE_IP"); ok {
		cfg.CubeSandbox.ProxyNodeIP = value
		cfg.credentialProvenance.cubeSandboxProxyNode = credentialSourceEnvironment
	}
	if value, ok := firstNonEmptyEnv("CRABBOX_CUBESANDBOX_PROXY_PORT_HTTP", "CUBE_PROXY_PORT_HTTP"); ok {
		port, err := strconv.Atoi(value)
		if err != nil {
			return exit(2, "invalid cubesandbox proxy HTTP port %q", value)
		}
		cfg.CubeSandbox.ProxyPortHTTP = port
		cfg.credentialProvenance.cubeSandboxProxyPort = credentialSourceEnvironment
	}
	if value, ok := firstNonEmptyEnv("CRABBOX_CUBESANDBOX_PROXY_SCHEME", "CUBE_PROXY_SCHEME"); ok {
		cfg.CubeSandbox.ProxyScheme = value
		cfg.credentialProvenance.cubeSandboxProxyProto = credentialSourceEnvironment
	}
	if value, ok := firstNonEmptyEnv("CRABBOX_EXE_DEV_CONTROL_HOST", "EXE_DEV_CONTROL_HOST"); ok {
		cfg.ExeDev.ControlHost = value
		cfg.credentialProvenance.exeDevControlHost = credentialSourceEnvironment
	}
	cfg.ExeDev.Image = getenv("CRABBOX_EXE_DEV_IMAGE", getenv("EXE_DEV_IMAGE", cfg.ExeDev.Image))
	cfg.ExeDev.CPUs = getenvInt("CRABBOX_EXE_DEV_CPUS", cfg.ExeDev.CPUs)
	cfg.ExeDev.Memory = getenv("CRABBOX_EXE_DEV_MEMORY", getenv("EXE_DEV_MEMORY", cfg.ExeDev.Memory))
	cfg.ExeDev.Disk = getenv("CRABBOX_EXE_DEV_DISK", getenv("EXE_DEV_DISK", cfg.ExeDev.Disk))
	cfg.ExeDev.Command = getenv("CRABBOX_EXE_DEV_COMMAND", cfg.ExeDev.Command)
	cfg.ExeDev.User = getenv("CRABBOX_EXE_DEV_USER", cfg.ExeDev.User)
	cfg.ExeDev.WorkRoot = getenv("CRABBOX_EXE_DEV_WORK_ROOT", cfg.ExeDev.WorkRoot)
	if value, ok := getenvBool("CRABBOX_EXE_DEV_NO_EMAIL"); ok {
		cfg.ExeDev.NoEmail = value
	}
	if value, ok := firstNonEmptyEnv("CRABBOX_RAILWAY_API_TOKEN", "RAILWAY_API_TOKEN"); ok {
		cfg.Railway.APIToken = value
		cfg.credentialProvenance.railwayAPIToken = credentialSourceEnvironment
	}
	if value, ok := firstNonEmptyEnv("CRABBOX_RAILWAY_API_URL", "RAILWAY_API_URL"); ok {
		cfg.Railway.APIURL = value
		cfg.credentialProvenance.railwayAPIURL = credentialSourceEnvironment
	}
	cfg.Railway.ProjectID = getenv("CRABBOX_RAILWAY_PROJECT_ID", getenv("RAILWAY_PROJECT_ID", cfg.Railway.ProjectID))
	cfg.Railway.EnvironmentID = getenv("CRABBOX_RAILWAY_ENVIRONMENT_ID", getenv("RAILWAY_ENVIRONMENT_ID", cfg.Railway.EnvironmentID))
	if value, ok := firstNonEmptyEnv("CRABBOX_FASTAPI_CLOUD_TOKEN", "FASTAPI_CLOUD_TOKEN"); ok {
		cfg.FastAPICloud.Token = value
		cfg.credentialProvenance.fastAPICloudToken = credentialSourceEnvironment
	}
	if value, ok := firstNonEmptyEnv("CRABBOX_FASTAPI_CLOUD_API_URL", "FASTAPI_CLOUD_API_URL"); ok {
		cfg.FastAPICloud.APIURL = value
		cfg.credentialProvenance.fastAPICloudAPIURL = credentialSourceEnvironment
	}
	cfg.FastAPICloud.AppID = getenv("CRABBOX_FASTAPI_CLOUD_APP_ID", getenv("FASTAPI_CLOUD_APP_ID", cfg.FastAPICloud.AppID))
	cfg.FastAPICloud.TeamID = getenv("CRABBOX_FASTAPI_CLOUD_TEAM_ID", getenv("FASTAPI_CLOUD_TEAM_ID", cfg.FastAPICloud.TeamID))
	if value, ok := firstNonEmptyEnv("CRABBOX_UNIKRAFT_CLOUD_API_KEY", "UNIKRAFT_CLOUD_API_KEY", "UKC_API_KEY", "UKC_TOKEN"); ok {
		cfg.UnikraftCloud.APIKey = value
		cfg.credentialProvenance.unikraftCloudAPIKey = credentialSourceEnvironment
	}
	if value, ok := firstNonEmptyEnv("CRABBOX_UNIKRAFT_CLOUD_API_URL", "UNIKRAFT_CLOUD_API_URL"); ok {
		cfg.UnikraftCloud.APIURL = value
		cfg.credentialProvenance.unikraftCloudAPIURL = credentialSourceEnvironment
	}
	cfg.UnikraftCloud.Metro = getenv("CRABBOX_UNIKRAFT_CLOUD_METRO", getenv("UNIKRAFT_CLOUD_METRO", getenv("UKC_METRO", cfg.UnikraftCloud.Metro)))
	cfg.UnikraftCloud.Image = getenv("CRABBOX_UNIKRAFT_CLOUD_IMAGE", getenv("UNIKRAFT_CLOUD_IMAGE", cfg.UnikraftCloud.Image))
	if value, ok := firstNonEmptyEnv("CRABBOX_RUNPOD_API_KEY", "RUNPOD_API_KEY"); ok {
		cfg.Runpod.APIKey = value
		cfg.credentialProvenance.runpodAPIKey = credentialSourceEnvironment
	}
	if value, ok := firstNonEmptyEnv("CRABBOX_RUNPOD_API_URL", "RUNPOD_API_URL"); ok {
		cfg.Runpod.APIURL = value
		cfg.credentialProvenance.runpodAPIURL = credentialSourceEnvironment
	}
	cfg.Runpod.CloudType = getenv("CRABBOX_RUNPOD_CLOUD_TYPE", getenv("RUNPOD_CLOUD_TYPE", cfg.Runpod.CloudType))
	cfg.Runpod.InstanceID = getenv("CRABBOX_RUNPOD_INSTANCE_ID", getenv("RUNPOD_INSTANCE_ID", cfg.Runpod.InstanceID))
	cfg.Runpod.Image = getenv("CRABBOX_RUNPOD_IMAGE", getenv("RUNPOD_IMAGE", cfg.Runpod.Image))
	cfg.Runpod.TemplateID = getenv("CRABBOX_RUNPOD_TEMPLATE_ID", getenv("RUNPOD_TEMPLATE_ID", cfg.Runpod.TemplateID))
	cfg.Runpod.DiskGB = getenvInt("CRABBOX_RUNPOD_DISK_GB", cfg.Runpod.DiskGB)
	cfg.Runpod.User = getenv("CRABBOX_RUNPOD_USER", cfg.Runpod.User)
	cfg.Runpod.WorkRoot = getenv("CRABBOX_RUNPOD_WORK_ROOT", cfg.Runpod.WorkRoot)
	if value, ok := firstNonEmptyEnv("CRABBOX_VAST_API_KEY", "VAST_API_KEY"); ok {
		cfg.Vast.APIKey = value
		cfg.credentialProvenance.vastAPIKey = credentialSourceEnvironment
	}
	if value, ok := firstNonEmptyEnv("CRABBOX_VAST_API_URL", "VAST_API_URL"); ok {
		cfg.Vast.APIURL = value
		cfg.credentialProvenance.vastAPIURL = credentialSourceEnvironment
	}
	cfg.Vast.InstanceType = getenv("CRABBOX_VAST_INSTANCE_TYPE", cfg.Vast.InstanceType)
	cfg.Vast.GPUName = getenv("CRABBOX_VAST_GPU_NAME", cfg.Vast.GPUName)
	cfg.Vast.GPUCount = getenvInt("CRABBOX_VAST_GPU_COUNT", cfg.Vast.GPUCount)
	cfg.Vast.Image = getenv("CRABBOX_VAST_IMAGE", cfg.Vast.Image)
	cfg.Vast.TemplateID = getenv("CRABBOX_VAST_TEMPLATE_ID", cfg.Vast.TemplateID)
	cfg.Vast.Runtype = getenv("CRABBOX_VAST_RUNTYPE", cfg.Vast.Runtype)
	cfg.Vast.DiskGB = getenvInt("CRABBOX_VAST_DISK_GB", cfg.Vast.DiskGB)
	cfg.Vast.MaxDphTotal = getenvFloat("CRABBOX_VAST_MAX_DPH_TOTAL", cfg.Vast.MaxDphTotal)
	cfg.Vast.MinReliability = getenvFloat("CRABBOX_VAST_MIN_RELIABILITY", cfg.Vast.MinReliability)
	cfg.Vast.Order = getenv("CRABBOX_VAST_ORDER", cfg.Vast.Order)
	cfg.Vast.User = getenv("CRABBOX_VAST_USER", cfg.Vast.User)
	if value := os.Getenv("CRABBOX_VAST_WORK_ROOT"); value != "" {
		cfg.Vast.WorkRoot = value
		MarkVastWorkRootExplicit(cfg)
	}
	if value := os.Getenv("CRABBOX_VAST_RELEASE_ACTION"); value != "" {
		cfg.Vast.ReleaseAction = value
		MarkDeleteOnReleaseExplicit(cfg, "vast")
	}
	cfg.NvidiaBrev.CLI = getenv("CRABBOX_NVIDIA_BREV_CLI", cfg.NvidiaBrev.CLI)
	cfg.NvidiaBrev.Org = getenv("CRABBOX_NVIDIA_BREV_ORG", cfg.NvidiaBrev.Org)
	cfg.NvidiaBrev.Type = getenv("CRABBOX_NVIDIA_BREV_TYPE", cfg.NvidiaBrev.Type)
	cfg.NvidiaBrev.GPUName = getenv("CRABBOX_NVIDIA_BREV_GPU_NAME", cfg.NvidiaBrev.GPUName)
	cfg.NvidiaBrev.Provider = getenv("CRABBOX_NVIDIA_BREV_PROVIDER", cfg.NvidiaBrev.Provider)
	cfg.NvidiaBrev.Mode = getenv("CRABBOX_NVIDIA_BREV_MODE", cfg.NvidiaBrev.Mode)
	cfg.NvidiaBrev.Launchable = getenv("CRABBOX_NVIDIA_BREV_LAUNCHABLE", cfg.NvidiaBrev.Launchable)
	cfg.NvidiaBrev.StartupScript = getenv("CRABBOX_NVIDIA_BREV_STARTUP_SCRIPT", cfg.NvidiaBrev.StartupScript)
	if value := os.Getenv("CRABBOX_NVIDIA_BREV_RELEASE_ACTION"); value != "" {
		cfg.NvidiaBrev.ReleaseAction = value
		MarkDeleteOnReleaseExplicit(cfg, "nvidia-brev")
	}
	cfg.NvidiaBrev.Target = getenv("CRABBOX_NVIDIA_BREV_TARGET", cfg.NvidiaBrev.Target)
	cfg.NvidiaBrev.User = getenv("CRABBOX_NVIDIA_BREV_USER", cfg.NvidiaBrev.User)
	if value := os.Getenv("CRABBOX_NVIDIA_BREV_WORK_ROOT"); value != "" {
		cfg.NvidiaBrev.WorkRoot = value
		MarkNvidiaBrevWorkRootExplicit(cfg)
	}
	cfg.Hostinger.APIToken = getenv("CRABBOX_HOSTINGER_API_TOKEN", getenv("HOSTINGER_API_TOKEN", cfg.Hostinger.APIToken))
	cfg.Hostinger.APIURL = getenv("CRABBOX_HOSTINGER_API_URL", getenv("HOSTINGER_API_URL", cfg.Hostinger.APIURL))
	cfg.Hostinger.ItemID = getenv("CRABBOX_HOSTINGER_ITEM_ID", cfg.Hostinger.ItemID)
	cfg.Hostinger.PaymentMethodID = getenv("CRABBOX_HOSTINGER_PAYMENT_METHOD_ID", cfg.Hostinger.PaymentMethodID)
	cfg.Hostinger.TemplateID = getenv("CRABBOX_HOSTINGER_TEMPLATE_ID", cfg.Hostinger.TemplateID)
	cfg.Hostinger.DataCenterID = getenv("CRABBOX_HOSTINGER_DATA_CENTER_ID", cfg.Hostinger.DataCenterID)
	cfg.Hostinger.HostnamePrefix = getenv("CRABBOX_HOSTINGER_HOSTNAME_PREFIX", cfg.Hostinger.HostnamePrefix)
	if user := os.Getenv("CRABBOX_HOSTINGER_USER"); user != "" {
		cfg.Hostinger.User = user
		MarkHostingerUserExplicit(cfg)
	}
	if workRoot := os.Getenv("CRABBOX_HOSTINGER_WORK_ROOT"); workRoot != "" {
		cfg.Hostinger.WorkRoot = workRoot
		MarkHostingerWorkRootExplicit(cfg)
	}
	if value, ok := getenvBool("CRABBOX_HOSTINGER_ALLOW_PURCHASE"); ok {
		cfg.Hostinger.AllowPurchase = value
	}
	cfg.Hostinger.ReleaseAction = getenv("CRABBOX_HOSTINGER_RELEASE_ACTION", cfg.Hostinger.ReleaseAction)
	// WANDB_API_KEY is resolved by the W&B client after file config so a
	// generic shell login cannot override an explicit wandb.apiKey value.
	cfg.Wandb.APIKey = getenv("CRABBOX_WANDB_API_KEY", cfg.Wandb.APIKey)
	cfg.Wandb.DefaultImage = getenv("CRABBOX_WANDB_DEFAULT_IMAGE", getenv("WANDB_DEFAULT_IMAGE", cfg.Wandb.DefaultImage))
	cfg.Wandb.MaxLifetimeSeconds = getenvInt("CRABBOX_WANDB_MAX_LIFETIME_SECONDS", getenvInt("WANDB_MAX_LIFETIME_SECONDS", cfg.Wandb.MaxLifetimeSeconds))
	if value := os.Getenv("CRABBOX_ORGO_API_KEY"); value != "" {
		cfg.Orgo.APIKey = value
		cfg.credentialProvenance.orgoAPIKey = credentialSourceEnvironment
	} else if cfg.Orgo.APIKey == "" {
		if value := os.Getenv("ORGO_API_KEY"); value != "" {
			cfg.Orgo.APIKey = value
			cfg.credentialProvenance.orgoAPIKey = credentialSourceEnvironment
		}
	}
	if value, ok := firstNonEmptyEnv("CRABBOX_ORGO_API_BASE", "ORGO_API_BASE_URL"); ok {
		cfg.Orgo.APIBase = value
		cfg.credentialProvenance.orgoAPIBase = credentialSourceEnvironment
	}
	cfg.Orgo.WorkspaceID = getenv("CRABBOX_ORGO_WORKSPACE_ID", getenv("ORGO_WORKSPACE_ID", cfg.Orgo.WorkspaceID))
	cfg.Orgo.RAMGB = getenvInt("CRABBOX_ORGO_RAM_GB", cfg.Orgo.RAMGB)
	cfg.Orgo.CPUs = getenvInt("CRABBOX_ORGO_CPUS", cfg.Orgo.CPUs)
	cfg.Orgo.DiskGB = getenvInt("CRABBOX_ORGO_DISK_GB", cfg.Orgo.DiskGB)
	cfg.Orgo.Resolution = getenv("CRABBOX_ORGO_RESOLUTION", cfg.Orgo.Resolution)
	if value, ok := firstNonEmptyEnv("CRABBOX_ISLO_API_KEY", "ISLO_API_KEY"); ok {
		cfg.Islo.APIKey = value
		cfg.credentialProvenance.isloAPIKey = credentialSourceEnvironment
	}
	if value, ok := firstNonEmptyEnv("CRABBOX_ISLO_BASE_URL", "ISLO_BASE_URL"); ok {
		cfg.Islo.BaseURL = value
		cfg.credentialProvenance.isloBaseURL = credentialSourceEnvironment
	}
	if image := os.Getenv("CRABBOX_ISLO_IMAGE"); image != "" {
		cfg.Islo.Image = image
		cfg.isloImageExplicit = true
	}
	cfg.Islo.Workdir = getenv("CRABBOX_ISLO_WORKDIR", cfg.Islo.Workdir)
	cfg.Islo.GatewayProfile = getenv("CRABBOX_ISLO_GATEWAY_PROFILE", cfg.Islo.GatewayProfile)
	cfg.Islo.SnapshotName = getenv("CRABBOX_ISLO_SNAPSHOT_NAME", cfg.Islo.SnapshotName)
	if raw := os.Getenv("CRABBOX_ISLO_VCPUS"); raw != "" {
		cfg.Islo.VCPUs = getenvInt("CRABBOX_ISLO_VCPUS", cfg.Islo.VCPUs)
		if _, err := strconv.Atoi(raw); err == nil {
			cfg.isloVCPUsExplicit = true
		}
	}
	if raw := os.Getenv("CRABBOX_ISLO_MEMORY_MB"); raw != "" {
		cfg.Islo.MemoryMB = getenvInt("CRABBOX_ISLO_MEMORY_MB", cfg.Islo.MemoryMB)
		if _, err := strconv.Atoi(raw); err == nil {
			cfg.isloMemoryMBExplicit = true
		}
	}
	if raw := os.Getenv("CRABBOX_ISLO_DISK_GB"); raw != "" {
		cfg.Islo.DiskGB = getenvInt("CRABBOX_ISLO_DISK_GB", cfg.Islo.DiskGB)
		if _, err := strconv.Atoi(raw); err == nil {
			cfg.isloDiskGBExplicit = true
		}
	}
	cfg.Freestyle.APIKey = getenv("CRABBOX_FREESTYLE_API_KEY", getenv("FREESTYLE_API_KEY", cfg.Freestyle.APIKey))
	cfg.Freestyle.APIURL = getenv("CRABBOX_FREESTYLE_API_URL", getenv("FREESTYLE_API_URL", cfg.Freestyle.APIURL))
	cfg.Freestyle.Workdir = getenv("CRABBOX_FREESTYLE_WORKDIR", cfg.Freestyle.Workdir)
	cfg.Freestyle.VCPUs = getenvInt("CRABBOX_FREESTYLE_VCPUS", cfg.Freestyle.VCPUs)
	cfg.Freestyle.MemoryGB = getenvInt("CRABBOX_FREESTYLE_MEMORY_GB", cfg.Freestyle.MemoryGB)
	cfg.Tenki.CLIPath = getenv("CRABBOX_TENKI_CLI", getenv("TENKI_CLI", cfg.Tenki.CLIPath))
	if value, ok := firstNonEmptyEnv("CRABBOX_TENKI_ENDPOINT", "TENKI_ENDPOINT"); ok {
		cfg.Tenki.Endpoint = value
		cfg.credentialProvenance.tenkiEndpoint = credentialSourceEnvironment
	}
	if value, ok := firstNonEmptyEnv("CRABBOX_TENKI_GATEWAY", "TENKI_GATEWAY"); ok {
		cfg.Tenki.Gateway = value
		cfg.credentialProvenance.tenkiGateway = credentialSourceEnvironment
	}
	cfg.Tenki.Workspace = getenv("CRABBOX_TENKI_WORKSPACE", cfg.Tenki.Workspace)
	cfg.Tenki.Project = getenv("CRABBOX_TENKI_PROJECT", cfg.Tenki.Project)
	cfg.Tenki.Image = getenv("CRABBOX_TENKI_IMAGE", cfg.Tenki.Image)
	cfg.Tenki.Snapshot = getenv("CRABBOX_TENKI_SNAPSHOT", cfg.Tenki.Snapshot)
	cfg.Tenki.WorkRoot = getenv("CRABBOX_TENKI_WORK_ROOT", cfg.Tenki.WorkRoot)
	cfg.Tenki.CPUs = getenvInt("CRABBOX_TENKI_CPUS", cfg.Tenki.CPUs)
	cfg.Tenki.MemoryMB = getenvInt("CRABBOX_TENKI_MEMORY_MB", cfg.Tenki.MemoryMB)
	cfg.Tenki.DiskGB = getenvInt("CRABBOX_TENKI_DISK_GB", cfg.Tenki.DiskGB)
	if value, ok := firstNonEmptyEnv("CRABBOX_TENSORLAKE_API_KEY", "TENSORLAKE_API_KEY"); ok {
		cfg.Tensorlake.APIKey = value
		cfg.credentialProvenance.tensorlakeAPIKey = credentialSourceEnvironment
	}
	if value, ok := firstNonEmptyEnv("CRABBOX_TENSORLAKE_API_URL", "TENSORLAKE_API_URL"); ok {
		cfg.Tensorlake.APIURL = value
		cfg.credentialProvenance.tensorlakeAPIURL = credentialSourceEnvironment
	}
	cfg.Tensorlake.CLIPath = getenv("CRABBOX_TENSORLAKE_CLI", cfg.Tensorlake.CLIPath)
	cfg.Tensorlake.Image = getenv("CRABBOX_TENSORLAKE_IMAGE", cfg.Tensorlake.Image)
	cfg.Tensorlake.Snapshot = getenv("CRABBOX_TENSORLAKE_SNAPSHOT", cfg.Tensorlake.Snapshot)
	cfg.Tensorlake.OrganizationID = getenv("CRABBOX_TENSORLAKE_ORGANIZATION_ID", getenv("TENSORLAKE_ORGANIZATION_ID", cfg.Tensorlake.OrganizationID))
	cfg.Tensorlake.ProjectID = getenv("CRABBOX_TENSORLAKE_PROJECT_ID", getenv("TENSORLAKE_PROJECT_ID", cfg.Tensorlake.ProjectID))
	cfg.Tensorlake.Namespace = getenv("CRABBOX_TENSORLAKE_NAMESPACE", getenv("INDEXIFY_NAMESPACE", cfg.Tensorlake.Namespace))
	cfg.Tensorlake.Workdir = getenv("CRABBOX_TENSORLAKE_WORKDIR", cfg.Tensorlake.Workdir)
	cfg.Tensorlake.CPUs = getenvFloat("CRABBOX_TENSORLAKE_CPUS", cfg.Tensorlake.CPUs)
	cfg.Tensorlake.MemoryMB = getenvInt("CRABBOX_TENSORLAKE_MEMORY_MB", cfg.Tensorlake.MemoryMB)
	cfg.Tensorlake.DiskMB = getenvInt("CRABBOX_TENSORLAKE_DISK_MB", cfg.Tensorlake.DiskMB)
	cfg.Tensorlake.TimeoutSecs = getenvInt("CRABBOX_TENSORLAKE_TIMEOUT_SECS", cfg.Tensorlake.TimeoutSecs)
	if v, ok := getenvBool("CRABBOX_TENSORLAKE_NO_INTERNET"); ok {
		cfg.Tensorlake.NoInternet = v
	}
	var err error
	cfg.Cua.APIURL = getenv("CRABBOX_CUA_API_URL", getenv("CUA_BASE_URL", cfg.Cua.APIURL))
	cfg.Cua.Image = getenv("CRABBOX_CUA_IMAGE", cfg.Cua.Image)
	cfg.Cua.Kind = getenv("CRABBOX_CUA_KIND", cfg.Cua.Kind)
	cfg.Cua.Region = getenv("CRABBOX_CUA_REGION", cfg.Cua.Region)
	cfg.Cua.Workdir = getenv("CRABBOX_CUA_WORKDIR", cfg.Cua.Workdir)
	cfg.Cua.VCPUs, err = getenvNonNegativeInt("CRABBOX_CUA_VCPUS", cfg.Cua.VCPUs)
	if err != nil {
		return err
	}
	cfg.Cua.MemoryMB, err = getenvNonNegativeInt("CRABBOX_CUA_MEMORY_MB", cfg.Cua.MemoryMB)
	if err != nil {
		return err
	}
	cfg.Cua.DiskGB, err = getenvNonNegativeInt("CRABBOX_CUA_DISK_GB", cfg.Cua.DiskGB)
	if err != nil {
		return err
	}
	cfg.Cua.StartupTimeoutSecs, err = getenvNonNegativeInt("CRABBOX_CUA_STARTUP_TIMEOUT_SECS", cfg.Cua.StartupTimeoutSecs)
	if err != nil {
		return err
	}
	cfg.Cua.ExecTimeoutSecs, err = getenvNonNegativeInt("CRABBOX_CUA_EXEC_TIMEOUT_SECS", cfg.Cua.ExecTimeoutSecs)
	if err != nil {
		return err
	}
	cfg.Cua.BridgeCommand = getenv("CRABBOX_CUA_BRIDGE_COMMAND", cfg.Cua.BridgeCommand)
	cfg.Cua.SDKPackage = getenv("CRABBOX_CUA_SDK_PACKAGE", cfg.Cua.SDKPackage)
	cfg.Cua.SDKImport = getenv("CRABBOX_CUA_SDK_IMPORT", cfg.Cua.SDKImport)
	cfg.Cua.SDKFallbackImport = getenv("CRABBOX_CUA_SDK_FALLBACK_IMPORT", cfg.Cua.SDKFallbackImport)
	cfg.OpenComputer.APIURL = getenv("CRABBOX_OPENCOMPUTER_API_URL", getenv("OPENCOMPUTER_API_URL", cfg.OpenComputer.APIURL))
	cfg.OpenComputer.Workdir = getenv("CRABBOX_OPENCOMPUTER_WORKDIR", cfg.OpenComputer.Workdir)
	cfg.OpenComputer.CPU = getenvInt("CRABBOX_OPENCOMPUTER_CPU", cfg.OpenComputer.CPU)
	cfg.OpenComputer.MemoryMB = getenvInt("CRABBOX_OPENCOMPUTER_MEMORY_MB", cfg.OpenComputer.MemoryMB)
	cfg.OpenComputer.TimeoutSecs = getenvInt("CRABBOX_OPENCOMPUTER_TIMEOUT_SECS", cfg.OpenComputer.TimeoutSecs)
	cfg.OpenComputer.ExecTimeoutSecs = getenvInt("CRABBOX_OPENCOMPUTER_EXEC_TIMEOUT_SECS", cfg.OpenComputer.ExecTimeoutSecs)
	if v, ok := getenvBool("CRABBOX_OPENCOMPUTER_BURST"); ok {
		cfg.OpenComputer.Burst = v
	}
	cfg.CodeSandbox.TemplateID = getenv("CRABBOX_CODESANDBOX_TEMPLATE_ID", cfg.CodeSandbox.TemplateID)
	cfg.CodeSandbox.Workdir = getenv("CRABBOX_CODESANDBOX_WORKDIR", cfg.CodeSandbox.Workdir)
	cfg.CodeSandbox.VMTier = getenv("CRABBOX_CODESANDBOX_VM_TIER", cfg.CodeSandbox.VMTier)
	cfg.CodeSandbox.Privacy = getenv("CRABBOX_CODESANDBOX_PRIVACY", cfg.CodeSandbox.Privacy)
	cfg.CodeSandbox.HibernationTimeoutSecs, err = getenvNonNegativeInt("CRABBOX_CODESANDBOX_HIBERNATION_TIMEOUT_SECS", cfg.CodeSandbox.HibernationTimeoutSecs)
	if err != nil {
		return err
	}
	if v, ok := getenvBool("CRABBOX_CODESANDBOX_AUTOMATIC_WAKEUP_HTTP"); ok {
		cfg.CodeSandbox.AutomaticWakeupHTTP = v
	}
	if v, ok := getenvBool("CRABBOX_CODESANDBOX_AUTOMATIC_WAKEUP_WEBSOCKET"); ok {
		cfg.CodeSandbox.AutomaticWakeupWebSocket = v
	}
	cfg.CodeSandbox.BridgeCommand = getenv("CRABBOX_CODESANDBOX_BRIDGE_COMMAND", cfg.CodeSandbox.BridgeCommand)
	cfg.CodeSandbox.SDKPackage = getenv("CRABBOX_CODESANDBOX_SDK_PACKAGE", cfg.CodeSandbox.SDKPackage)
	cfg.CodeSandbox.DoctorListLimit, err = getenvNonNegativeInt("CRABBOX_CODESANDBOX_DOCTOR_LIST_LIMIT", cfg.CodeSandbox.DoctorListLimit)
	if err != nil {
		return err
	}
	cfg.CodeSandbox.OperationTimeoutSecs, err = getenvNonNegativeInt("CRABBOX_CODESANDBOX_OPERATION_TIMEOUT_SECS", cfg.CodeSandbox.OperationTimeoutSecs)
	if err != nil {
		return err
	}
	cfg.OpenSandbox.APIURL = getenv("CRABBOX_OPENSANDBOX_API_URL", getenv("OPEN_SANDBOX_API_URL", cfg.OpenSandbox.APIURL))
	cfg.OpenSandbox.Image = getenv("CRABBOX_OPENSANDBOX_IMAGE", cfg.OpenSandbox.Image)
	cfg.OpenSandbox.Workdir = getenv("CRABBOX_OPENSANDBOX_WORKDIR", cfg.OpenSandbox.Workdir)
	cfg.OpenSandbox.CPU = getenv("CRABBOX_OPENSANDBOX_CPU", cfg.OpenSandbox.CPU)
	cfg.OpenSandbox.Memory = getenv("CRABBOX_OPENSANDBOX_MEMORY", cfg.OpenSandbox.Memory)
	cfg.OpenSandbox.TimeoutSecs, err = getenvNonNegativeInt("CRABBOX_OPENSANDBOX_TIMEOUT_SECS", cfg.OpenSandbox.TimeoutSecs)
	if err != nil {
		return err
	}
	cfg.OpenSandbox.ExecTimeoutSecs, err = getenvNonNegativeInt("CRABBOX_OPENSANDBOX_EXEC_TIMEOUT_SECS", cfg.OpenSandbox.ExecTimeoutSecs)
	if err != nil {
		return err
	}
	cfg.OpenSandbox.PlatformOS = getenv("CRABBOX_OPENSANDBOX_PLATFORM_OS", cfg.OpenSandbox.PlatformOS)
	cfg.OpenSandbox.PlatformArch = getenv("CRABBOX_OPENSANDBOX_PLATFORM_ARCH", cfg.OpenSandbox.PlatformArch)
	if v, ok := getenvBool("CRABBOX_OPENSANDBOX_SECURE_ACCESS"); ok {
		cfg.OpenSandbox.SecureAccess = v
	}
	if v, ok := getenvBool("CRABBOX_OPENSANDBOX_USE_SERVER_PROXY"); ok {
		cfg.OpenSandbox.UseServerProxy = v
	}
	if value := os.Getenv("CRABBOX_NOMAD_ADDR"); value != "" {
		cfg.Nomad.Address = value
		cfg.credentialProvenance.nomadAddress = credentialSourceEnvironment
	} else if value := os.Getenv("NOMAD_ADDR"); value != "" {
		cfg.Nomad.Address = value
		cfg.credentialProvenance.nomadAddress = credentialSourceEnvironment
	}
	cfg.Nomad.Region = getenv("CRABBOX_NOMAD_REGION", getenv("NOMAD_REGION", cfg.Nomad.Region))
	cfg.Nomad.Namespace = getenv("CRABBOX_NOMAD_NAMESPACE", getenv("NOMAD_NAMESPACE", cfg.Nomad.Namespace))
	if value := os.Getenv("CRABBOX_NOMAD_TOKEN_ENV"); value != "" {
		cfg.Nomad.TokenEnv = value
		cfg.credentialProvenance.nomadTokenEnv = credentialSourceEnvironment
	}
	cfg.Nomad.CACert = expandUserPath(getenv("CRABBOX_NOMAD_CA_CERT", getenv("NOMAD_CACERT", cfg.Nomad.CACert)))
	cfg.Nomad.CAPath = expandUserPath(getenv("CRABBOX_NOMAD_CA_PATH", getenv("NOMAD_CAPATH", cfg.Nomad.CAPath)))
	cfg.Nomad.ClientCert = expandUserPath(getenv("CRABBOX_NOMAD_CLIENT_CERT", getenv("NOMAD_CLIENT_CERT", cfg.Nomad.ClientCert)))
	cfg.Nomad.ClientKey = expandUserPath(getenv("CRABBOX_NOMAD_CLIENT_KEY", getenv("NOMAD_CLIENT_KEY", cfg.Nomad.ClientKey)))
	cfg.Nomad.TLSServerName = getenv("CRABBOX_NOMAD_TLS_SERVER_NAME", getenv("NOMAD_TLS_SERVER_NAME", cfg.Nomad.TLSServerName))
	if v, ok := getenvBool("CRABBOX_NOMAD_SKIP_VERIFY"); ok {
		cfg.Nomad.SkipVerify = v
	} else if v, ok := getenvBool("NOMAD_SKIP_VERIFY"); ok {
		cfg.Nomad.SkipVerify = v
	}
	cfg.Nomad.Task = getenv("CRABBOX_NOMAD_TASK", cfg.Nomad.Task)
	cfg.Nomad.Driver = getenv("CRABBOX_NOMAD_DRIVER", cfg.Nomad.Driver)
	cfg.Nomad.Image = getenv("CRABBOX_NOMAD_IMAGE", cfg.Nomad.Image)
	cfg.Nomad.Workdir = getenv("CRABBOX_NOMAD_WORKDIR", cfg.Nomad.Workdir)
	cfg.Nomad.JobSpecTemplate = expandUserPath(getenv("CRABBOX_NOMAD_JOBSPEC_TEMPLATE", cfg.Nomad.JobSpecTemplate))
	cfg.Nomad.NodePool = getenv("CRABBOX_NOMAD_NODE_POOL", cfg.Nomad.NodePool)
	if datacenters, ok := getenvList("CRABBOX_NOMAD_DATACENTERS"); ok {
		cfg.Nomad.Datacenters = datacenters
	}
	cfg.Nomad.CPU = getenvInt("CRABBOX_NOMAD_CPU", cfg.Nomad.CPU)
	cfg.Nomad.MemoryMB = getenvInt("CRABBOX_NOMAD_MEMORY_MB", cfg.Nomad.MemoryMB)
	cfg.Nomad.DiskMB = getenvInt("CRABBOX_NOMAD_DISK_MB", cfg.Nomad.DiskMB)
	if timeout := os.Getenv("CRABBOX_NOMAD_ALLOC_READY_TIMEOUT"); timeout != "" {
		applyLeaseDuration(&cfg.Nomad.AllocReadyTimeout, timeout)
	}
	if timeout := os.Getenv("CRABBOX_NOMAD_EVAL_TIMEOUT"); timeout != "" {
		applyLeaseDuration(&cfg.Nomad.EvalTimeout, timeout)
	}
	cfg.Nomad.ExecTimeoutSecs, err = getenvNonNegativeInt("CRABBOX_NOMAD_EXEC_TIMEOUT_SECS", cfg.Nomad.ExecTimeoutSecs)
	if err != nil {
		return err
	}
	cfg.Blaxel.APIKey = getenv("CRABBOX_BLAXEL_API_KEY", getenv("BL_API_KEY", cfg.Blaxel.APIKey))
	cfg.Blaxel.APIURL = getenv("CRABBOX_BLAXEL_API_URL", cfg.Blaxel.APIURL)
	cfg.Blaxel.Workspace = getenv("CRABBOX_BLAXEL_WORKSPACE", getenv("BL_WORKSPACE", cfg.Blaxel.Workspace))
	cfg.Blaxel.Region = getenv("CRABBOX_BLAXEL_REGION", getenv("BL_REGION", cfg.Blaxel.Region))
	cfg.Blaxel.Image = getenv("CRABBOX_BLAXEL_IMAGE", cfg.Blaxel.Image)
	cfg.Blaxel.MemoryMB = getenvInt("CRABBOX_BLAXEL_MEMORY_MB", cfg.Blaxel.MemoryMB)
	cfg.Blaxel.TTL = getenv("CRABBOX_BLAXEL_TTL", cfg.Blaxel.TTL)
	cfg.Blaxel.IdleTTL = getenv("CRABBOX_BLAXEL_IDLE_TTL", cfg.Blaxel.IdleTTL)
	cfg.Blaxel.Workdir = getenv("CRABBOX_BLAXEL_WORKDIR", cfg.Blaxel.Workdir)
	cfg.Blaxel.ExecTimeoutSecs, err = getenvNonNegativeInt("CRABBOX_BLAXEL_EXEC_TIMEOUT_SECS", cfg.Blaxel.ExecTimeoutSecs)
	if err != nil {
		return err
	}
	if value, ok := getenvBool("CRABBOX_BLAXEL_FORGET_MISSING"); ok {
		cfg.Blaxel.ForgetMissing = value
	}
	if err := cfg.VercelSandbox.applyEnv(); err != nil {
		return err
	}
	cfg.CloudflareSandbox.BridgeURL = getenv("CRABBOX_CLOUDFLARE_SANDBOX_URL", cfg.CloudflareSandbox.BridgeURL)
	cfg.CloudflareSandbox.Token = getenv("CRABBOX_CLOUDFLARE_SANDBOX_TOKEN", cfg.CloudflareSandbox.Token)
	cfg.CloudflareSandbox.Workdir = getenv("CRABBOX_CLOUDFLARE_SANDBOX_WORKDIR", cfg.CloudflareSandbox.Workdir)
	cfg.CloudflareSandbox.ExecTimeoutSecs, err = getenvNonNegativeInt("CRABBOX_CLOUDFLARE_SANDBOX_EXEC_TIMEOUT_SECS", cfg.CloudflareSandbox.ExecTimeoutSecs)
	if err != nil {
		return err
	}
	if v, ok := getenvBool("CRABBOX_CLOUDFLARE_SANDBOX_FORGET_MISSING"); ok {
		cfg.CloudflareSandbox.ForgetMissing = v
	}
	cfg.Superserve.BaseURL = getenv("CRABBOX_SUPERSERVE_BASE_URL", getenv("SUPERSERVE_BASE_URL", cfg.Superserve.BaseURL))
	cfg.Superserve.Template = getenv("CRABBOX_SUPERSERVE_TEMPLATE", cfg.Superserve.Template)
	cfg.Superserve.Snapshot = getenv("CRABBOX_SUPERSERVE_SNAPSHOT", cfg.Superserve.Snapshot)
	cfg.Superserve.Workdir = getenv("CRABBOX_SUPERSERVE_WORKDIR", cfg.Superserve.Workdir)
	cfg.Superserve.TimeoutSecs, err = getenvNonNegativeInt("CRABBOX_SUPERSERVE_TIMEOUT_SECS", cfg.Superserve.TimeoutSecs)
	if err != nil {
		return err
	}
	cfg.Superserve.ExecTimeoutSecs, err = getenvNonNegativeInt("CRABBOX_SUPERSERVE_EXEC_TIMEOUT_SECS", cfg.Superserve.ExecTimeoutSecs)
	if err != nil {
		return err
	}
	if allowOut := os.Getenv("CRABBOX_SUPERSERVE_NETWORK_ALLOW_OUT"); allowOut != "" {
		cfg.Superserve.NetworkAllowOut = splitCommaList(allowOut)
	}
	if denyOut := os.Getenv("CRABBOX_SUPERSERVE_NETWORK_DENY_OUT"); denyOut != "" {
		cfg.Superserve.NetworkDenyOut = splitCommaList(denyOut)
	}
	if v, ok := getenvBool("CRABBOX_SUPERSERVE_FORGET_MISSING"); ok {
		cfg.Superserve.ForgetMissing = v
	}
	cfg.DockerSandbox.CLIPath = getenv("CRABBOX_DOCKER_SANDBOX_CLI", cfg.DockerSandbox.CLIPath)
	cfg.DockerSandbox.Agent = getenv("CRABBOX_DOCKER_SANDBOX_AGENT", cfg.DockerSandbox.Agent)
	cfg.DockerSandbox.Template = getenv("CRABBOX_DOCKER_SANDBOX_TEMPLATE", cfg.DockerSandbox.Template)
	if cpus := os.Getenv("CRABBOX_DOCKER_SANDBOX_CPUS"); cpus != "" {
		parsed, err := strconv.ParseFloat(cpus, 64)
		if err != nil {
			return fmt.Errorf("parse CRABBOX_DOCKER_SANDBOX_CPUS: %w", err)
		}
		cfg.DockerSandbox.CPUs = parsed
	}
	cfg.DockerSandbox.Memory = getenv("CRABBOX_DOCKER_SANDBOX_MEMORY", cfg.DockerSandbox.Memory)
	if v, ok := getenvBool("CRABBOX_DOCKER_SANDBOX_CLONE"); ok {
		cfg.DockerSandbox.Clone = v
	}
	cfg.DockerSandbox.Workdir = getenv("CRABBOX_DOCKER_SANDBOX_WORKDIR", cfg.DockerSandbox.Workdir)
	if values, ok := getenvList("CRABBOX_DOCKER_SANDBOX_EXTRA_WORKSPACES"); ok {
		cfg.DockerSandbox.ExtraWorkspaces = values
	}
	if values, ok := getenvList("CRABBOX_DOCKER_SANDBOX_MCP"); ok {
		cfg.DockerSandbox.MCP = values
	}
	if values, ok := getenvList("CRABBOX_DOCKER_SANDBOX_KIT"); ok {
		cfg.DockerSandbox.Kit = values
	}
	cfg.AnthropicSRT.CLIPath = getenv("CRABBOX_ANTHROPIC_SANDBOX_RUNTIME_CLI", cfg.AnthropicSRT.CLIPath)
	cfg.AnthropicSRT.Settings = getenv("CRABBOX_ANTHROPIC_SANDBOX_RUNTIME_SETTINGS", cfg.AnthropicSRT.Settings)
	if value, ok := getenvBool("CRABBOX_ANTHROPIC_SANDBOX_RUNTIME_DEBUG"); ok {
		cfg.AnthropicSRT.Debug = value
	}
	cfg.CloudRunSandbox.GatewayURL = getenv("CRABBOX_CLOUD_RUN_SANDBOX_GATEWAY_URL", getenv("CLOUD_RUN_SANDBOX_URL", cfg.CloudRunSandbox.GatewayURL))
	cfg.CloudRunSandbox.CLIPath = getenv("CRABBOX_CLOUD_RUN_SANDBOX_CLI", getenv("CLOUD_RUN_SANDBOX_BINARY", cfg.CloudRunSandbox.CLIPath))
	cfg.CloudRunSandbox.Workdir = getenv("CRABBOX_CLOUD_RUN_SANDBOX_WORKDIR", cfg.CloudRunSandbox.Workdir)
	if value, ok := getenvBool("CRABBOX_CLOUD_RUN_SANDBOX_ALLOW_EGRESS"); ok {
		cfg.CloudRunSandbox.AllowEgress = value
	}
	if value, ok := getenvBool("CRABBOX_CLOUD_RUN_SANDBOX_WRITE"); ok {
		cfg.CloudRunSandbox.Write = value
	}
	cfg.CloudRunSandbox.Rootfs = getenv("CRABBOX_CLOUD_RUN_SANDBOX_ROOTFS", cfg.CloudRunSandbox.Rootfs)
	cfg.Modal.App = getenv("CRABBOX_MODAL_APP", cfg.Modal.App)
	cfg.Modal.Image = getenv("CRABBOX_MODAL_IMAGE", cfg.Modal.Image)
	cfg.Modal.Workdir = getenv("CRABBOX_MODAL_WORKDIR", cfg.Modal.Workdir)
	cfg.Modal.Python = getenv("CRABBOX_MODAL_PYTHON", cfg.Modal.Python)
	cfg.Modal.Environment = getenv("CRABBOX_MODAL_ENVIRONMENT", cfg.Modal.Environment)
	if values, ok := getenvList("CRABBOX_MODAL_SECRETS"); ok {
		cfg.Modal.Secrets = values
	}
	if value, ok := firstNonEmptyEnv("CRABBOX_UPSTASH_BOX_API_KEY", "UPSTASH_BOX_API_KEY"); ok {
		cfg.UpstashBox.APIKey = value
		cfg.credentialProvenance.upstashBoxAPIKey = credentialSourceEnvironment
	}
	if value, ok := firstNonEmptyEnv("CRABBOX_UPSTASH_BOX_BASE_URL", "UPSTASH_BOX_BASE_URL"); ok {
		cfg.UpstashBox.BaseURL = value
		cfg.credentialProvenance.upstashBoxBaseURL = credentialSourceEnvironment
	}
	cfg.UpstashBox.Runtime = getenv("CRABBOX_UPSTASH_BOX_RUNTIME", cfg.UpstashBox.Runtime)
	cfg.UpstashBox.Size = getenv("CRABBOX_UPSTASH_BOX_SIZE", cfg.UpstashBox.Size)
	cfg.UpstashBox.Workdir = getenv("CRABBOX_UPSTASH_BOX_WORKDIR", cfg.UpstashBox.Workdir)
	if value, ok := getenvBool("CRABBOX_UPSTASH_BOX_KEEP_ALIVE"); ok {
		cfg.UpstashBox.KeepAlive = value
	}
	if value, ok := firstNonEmptyEnv("CRABBOX_SMOLVM_API_KEY", "SMOLMACHINES_API_KEY", "SMK_API_KEY"); ok {
		cfg.Smolvm.APIKey = value
		cfg.credentialProvenance.smolvmAPIKey = credentialSourceEnvironment
	}
	if value := os.Getenv("CRABBOX_SMOLVM_BASE_URL"); value != "" {
		cfg.Smolvm.BaseURL = value
		cfg.credentialProvenance.smolvmBaseURL = credentialSourceEnvironment
	}
	cfg.Smolvm.Image = getenv("CRABBOX_SMOLVM_IMAGE", cfg.Smolvm.Image)
	cfg.Smolvm.Workdir = getenv("CRABBOX_SMOLVM_WORKDIR", cfg.Smolvm.Workdir)
	cfg.Smolvm.CPUs = getenvInt("CRABBOX_SMOLVM_CPUS", cfg.Smolvm.CPUs)
	cfg.Smolvm.MemoryMB = getenvInt("CRABBOX_SMOLVM_MEMORY_MB", cfg.Smolvm.MemoryMB)
	cfg.Smolvm.Network = getenv("CRABBOX_SMOLVM_NETWORK", cfg.Smolvm.Network)
	if value, ok := getenvBool("CRABBOX_SMOLVM_KEEP"); ok {
		cfg.Smolvm.Keep = value
	}
	if value, ok := firstNonEmptyEnv("CRABBOX_ASCII_BOX_API_KEY", "ASCII_BOX_API_KEY"); ok {
		cfg.AsciiBox.APIKey = value
		cfg.credentialProvenance.asciiBoxAPIKey = credentialSourceEnvironment
	}
	if value, ok := firstNonEmptyEnv("CRABBOX_ASCII_BOX_BASE_URL", "ASCII_BOX_BASE_URL"); ok {
		cfg.AsciiBox.BaseURL = value
		cfg.credentialProvenance.asciiBoxBaseURL = credentialSourceEnvironment
	}
	cfg.AsciiBox.CLIPath = getenv("CRABBOX_ASCII_BOX_CLI", getenv("BOX_CLI", cfg.AsciiBox.CLIPath))
	cfg.AsciiBox.Workdir = getenv("CRABBOX_ASCII_BOX_WORKDIR", cfg.AsciiBox.Workdir)
	if value := os.Getenv("CRABBOX_CLOUDFLARE_RUNNER_URL"); value != "" {
		cfg.Cloudflare.APIURL = value
		cfg.credentialProvenance.cloudflareAPIURL = credentialSourceEnvironment
	}
	if value := os.Getenv("CRABBOX_CLOUDFLARE_RUNNER_TOKEN"); value != "" {
		cfg.Cloudflare.Token = value
		cfg.credentialProvenance.cloudflareToken = credentialSourceEnvironment
	}
	cfg.Cloudflare.Workdir = getenv("CRABBOX_CLOUDFLARE_WORKDIR", cfg.Cloudflare.Workdir)
	cfg.Crownest.APIURL = getenv("CRABBOX_CROWNEST_API_URL", getenv("CROWNEST_API_URL", cfg.Crownest.APIURL))
	cfg.Crownest.ProjectID = getenv("CRABBOX_CROWNEST_PROJECT_ID", getenv("CROWNEST_PROJECT_ID", cfg.Crownest.ProjectID))
	cfg.Crownest.Template = getenv("CRABBOX_CROWNEST_TEMPLATE", getenv("CROWNEST_TEMPLATE", cfg.Crownest.Template))
	crownestTimeoutEnv := "CRABBOX_CROWNEST_TIMEOUT_SECS"
	crownestTimeoutValue := os.Getenv(crownestTimeoutEnv)
	if crownestTimeoutValue == "" {
		crownestTimeoutEnv = "CROWNEST_TIMEOUT_SECS"
		crownestTimeoutValue = os.Getenv(crownestTimeoutEnv)
	}
	if crownestTimeoutValue != "" {
		parsed, parseErr := strconv.Atoi(crownestTimeoutValue)
		if parseErr != nil {
			return exit(2, "%s must be an integer", crownestTimeoutEnv)
		}
		if parsed < 0 {
			return exit(2, "%s must be non-negative", crownestTimeoutEnv)
		}
		cfg.Crownest.TimeoutSecs = parsed
	}
	if v, ok := getenvBool("CRABBOX_CROWNEST_FORGET_MISSING"); ok {
		cfg.Crownest.ForgetMissing = v
	} else if v, ok := getenvBool("CROWNEST_FORGET_MISSING"); ok {
		cfg.Crownest.ForgetMissing = v
	}
	cfg.CloudflareDynamicWorkers.LoaderURL = getenv("CRABBOX_CLOUDFLARE_DYNAMIC_WORKERS_URL", getenv("CRABBOX_CLOUDFLARE_DYNAMIC_WORKERS_LOADER_URL", cfg.CloudflareDynamicWorkers.LoaderURL))
	cfg.CloudflareDynamicWorkers.Token = getenv("CRABBOX_CLOUDFLARE_DYNAMIC_WORKERS_TOKEN", cfg.CloudflareDynamicWorkers.Token)
	cfg.CloudflareDynamicWorkers.CompatibilityDate = getenv("CRABBOX_CLOUDFLARE_DYNAMIC_WORKERS_COMPATIBILITY_DATE", cfg.CloudflareDynamicWorkers.CompatibilityDate)
	if flags, ok := getenvList("CRABBOX_CLOUDFLARE_DYNAMIC_WORKERS_COMPATIBILITY_FLAGS"); ok {
		cfg.CloudflareDynamicWorkers.CompatibilityFlags = flags
	}
	cfg.CloudflareDynamicWorkers.CacheMode = getenv("CRABBOX_CLOUDFLARE_DYNAMIC_WORKERS_CACHE_MODE", cfg.CloudflareDynamicWorkers.CacheMode)
	cfg.CloudflareDynamicWorkers.Egress = getenv("CRABBOX_CLOUDFLARE_DYNAMIC_WORKERS_EGRESS", cfg.CloudflareDynamicWorkers.Egress)
	cfg.CloudflareDynamicWorkers.CPUMs = getenvInt("CRABBOX_CLOUDFLARE_DYNAMIC_WORKERS_CPU_MS", cfg.CloudflareDynamicWorkers.CPUMs)
	cfg.CloudflareDynamicWorkers.Subrequests = getenvInt("CRABBOX_CLOUDFLARE_DYNAMIC_WORKERS_SUBREQUESTS", cfg.CloudflareDynamicWorkers.Subrequests)
	cfg.CloudflareDynamicWorkers.TimeoutSecs = getenvInt("CRABBOX_CLOUDFLARE_DYNAMIC_WORKERS_TIMEOUT_SECS", cfg.CloudflareDynamicWorkers.TimeoutSecs)
	if value, ok := firstNonEmptyEnv("CRABBOX_SEMAPHORE_HOST", "SEMAPHORE_HOST"); ok {
		cfg.Semaphore.Host = value
		cfg.credentialProvenance.semaphoreHost = credentialSourceEnvironment
	}
	if value, ok := firstNonEmptyEnv("CRABBOX_SEMAPHORE_TOKEN", "SEMAPHORE_API_TOKEN"); ok {
		cfg.Semaphore.Token = value
		cfg.credentialProvenance.semaphoreToken = credentialSourceEnvironment
	}
	cfg.Semaphore.Project = getenv("CRABBOX_SEMAPHORE_PROJECT", getenv("SEMAPHORE_PROJECT", cfg.Semaphore.Project))
	cfg.Semaphore.Machine = getenv("CRABBOX_SEMAPHORE_MACHINE", cfg.Semaphore.Machine)
	cfg.Semaphore.OSImage = getenv("CRABBOX_SEMAPHORE_OS_IMAGE", cfg.Semaphore.OSImage)
	cfg.Semaphore.IdleTimeout = getenv("CRABBOX_SEMAPHORE_IDLE_TIMEOUT", cfg.Semaphore.IdleTimeout)
	if value, ok := firstNonEmptyEnv("CRABBOX_SPRITES_TOKEN", "SPRITES_TOKEN", "SPRITE_TOKEN", "SETUP_SPRITE_TOKEN"); ok {
		cfg.Sprites.Token = value
		cfg.credentialProvenance.spritesToken = credentialSourceEnvironment
	}
	if value, ok := firstNonEmptyEnv("CRABBOX_SPRITES_API_URL", "SPRITES_API_URL"); ok {
		cfg.Sprites.APIURL = value
		cfg.credentialProvenance.spritesAPIURL = credentialSourceEnvironment
	}
	cfg.Sprites.WorkRoot = getenv("CRABBOX_SPRITES_WORK_ROOT", cfg.Sprites.WorkRoot)
	if runtimeName := os.Getenv("CRABBOX_LOCAL_CONTAINER_RUNTIME"); runtimeName != "" {
		cfg.LocalContainer.Runtime = runtimeName
		cfg.localContainerRuntimeExplicit = true
	}
	if image := os.Getenv("CRABBOX_LOCAL_CONTAINER_IMAGE"); image != "" {
		cfg.LocalContainer.Image = image
		cfg.localContainerImageExplicit = true
	}
	cfg.LocalContainer.User = getenv("CRABBOX_LOCAL_CONTAINER_USER", cfg.LocalContainer.User)
	if workRoot := os.Getenv("CRABBOX_LOCAL_CONTAINER_WORK_ROOT"); workRoot != "" {
		cfg.LocalContainer.WorkRoot = workRoot
		cfg.localContainerRootExplicit = true
	}
	cfg.LocalContainer.CPUs = getenvInt("CRABBOX_LOCAL_CONTAINER_CPUS", cfg.LocalContainer.CPUs)
	cfg.LocalContainer.Memory = getenv("CRABBOX_LOCAL_CONTAINER_MEMORY", cfg.LocalContainer.Memory)
	cfg.LocalContainer.Network = getenv("CRABBOX_LOCAL_CONTAINER_NETWORK", cfg.LocalContainer.Network)
	if value, ok := getenvBool("CRABBOX_LOCAL_CONTAINER_DOCKER_SOCKET"); ok {
		cfg.LocalContainer.DockerSocket = value
	}
	cfg.AppleContainer.CLIPath = getenv("CRABBOX_APPLE_CONTAINER_CLI", cfg.AppleContainer.CLIPath)
	if image := os.Getenv("CRABBOX_APPLE_CONTAINER_IMAGE"); image != "" {
		cfg.AppleContainer.Image = image
		cfg.appleContainerImageExplicit = true
	}
	cfg.AppleContainer.User = getenv("CRABBOX_APPLE_CONTAINER_USER", cfg.AppleContainer.User)
	cfg.AppleContainer.WorkRoot = getenv("CRABBOX_APPLE_CONTAINER_WORK_ROOT", cfg.AppleContainer.WorkRoot)
	cfg.AppleContainer.CPUs = getenvInt("CRABBOX_APPLE_CONTAINER_CPUS", cfg.AppleContainer.CPUs)
	cfg.AppleContainer.Memory = getenv("CRABBOX_APPLE_CONTAINER_MEMORY", cfg.AppleContainer.Memory)
	if extra := strings.Fields(os.Getenv("CRABBOX_APPLE_CONTAINER_EXTRA_RUN_ARGS")); len(extra) > 0 {
		cfg.AppleContainer.ExtraRunArgs = extra
	}
	cfg.AppleVM.HelperPath = getenv("CRABBOX_APPLE_VM_HELPER", getenv("CRABBOX_APPLE_VZ_HELPER", cfg.AppleVM.HelperPath))
	if image := appleVMEnv("IMAGE"); image != "" {
		cfg.AppleVM.Image = image
		cfg.AppleVM.ImageSHA256 = ""
		cfg.appleVMImageExplicit = true
		cfg.appleVMImageSHA256Explicit = false
	}
	if checksum := appleVMEnv("IMAGE_SHA256"); checksum != "" {
		cfg.AppleVM.ImageSHA256 = checksum
		cfg.appleVMImageSHA256Explicit = true
	}
	cfg.AppleVM.User = getenv("CRABBOX_APPLE_VM_USER", getenv("CRABBOX_APPLE_VZ_USER", cfg.AppleVM.User))
	cfg.AppleVM.WorkRoot = getenv("CRABBOX_APPLE_VM_WORK_ROOT", getenv("CRABBOX_APPLE_VZ_WORK_ROOT", cfg.AppleVM.WorkRoot))
	if rawCPUs := appleVMEnv("CPUS"); rawCPUs != "" {
		cpus, err := strconv.Atoi(strings.TrimSpace(rawCPUs))
		if err != nil {
			return fmt.Errorf("CRABBOX_APPLE_VM_CPUS must be an integer: %w", err)
		}
		cfg.AppleVM.CPUs = cpus
		cfg.appleVMCPUsExplicit = true
	}
	if rawMemory := appleVMEnv("MEMORY"); rawMemory != "" {
		memoryMiB, err := strconv.Atoi(strings.TrimSpace(rawMemory))
		if err != nil {
			return fmt.Errorf("CRABBOX_APPLE_VM_MEMORY must be an integer: %w", err)
		}
		cfg.AppleVM.MemoryMiB = memoryMiB
		cfg.appleVMMemoryExplicit = true
	}
	if rawDisk := appleVMEnv("DISK"); rawDisk != "" {
		diskGiB, err := strconv.Atoi(strings.TrimSpace(rawDisk))
		if err != nil {
			return fmt.Errorf("CRABBOX_APPLE_VM_DISK must be an integer: %w", err)
		}
		cfg.AppleVM.DiskGiB = diskGiB
		cfg.appleVMDiskExplicit = true
	}
	cfg.MXC.CLIPath = getenv("CRABBOX_MXC_CLI", cfg.MXC.CLIPath)
	cfg.MXC.Version = getenv("CRABBOX_MXC_VERSION", cfg.MXC.Version)
	cfg.MXC.Containment = getenv("CRABBOX_MXC_CONTAINMENT", cfg.MXC.Containment)
	cfg.MXC.Network = getenv("CRABBOX_MXC_NETWORK", cfg.MXC.Network)
	if value := os.Getenv("CRABBOX_MXC_READONLY_PATHS"); value != "" {
		cfg.MXC.ReadOnlyPaths = splitCommaList(value)
	}
	if value := os.Getenv("CRABBOX_MXC_READWRITE_PATHS"); value != "" {
		cfg.MXC.ReadWritePaths = splitCommaList(value)
	}
	if value := os.Getenv("CRABBOX_MXC_ALLOWED_HOSTS"); value != "" {
		cfg.MXC.AllowedHosts = splitCommaList(value)
	}
	if value := os.Getenv("CRABBOX_MXC_BLOCKED_HOSTS"); value != "" {
		cfg.MXC.BlockedHosts = splitCommaList(value)
	}
	if value, ok := getenvBool("CRABBOX_MXC_ALLOW_DACL_MUTATION"); ok {
		cfg.MXC.AllowDACLMutation = value
	}
	if value, ok := getenvBool("CRABBOX_MXC_ALLOW_WINDOWS_UI"); ok {
		cfg.MXC.AllowWindowsUI = value
	}
	if value, ok := getenvBool("CRABBOX_MXC_EXPERIMENTAL"); ok {
		cfg.MXC.Experimental = value
	}
	cfg.Multipass.CLIPath = getenv("CRABBOX_MULTIPASS_CLI", cfg.Multipass.CLIPath)
	if image := os.Getenv("CRABBOX_MULTIPASS_IMAGE"); image != "" {
		cfg.Multipass.Image = image
		cfg.multipassImageExplicit = true
	}
	cfg.Multipass.User = getenv("CRABBOX_MULTIPASS_USER", cfg.Multipass.User)
	cfg.Multipass.WorkRoot = getenv("CRABBOX_MULTIPASS_WORK_ROOT", cfg.Multipass.WorkRoot)
	cfg.Multipass.CPUs = getenvInt("CRABBOX_MULTIPASS_CPUS", cfg.Multipass.CPUs)
	cfg.Multipass.Memory = getenv("CRABBOX_MULTIPASS_MEMORY", cfg.Multipass.Memory)
	cfg.Multipass.Disk = getenv("CRABBOX_MULTIPASS_DISK", cfg.Multipass.Disk)
	if timeout := os.Getenv("CRABBOX_MULTIPASS_LAUNCH_TIMEOUT"); timeout != "" {
		applyLeaseDuration(&cfg.Multipass.LaunchTimeout, timeout)
	}
	cfg.Machine0.CLIPath = getenv("CRABBOX_MACHINE0_CLI", cfg.Machine0.CLIPath)
	cfg.Machine0.Image = getenv("CRABBOX_MACHINE0_IMAGE", cfg.Machine0.Image)
	cfg.Machine0.ImageVersion = getenvInt("CRABBOX_MACHINE0_IMAGE_VERSION", cfg.Machine0.ImageVersion)
	cfg.Machine0.DesktopImage = getenv("CRABBOX_MACHINE0_DESKTOP_IMAGE", cfg.Machine0.DesktopImage)
	if size := os.Getenv("CRABBOX_MACHINE0_SIZE"); size != "" {
		cfg.Machine0.Size = size
		cfg.Machine0.SizeExplicit = true
	}
	cfg.Machine0.Region = getenv("CRABBOX_MACHINE0_REGION", cfg.Machine0.Region)
	cfg.Machine0.Key = getenv("CRABBOX_MACHINE0_KEY", cfg.Machine0.Key)
	cfg.Machine0.WorkRoot = getenv("CRABBOX_MACHINE0_WORK_ROOT", cfg.Machine0.WorkRoot)
	cfg.Machine0.ReleasePolicy = getenv("CRABBOX_MACHINE0_RELEASE_POLICY", cfg.Machine0.ReleasePolicy)
	if timeout := os.Getenv("CRABBOX_MACHINE0_CREATE_TIMEOUT"); timeout != "" {
		applyLeaseDuration(&cfg.Machine0.CreateTimeout, timeout)
	}
	if interval := os.Getenv("CRABBOX_MACHINE0_POLL_INTERVAL"); interval != "" {
		applyLeaseDuration(&cfg.Machine0.PollInterval, interval)
	}
	if image := os.Getenv("CRABBOX_TART_IMAGE"); image != "" {
		cfg.Tart.Image = image
		cfg.tartImageExplicit = true
	}
	cfg.Tart.User = getenv("CRABBOX_TART_USER", cfg.Tart.User)
	cfg.Tart.Password = getenv("CRABBOX_TART_PASSWORD", cfg.Tart.Password)
	cfg.Tart.WorkRoot = getenv("CRABBOX_TART_WORK_ROOT", cfg.Tart.WorkRoot)
	if v := os.Getenv("CRABBOX_TART_CPUS"); v != "" {
		cfg.Tart.CPUs = getenvInt("CRABBOX_TART_CPUS", cfg.Tart.CPUs)
		cfg.tartCPUsExplicit = true
	}
	if v := os.Getenv("CRABBOX_TART_MEMORY"); v != "" {
		cfg.Tart.Memory = getenvInt("CRABBOX_TART_MEMORY", cfg.Tart.Memory)
		cfg.tartMemoryExplicit = true
	}
	if v := os.Getenv("CRABBOX_TART_DISK"); v != "" {
		cfg.Tart.Disk = getenvInt("CRABBOX_TART_DISK", cfg.Tart.Disk)
		cfg.tartDiskExplicit = cfg.Tart.Disk > 0
	}
	cfg.Lume.CLIPath = getenv("CRABBOX_LUME_CLI", cfg.Lume.CLIPath)
	cfg.Lume.Base = getenv("CRABBOX_LUME_BASE", cfg.Lume.Base)
	cfg.Lume.Storage = getenv("CRABBOX_LUME_STORAGE", cfg.Lume.Storage)
	cfg.Lume.User = getenv("CRABBOX_LUME_USER", cfg.Lume.User)
	cfg.Lume.WorkRoot = getenv("CRABBOX_LUME_WORK_ROOT", cfg.Lume.WorkRoot)
	cfg.HyperV.Image = getenv("CRABBOX_HYPERV_IMAGE", cfg.HyperV.Image)
	cfg.HyperV.User = getenv("CRABBOX_HYPERV_USER", cfg.HyperV.User)
	cfg.HyperV.WorkRoot = getenv("CRABBOX_HYPERV_WORK_ROOT", cfg.HyperV.WorkRoot)
	cfg.HyperV.CPUs = getenvInt("CRABBOX_HYPERV_CPUS", cfg.HyperV.CPUs)
	cfg.HyperV.Memory = getenvInt("CRABBOX_HYPERV_MEMORY", cfg.HyperV.Memory)
	cfg.HyperV.Switch = getenv("CRABBOX_HYPERV_SWITCH", cfg.HyperV.Switch)
	cfg.HyperV.GuestPassword = getenv("CRABBOX_HYPERV_GUEST_PASSWORD", cfg.HyperV.GuestPassword)
	if value, ok := getenvBool("CRABBOX_HYPERV_INIT_PASSWORD"); ok {
		cfg.HyperV.InitPassword = value
	}
	cfg.WindowsSandbox.Workdir = getenv("CRABBOX_WINDOWS_SANDBOX_WORKDIR", cfg.WindowsSandbox.Workdir)
	cfg.WindowsSandbox.TempRoot = expandUserPath(getenv("CRABBOX_WINDOWS_SANDBOX_TEMP_ROOT", cfg.WindowsSandbox.TempRoot))
	cfg.WindowsSandbox.Networking = getenv("CRABBOX_WINDOWS_SANDBOX_NETWORKING", cfg.WindowsSandbox.Networking)
	cfg.WindowsSandbox.VGPU = getenv("CRABBOX_WINDOWS_SANDBOX_VGPU", cfg.WindowsSandbox.VGPU)
	cfg.WindowsSandbox.Clipboard = getenv("CRABBOX_WINDOWS_SANDBOX_CLIPBOARD", cfg.WindowsSandbox.Clipboard)
	cfg.WindowsSandbox.ProtectedClient = getenv("CRABBOX_WINDOWS_SANDBOX_PROTECTED_CLIENT", cfg.WindowsSandbox.ProtectedClient)
	cfg.WindowsSandbox.AudioInput = getenv("CRABBOX_WINDOWS_SANDBOX_AUDIO_INPUT", cfg.WindowsSandbox.AudioInput)
	cfg.WindowsSandbox.VideoInput = getenv("CRABBOX_WINDOWS_SANDBOX_VIDEO_INPUT", cfg.WindowsSandbox.VideoInput)
	cfg.WindowsSandbox.PrinterRedirection = getenv("CRABBOX_WINDOWS_SANDBOX_PRINTER_REDIRECTION", cfg.WindowsSandbox.PrinterRedirection)
	cfg.WindowsSandbox.MemoryMB = getenvInt("CRABBOX_WINDOWS_SANDBOX_MEMORY_MB", cfg.WindowsSandbox.MemoryMB)
	if value, ok := getenvBool("CRABBOX_TAILSCALE"); ok {
		cfg.Tailscale.Enabled = value
	}
	if tags := os.Getenv("CRABBOX_TAILSCALE_TAGS"); tags != "" {
		cfg.Tailscale.Tags = normalizeTailscaleTags(splitCommaList(tags))
	}
	cfg.Tailscale.HostnameTemplate = getenv("CRABBOX_TAILSCALE_HOSTNAME_TEMPLATE", cfg.Tailscale.HostnameTemplate)
	cfg.Tailscale.AuthKeyEnv = getenv("CRABBOX_TAILSCALE_AUTH_KEY_ENV", cfg.Tailscale.AuthKeyEnv)
	cfg.Tailscale.ExitNode = getenv("CRABBOX_TAILSCALE_EXIT_NODE", cfg.Tailscale.ExitNode)
	if value, ok := getenvBool("CRABBOX_TAILSCALE_EXIT_NODE_ALLOW_LAN_ACCESS"); ok {
		cfg.Tailscale.ExitNodeAllowLANAccess = value
	}
	if cfg.Tailscale.AuthKeyEnv != "" {
		cfg.Tailscale.AuthKey = getenv(cfg.Tailscale.AuthKeyEnv, "")
	}
	cfg.Static.ID = getenv("CRABBOX_STATIC_ID", cfg.Static.ID)
	cfg.Static.Name = getenv("CRABBOX_STATIC_NAME", cfg.Static.Name)
	if value := os.Getenv("CRABBOX_STATIC_HOST"); value != "" {
		cfg.Static.Host = value
		cfg.credentialProvenance.staticHost = credentialSourceEnvironment
	}
	cfg.Static.User = getenv("CRABBOX_STATIC_USER", cfg.Static.User)
	cfg.Static.Port = getenv("CRABBOX_STATIC_PORT", cfg.Static.Port)
	cfg.Static.WorkRoot = getenv("CRABBOX_STATIC_WORK_ROOT", cfg.Static.WorkRoot)
	if idleTimeout := os.Getenv("CRABBOX_BLACKSMITH_IDLE_TIMEOUT"); idleTimeout != "" {
		applyLeaseDuration(&cfg.Blacksmith.IdleTimeout, idleTimeout)
	}
	if value, ok := getenvBool("CRABBOX_BLACKSMITH_DEBUG"); ok {
		cfg.Blacksmith.Debug = value
	}
	if labels := os.Getenv("CRABBOX_ACTIONS_RUNNER_LABELS"); labels != "" {
		cfg.Actions.RunnerLabels = splitCommaList(labels)
	}
	if value, ok := getenvBool("CRABBOX_ACTIONS_EPHEMERAL"); ok {
		cfg.Actions.Ephemeral = value
	}
	if junit := os.Getenv("CRABBOX_RESULTS_JUNIT"); junit != "" {
		cfg.Results.JUnit = splitCommaList(junit)
	}
	if value, ok := getenvBool("CRABBOX_RESULTS_AUTO"); ok {
		cfg.Results.Auto = value
	}
	if value, ok := getenvBool("CRABBOX_RESULTS_FAIL_ON_FAILURES"); ok {
		cfg.Results.FailOnFailures = value
	}
	if value, ok := getenvBool("CRABBOX_CACHE_PNPM"); ok {
		cfg.Cache.Pnpm = value
	}
	if value, ok := getenvBool("CRABBOX_CACHE_NPM"); ok {
		cfg.Cache.Npm = value
	}
	if value, ok := getenvBool("CRABBOX_CACHE_DOCKER"); ok {
		cfg.Cache.Docker = value
	}
	if value, ok := getenvBool("CRABBOX_CACHE_GIT"); ok {
		cfg.Cache.Git = value
	}
	cfg.Cache.MaxGB = getenvInt("CRABBOX_CACHE_MAX_GB", cfg.Cache.MaxGB)
	if value, ok := getenvBool("CRABBOX_CACHE_PURGE_ON_RELEASE"); ok {
		cfg.Cache.PurgeOnRelease = value
	}
	if volumes := os.Getenv("CRABBOX_CACHE_VOLUMES"); volumes != "" {
		parsed, err := ParseCacheVolumeSpecs(splitCommaList(volumes))
		if err != nil {
			return err
		}
		cfg.Cache.Volumes = parsed
	}
	if regions := os.Getenv("CRABBOX_CAPACITY_REGIONS"); regions != "" {
		cfg.Capacity.Regions = splitCommaList(regions)
	}
	if zones := os.Getenv("CRABBOX_CAPACITY_AVAILABILITY_ZONES"); zones != "" {
		cfg.Capacity.AvailabilityZones = splitCommaList(zones)
	}
	if value, ok := getenvBool("CRABBOX_SYNC_CHECKSUM"); ok {
		cfg.Sync.Checksum = value
	}
	if value, ok := getenvBool("CRABBOX_SYNC_DELETE"); ok {
		cfg.Sync.Delete = value
	}
	if value, ok := getenvBool("CRABBOX_SYNC_GIT_SEED"); ok {
		cfg.Sync.GitSeed = value
	}
	if value, ok := getenvBool("CRABBOX_SYNC_GIT_OVERLAY"); ok {
		cfg.Sync.GitOverlay = value
	}
	if value, ok := getenvBool("CRABBOX_SYNC_FINGERPRINT"); ok {
		cfg.Sync.Fingerprint = value
	}
	if timeout := os.Getenv("CRABBOX_SYNC_TIMEOUT"); timeout != "" {
		if parsed, err := time.ParseDuration(timeout); err == nil {
			cfg.Sync.Timeout = parsed
		}
	}
	cfg.Sync.WarnFiles = getenvInt("CRABBOX_SYNC_WARN_FILES", cfg.Sync.WarnFiles)
	cfg.Sync.WarnBytes = int64(getenvInt("CRABBOX_SYNC_WARN_BYTES", int(cfg.Sync.WarnBytes)))
	cfg.Sync.FailFiles = getenvInt("CRABBOX_SYNC_FAIL_FILES", cfg.Sync.FailFiles)
	cfg.Sync.FailBytes = int64(getenvInt("CRABBOX_SYNC_FAIL_BYTES", int(cfg.Sync.FailBytes)))
	if value, ok := getenvBool("CRABBOX_SYNC_ALLOW_LARGE"); ok {
		cfg.Sync.AllowLarge = value
	}
	cfg.Sync.BaseRef = getenv("CRABBOX_SYNC_BASE_REF", cfg.Sync.BaseRef)
	if envAllow := os.Getenv("CRABBOX_ENV_ALLOW"); envAllow != "" {
		cfg.EnvAllow = splitCommaList(envAllow)
		cfg.envAllowOverriddenByEnv = true
	}
	if tools := os.Getenv("CRABBOX_PREFLIGHT_TOOLS"); tools != "" {
		cfg.Run.PreflightTools = parsePreflightToolsOverride(tools)
	}
	return nil
}

// ApplyExternalDesktopEnvironmentOverrides reapplies process-local desktop
// credential references after persisted routing replaces External config.

// ApplyExternalDesktopEnvironmentOverrides reapplies process-local desktop
// credential references after persisted routing replaces External config.
func ApplyExternalDesktopEnvironmentOverrides(cfg *Config) {
	if cfg == nil {
		return
	}
	PreserveExternalDesktopChildEnvironmentBoundary(cfg)
	configuredPasswordEnv := strings.TrimSpace(cfg.External.Connection.Desktop.PasswordEnv)
	if !strings.EqualFold(configuredPasswordEnv, "CRABBOX_EXTERNAL_DESKTOP_USERNAME") {
		cfg.External.Connection.Desktop.Username = getenv("CRABBOX_EXTERNAL_DESKTOP_USERNAME", cfg.External.Connection.Desktop.Username)
	}
	if os.Getenv("CRABBOX_EXTERNAL_DESKTOP_USERNAME") != "" && !strings.EqualFold(configuredPasswordEnv, "CRABBOX_EXTERNAL_DESKTOP_USERNAME") {
		cfg.credentialProvenance.externalDesktopUser = credentialSourceEnvironment
	}
	if value := os.Getenv("CRABBOX_EXTERNAL_DESKTOP_PASSWORD_ENV"); value != "" && !strings.EqualFold(configuredPasswordEnv, "CRABBOX_EXTERNAL_DESKTOP_PASSWORD_ENV") {
		cfg.External.Connection.Desktop.PasswordEnv = value
		cfg.credentialProvenance.externalDesktopEnv = credentialSourceEnvironment
	}
}

func expandUserPath(path string) string {
	if path == "~" {
		home, _ := os.UserHomeDir()
		if home != "" {
			return home
		}
	}
	if strings.HasPrefix(path, "~/") {
		home, _ := os.UserHomeDir()
		if home != "" {
			return filepath.Join(home, strings.TrimPrefix(path, "~/"))
		}
	}
	return path
}

func redactRemoteURL(value string) string {
	value = strings.TrimSpace(value)
	parsed, err := url.Parse(value)
	if err != nil {
		lower := strings.ToLower(value)
		if strings.HasPrefix(lower, "http://") || strings.HasPrefix(lower, "https://") {
			return "<remote-image>"
		}
		return value
	}
	if !strings.EqualFold(parsed.Scheme, "http") && !strings.EqualFold(parsed.Scheme, "https") {
		return value
	}
	return "<remote-image>"
}

func getenv(name, fallback string) string {
	if v := os.Getenv(name); v != "" {
		return v
	}
	return fallback
}

func getenvInt(name string, fallback int) int {
	v := os.Getenv(name)
	if v == "" {
		return fallback
	}
	n, err := strconv.Atoi(v)
	if err != nil {
		return fallback
	}
	return n
}

func getenvNonNegativeInt(name string, fallback int) (int, error) {
	value := os.Getenv(name)
	if value == "" {
		return fallback, nil
	}
	parsed, err := strconv.Atoi(value)
	if err != nil {
		return 0, exit(2, "%s must be an integer", name)
	}
	if parsed < 0 {
		return 0, exit(2, "%s must be non-negative", name)
	}
	return parsed, nil
}

func getenvInt32(name string, fallback int32) int32 {
	v := os.Getenv(name)
	if v == "" {
		return fallback
	}
	n, err := strconv.ParseInt(v, 10, 32)
	if err != nil {
		return fallback
	}
	return int32(n)
}

func getenvInt64(name string, fallback int64) int64 {
	v := os.Getenv(name)
	if v == "" {
		return fallback
	}
	n, err := strconv.ParseInt(v, 10, 64)
	if err != nil {
		return fallback
	}
	return n
}

func getenvFloat(name string, fallback float64) float64 {
	v := os.Getenv(name)
	if v == "" {
		return fallback
	}
	n, err := strconv.ParseFloat(v, 64)
	if err != nil {
		return fallback
	}
	return n
}

func getenvBool(name string) (bool, bool) {
	v := strings.TrimSpace(os.Getenv(name))
	if v == "" {
		return false, false
	}
	switch strings.ToLower(v) {
	case "1", "true", "yes", "on":
		return true, true
	case "0", "false", "no", "off":
		return false, true
	default:
		return false, false
	}
}

func getenvList(name string) ([]string, bool) {
	value, ok := os.LookupEnv(name)
	if !ok {
		return nil, false
	}
	if strings.EqualFold(strings.TrimSpace(value), "none") {
		return []string{}, true
	}
	return splitCommaList(value), true
}

func splitCommaList(value string) []string {
	parts := strings.Split(value, ",")
	return normalizeList(parts)
}

func parseLambdaFilesystemMounts(value string) []LambdaFilesystemMount {
	parts := splitCommaList(value)
	out := make([]LambdaFilesystemMount, 0, len(parts))
	for _, part := range parts {
		name, mountPath, ok := strings.Cut(part, ":")
		if !ok {
			out = append(out, LambdaFilesystemMount{Name: strings.TrimSpace(part)})
			continue
		}
		out = append(out, LambdaFilesystemMount{Name: strings.TrimSpace(name), MountPath: strings.TrimSpace(mountPath)})
	}
	return out
}

func normalizeList(values []string) []string {
	out := make([]string, 0, len(values))
	for _, part := range values {
		part = strings.TrimSpace(part)
		if part != "" {
			out = append(out, part)
		}
	}
	return out
}

func appendUniqueStrings(values []string, extra ...string) []string {
	seen := map[string]bool{}
	out := make([]string, 0, len(values)+len(extra))
	for _, value := range append(values, extra...) {
		value = strings.TrimSpace(value)
		if value == "" || seen[value] {
			continue
		}
		seen[value] = true
		out = append(out, value)
	}
	return out
}

func appendOrderedStrings(values []string, extra ...string) []string {
	out := append([]string(nil), values...)
	for _, value := range extra {
		if value = strings.TrimSpace(value); value != "" {
			out = append(out, value)
		}
	}
	return out
}
