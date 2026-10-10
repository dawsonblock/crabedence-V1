package cli

import (
	"os"
	"path/filepath"
	"strings"
	"time"
)

type providerSelectionSource string

const providerSelectionRequiredDiagnostic = "no provider selected; use --provider <name>, set CRABBOX_PROVIDER, or configure a provider; run 'crabbox providers recommend' to compare options"

const (
	providerSelectionCompiledDefault providerSelectionSource = "compiled_default"
	providerSelectionUserConfig      providerSelectionSource = "user_config"
	providerSelectionRepoConfig      providerSelectionSource = "repo_config"
	providerSelectionEnvironment     providerSelectionSource = "environment"
	providerSelectionFlag            providerSelectionSource = "flag"
	providerSelectionRecordedRun     providerSelectionSource = "recorded_run"
	providerSelectionLeaseContext    providerSelectionSource = "lease_context"
)

func setProviderSelection(cfg *Config, provider string, source providerSelectionSource) {
	cfg.Provider = provider
	cfg.providerSelectionSource = source
}

func providerSelectionIsActionable(cfg Config) bool {
	if strings.TrimSpace(cfg.Provider) == "" {
		return false
	}
	switch cfg.providerSelectionSource {
	case providerSelectionUserConfig,
		providerSelectionRepoConfig,
		providerSelectionEnvironment,
		providerSelectionFlag,
		providerSelectionRecordedRun,
		providerSelectionLeaseContext:
		return true
	default:
		return false
	}
}

func providerSelectionIsAuthoritativeRoute(cfg Config) bool {
	switch cfg.providerSelectionSource {
	case providerSelectionRecordedRun, providerSelectionLeaseContext:
		return true
	default:
		return false
	}
}

func providerSelectionSourceForConfigPath(trust configPathTrust) providerSelectionSource {
	if !trust.trusted {
		return providerSelectionRepoConfig
	}
	return providerSelectionUserConfig
}

type BrokerMode string

const (
	BrokerModeManaged    BrokerMode = "managed"
	BrokerModeRegistered BrokerMode = "registered"
)

func defaultConfig() Config {
	cfg, err := loadConfig()
	if err != nil {
		return baseConfig()
	}
	return cfg
}

func loadConfig() (Config, error) {
	return loadConfigWithOverrides("", "")
}

func loadConfigWithOverrides(coordinator, provider string) (Config, error) {
	cfg := baseConfig()
	for _, path := range configPaths() {
		trust := classifyConfigPath(path)
		freestyleAPIURL := cfg.Freestyle.APIURL
		if err := applyConfigFile(&cfg, path, trust); err != nil {
			return Config{}, err
		}
		if !trust.trusted {
			cfg.Freestyle.APIURL = freestyleAPIURL
		}
	}
	if err := applyEnv(&cfg); err != nil {
		return Config{}, err
	}
	// Validate this cross-provider environment destination before provider
	// dispatch. The selected value may itself be CRABBOX_PROVIDER, so waiting
	// for External provider validation would let that value route around it.
	if err := ValidateExternalDesktopPasswordEnvironmentName(cfg.External.Connection.Desktop.PasswordEnv); err != nil {
		return Config{}, exit(2, "%v", err)
	}
	applyCloudflareDynamicWorkersRepositoryCaps(&cfg)
	if coordinator = strings.TrimSpace(coordinator); coordinator != "" {
		cfg.Coordinator = coordinator
		markCoordinatorDestinationExplicit(&cfg)
	}
	if provider = strings.TrimSpace(provider); provider != "" {
		setProviderSelection(&cfg, provider, providerSelectionFlag)
		cfg.brokerProvider = ""
	}
	if err := normalizeBrokerConfig(&cfg); err != nil {
		return Config{}, err
	}
	canonicalizeConfigProvider(&cfg)
	if err := routeConfiguredProvider(&cfg); err != nil {
		return Config{}, err
	}
	if err := applyProviderConfigDefaults(&cfg); err != nil {
		return Config{}, err
	}
	normalizeTargetConfig(&cfg)
	if err := validateTargetConfig(cfg); err != nil {
		return Config{}, err
	}
	if err := validateNetworkConfig(cfg); err != nil {
		return Config{}, err
	}
	if cfg.ServerType == "" {
		cfg.ServerType = serverTypeForConfig(cfg)
	}
	return cfg, nil
}

func normalizeBrokerConfig(cfg *Config) error {
	mode, err := normalizeBrokerMode(string(cfg.BrokerMode))
	if err != nil {
		return err
	}
	cfg.BrokerMode = mode
	if mode == BrokerModeRegistered && strings.TrimSpace(cfg.Coordinator) == "" {
		return exit(2, "broker.mode=registered requires broker.url or coordinator")
	}
	return nil
}

func normalizeBrokerMode(value string) (BrokerMode, error) {
	mode := BrokerMode(strings.ToLower(strings.TrimSpace(value)))
	if mode == "" {
		mode = BrokerModeManaged
	}
	switch mode {
	case BrokerModeManaged, BrokerModeRegistered:
		return mode, nil
	default:
		return "", exit(2, "broker.mode must be managed or registered")
	}
}

func canonicalizeConfigProvider(cfg *Config) {
	provider, err := ProviderFor(cfg.Provider)
	if err == nil {
		cfg.Provider = provider.Name()
	}
}

func prepareProviderSelection(cfg *Config, provider string) error {
	cfg.Provider = strings.TrimSpace(provider)
	prepareProviderDefaults(cfg)
	return nil
}

func finalizeProviderSelection(cfg *Config) error {
	if err := routeConfiguredProvider(cfg); err != nil {
		return err
	}
	return applyProviderConfigDefaults(cfg)
}

func applyLinuxConnectionDefaults(cfg *Config, defaultSSHUser, defaultSSHPort string) {
	if !IsTargetExplicit(cfg) {
		cfg.TargetOS = targetLinux
	}
	if cfg.explicitWindowsMode != "" {
		cfg.WindowsMode = cfg.explicitWindowsMode
	} else {
		cfg.WindowsMode = windowsModeNormal
	}
	if cfg.explicitWorkRoot != "" {
		cfg.WorkRoot = cfg.explicitWorkRoot
	} else {
		cfg.WorkRoot = defaultPOSIXWorkRoot
	}
	if cfg.explicitSSHUser != "" {
		cfg.SSHUser = cfg.explicitSSHUser
	} else {
		cfg.SSHUser = defaultSSHUser
	}
	if cfg.explicitSSHPort != "" {
		cfg.SSHPort = cfg.explicitSSHPort
	} else {
		cfg.SSHPort = defaultSSHPort
	}
}

func applyProviderConfigDefaults(cfg *Config) error {
	prepareProviderDefaults(cfg)
	if normalized, err := normalizeArchitecture(cfg.Architecture); err != nil {
		return err
	} else {
		cfg.Architecture = normalized
	}
	if normalized, err := normalizeOSImage(cfg.OSImage); err != nil {
		return err
	} else {
		cfg.OSImage = normalized
	}
	applySingleProviderTargetDefault(cfg)
	applyOSImageProviderDefaults(cfg, false)
	if provider, err := ProviderFor(cfg.Provider); err == nil {
		if defaulter, ok := provider.(ProviderConfigDefaulter); ok {
			if err := defaulter.ApplyConfigDefaults(cfg); err != nil {
				return err
			}
			normalizeTargetConfig(cfg)
			return validateTargetConfig(*cfg)
		}
	}
	if cfg.Provider == "digitalocean" {
		if cfg.DigitalOcean.Region == "" {
			cfg.DigitalOcean.Region = "nyc3"
		}
		if cfg.osImageExplicit && !cfg.digitalOceanImageExplicit {
			if cfg.OSImage == "ubuntu:24.04" {
				cfg.DigitalOcean.Image = "ubuntu-24-04-x64"
			} else {
				cfg.DigitalOcean.Image = ""
			}
		} else if cfg.DigitalOcean.Image == "" {
			cfg.DigitalOcean.Image = "ubuntu-24-04-x64"
		}
		applyLinuxConnectionDefaults(cfg, baseConfig().SSHUser, baseConfig().SSHPort)
		normalizeTargetConfig(cfg)
		return validateTargetConfig(*cfg)
	}
	if cfg.Provider == "vultr" {
		if cfg.Vultr.Region == "" {
			cfg.Vultr.Region = "ewr"
		}
		if cfg.Vultr.UserScheme == "" {
			cfg.Vultr.UserScheme = "root"
		}
		applyLinuxConnectionDefaults(cfg, "root", "22")
		cfg.SSHFallbackPorts = nil
		normalizeTargetConfig(cfg)
		return validateTargetConfig(*cfg)
	}
	if cfg.Provider == "linode" {
		if cfg.Linode.Region == "" {
			cfg.Linode.Region = "us-ord"
		}
		if cfg.osImageExplicit && !cfg.linodeImageExplicit {
			if cfg.OSImage == "ubuntu:24.04" {
				cfg.Linode.Image = "linode/ubuntu24.04"
			} else {
				cfg.Linode.Image = ""
			}
		} else if cfg.Linode.Image == "" {
			cfg.Linode.Image = "linode/ubuntu24.04"
		}
		if cfg.Linode.Type == "" {
			cfg.Linode.Type = "g6-standard-1"
		}
		applyLinuxConnectionDefaults(cfg, baseConfig().SSHUser, baseConfig().SSHPort)
		normalizeTargetConfig(cfg)
		return validateTargetConfig(*cfg)
	}
	if cfg.Provider == "lambda" {
		if cfg.Lambda.Region == "" {
			cfg.Lambda.Region = "us-west-1"
		}
		if cfg.Lambda.Type == "" {
			cfg.Lambda.Type = "gpu_1x_a10"
		}
		if cfg.osImageExplicit && !cfg.lambdaImageExplicit && !cfg.lambdaImageFamilyExplicit {
			if cfg.OSImage == "ubuntu:24.04" {
				cfg.Lambda.ImageFamily = "lambda-stack-24-04"
			} else {
				cfg.Lambda.ImageFamily = ""
			}
		} else if cfg.Lambda.Image == "" && cfg.Lambda.ImageFamily == "" {
			cfg.Lambda.ImageFamily = "lambda-stack-24-04"
		}
		applyLinuxConnectionDefaults(cfg, "ubuntu", "22")
		cfg.SSHFallbackPorts = nil
		normalizeTargetConfig(cfg)
		return validateTargetConfig(*cfg)
	}
	if cfg.Provider == "vast" {
		cfg.Vast.InstanceType = normalizeVastInstanceType(cfg.Vast.InstanceType)
		if cfg.Vast.APIURL == "" {
			cfg.Vast.APIURL = "https://console.vast.ai/api/v0"
		}
		if cfg.Vast.InstanceType == "" {
			cfg.Vast.InstanceType = "ondemand"
		}
		if cfg.Vast.Image == "" {
			cfg.Vast.Image = "nvidia/cuda:12.8.1-cudnn-devel-ubuntu22.04"
		}
		if cfg.Vast.Runtype == "" {
			cfg.Vast.Runtype = "ssh_direct"
		}
		if cfg.Vast.DiskGB == 0 {
			cfg.Vast.DiskGB = 20
		}
		if cfg.Vast.Order == "" {
			cfg.Vast.Order = "dlperf_per_dphtotal desc"
		}
		if cfg.Vast.User == "" {
			cfg.Vast.User = "root"
		}
		if cfg.Vast.WorkRoot == "" {
			cfg.Vast.WorkRoot = defaultPOSIXWorkRoot
		}
		if cfg.Vast.ReleaseAction == "" {
			cfg.Vast.ReleaseAction = "destroy"
		}
		if !IsTargetExplicit(cfg) {
			cfg.TargetOS = targetLinux
		}
		if cfg.explicitWindowsMode != "" {
			cfg.WindowsMode = cfg.explicitWindowsMode
		} else {
			cfg.WindowsMode = windowsModeNormal
		}
		if cfg.explicitWorkRoot != "" && !IsVastWorkRootExplicit(cfg) {
			cfg.Vast.WorkRoot = cfg.explicitWorkRoot
		}
		cfg.WorkRoot = cfg.Vast.WorkRoot
		if cfg.explicitSSHUser != "" {
			cfg.SSHUser = cfg.explicitSSHUser
		} else {
			cfg.SSHUser = cfg.Vast.User
		}
		if cfg.explicitSSHPort != "" {
			cfg.SSHPort = cfg.explicitSSHPort
		} else {
			cfg.SSHPort = "22"
		}
		cfg.SSHFallbackPorts = nil
		normalizeTargetConfig(cfg)
		return validateTargetConfig(*cfg)
	}
	if cfg.Provider == "nebius" {
		if cfg.Nebius.CLI == "" {
			cfg.Nebius.CLI = "nebius"
		}
		if cfg.Nebius.Platform == "" {
			cfg.Nebius.Platform = "cpu-d3"
		}
		if cfg.Nebius.Preset == "" {
			cfg.Nebius.Preset = "4vcpu-16gb"
		}
		if cfg.Nebius.ImageFamily == "" {
			cfg.Nebius.ImageFamily = "ubuntu24.04-driverless"
		}
		if cfg.Nebius.DiskType == "" {
			cfg.Nebius.DiskType = "network_ssd"
		}
		if cfg.Nebius.DiskSizeGiB == 0 {
			cfg.Nebius.DiskSizeGiB = 50
		}
		if cfg.Nebius.User == "" {
			cfg.Nebius.User = "crabbox"
		}
		if cfg.Nebius.PublicIP == "" {
			cfg.Nebius.PublicIP = "dynamic"
		}
		if cfg.Nebius.RecoveryPolicy == "" {
			cfg.Nebius.RecoveryPolicy = "fail"
		}
		applyLinuxConnectionDefaults(cfg, cfg.Nebius.User, baseConfig().SSHPort)
		normalizeTargetConfig(cfg)
		return validateTargetConfig(*cfg)
	}
	if cfg.Provider == "ovh" {
		if cfg.OVH.Endpoint == "" {
			cfg.OVH.Endpoint = "https://api.us.ovhcloud.com/1.0"
		}
		if cfg.OVH.Image == "" {
			cfg.OVH.Image = "Ubuntu 24.04"
		}
		if cfg.OVH.Flavor == "" {
			cfg.OVH.Flavor = "b3-8"
		}
		applyLinuxConnectionDefaults(cfg, baseConfig().SSHUser, baseConfig().SSHPort)
		normalizeTargetConfig(cfg)
		return validateTargetConfig(*cfg)
	}
	if cfg.Provider == "scaleway" {
		if cfg.Scaleway.Region == "" {
			cfg.Scaleway.Region = "fr-par"
		}
		if cfg.Scaleway.Zone == "" {
			cfg.Scaleway.Zone = "fr-par-1"
		}
		if cfg.osImageExplicit && !cfg.scalewayImageExplicit {
			if cfg.OSImage == "ubuntu:24.04" {
				cfg.Scaleway.Image = "ubuntu_noble"
			} else {
				cfg.Scaleway.Image = ""
			}
		} else if cfg.Scaleway.Image == "" {
			cfg.Scaleway.Image = "ubuntu_noble"
		}
		if cfg.Scaleway.Type == "" {
			cfg.Scaleway.Type = "DEV1-S"
		}
		applyLinuxConnectionDefaults(cfg, "root", "22")
		normalizeTargetConfig(cfg)
		return validateTargetConfig(*cfg)
	}
	if cfg.Provider == "tencentcloud" {
		if cfg.TencentCloud.Region == "" {
			cfg.TencentCloud.Region = "ap-shanghai"
		}
		if cfg.TencentCloud.Zone == "" {
			cfg.TencentCloud.Zone = "ap-shanghai-2"
		}
		if cfg.TencentCloud.Type == "" {
			cfg.TencentCloud.Type = "SA5.MEDIUM2"
		}
		if cfg.TencentCloud.RootGB == 0 {
			cfg.TencentCloud.RootGB = 50
		}
		if cfg.TencentCloud.InternetChargeType == "" {
			cfg.TencentCloud.InternetChargeType = "TRAFFIC_POSTPAID_BY_HOUR"
		}
		if cfg.TencentCloud.InternetMaxBandwidthOut == 0 {
			cfg.TencentCloud.InternetMaxBandwidthOut = 5
		}
		applyLinuxConnectionDefaults(cfg, "ubuntu", "22")
		cfg.SSHFallbackPorts = nil
		normalizeTargetConfig(cfg)
		return validateTargetConfig(*cfg)
	}
	if cfg.Provider == "hyperv" {
		if !IsTargetExplicit(cfg) {
			cfg.TargetOS = targetWindows
		}
		cfg.SSHFallbackPorts = nil
		if cfg.HyperV.User != "" {
			cfg.SSHUser = cfg.HyperV.User
		}
		if cfg.HyperV.WorkRoot != "" {
			cfg.WorkRoot = cfg.HyperV.WorkRoot
		}
		cfg.SSHPort = "22"
		return nil
	}
	if cfg.Provider == "windows-sandbox" || cfg.Provider == "wsb" || cfg.Provider == "windows-sandbox-provider" {
		if IsTargetExplicit(cfg) && normalizeTargetOS(cfg.TargetOS) != targetWindows {
			return exit(2, "provider=windows-sandbox supports target=windows only")
		}
		if cfg.TargetOS == "" || (!IsTargetExplicit(cfg) && cfg.TargetOS == targetLinux) {
			cfg.TargetOS = targetWindows
		}
		if cfg.explicitWindowsMode != "" && normalizeWindowsMode(cfg.explicitWindowsMode) != windowsModeNormal {
			return exit(2, "provider=windows-sandbox supports windows.mode=normal only")
		}
		cfg.WindowsMode = windowsModeNormal
		if cfg.WindowsSandbox.Workdir == "" {
			cfg.WindowsSandbox.Workdir = `C:\crabbox-work`
		}
		cfg.WorkRoot = cfg.WindowsSandbox.Workdir
		return nil
	}
	if cfg.Provider == "exe-dev" || cfg.Provider == "exedev" || cfg.Provider == "exe" {
		if cfg.ExeDev.User != "" {
			cfg.SSHUser = cfg.ExeDev.User
		} else if cfg.SSHUser == baseConfig().SSHUser {
			cfg.SSHUser = getenv("USER", cfg.SSHUser)
		}
		if cfg.SSHPort == "" || cfg.SSHPort == baseConfig().SSHPort {
			cfg.SSHPort = "22"
		}
		cfg.SSHFallbackPorts = nil
		if cfg.ExeDev.WorkRoot == "" {
			if !isDefaultWorkRoot(cfg.WorkRoot) {
				cfg.ExeDev.WorkRoot = cfg.WorkRoot
			} else {
				cfg.ExeDev.WorkRoot = "/tmp/crabbox"
			}
		}
		if cfg.ExeDev.WorkRoot != "" {
			cfg.WorkRoot = cfg.ExeDev.WorkRoot
		}
		if cfg.TargetOS == "" {
			cfg.TargetOS = targetLinux
		}
		return nil
	}
	if cfg.Provider == "tart" || cfg.Provider == "local-tart" || cfg.Provider == "macos-vm" {
		if cfg.Tart.User != "" {
			cfg.SSHUser = cfg.Tart.User
		}
		if cfg.SSHPort == "" || cfg.SSHPort == baseConfig().SSHPort {
			cfg.SSHPort = "22"
		}
		cfg.SSHFallbackPorts = nil
		if cfg.Tart.WorkRoot != "" {
			cfg.WorkRoot = cfg.Tart.WorkRoot
		}
		if !IsTargetExplicit(cfg) && (cfg.TargetOS == "" || cfg.TargetOS == targetLinux) {
			cfg.TargetOS = targetMacOS
		}
		if !cfg.ServerTypeExplicit && cfg.Tart.Image != "" {
			cfg.ServerType = cfg.Tart.Image
		}
		return nil
	}
	if cfg.Provider == "lume" || cfg.Provider == "local-lume" || cfg.Provider == "lume-macos" {
		if cfg.Lume.User != "" {
			cfg.SSHUser = cfg.Lume.User
		}
		if cfg.SSHPort == "" || cfg.SSHPort == baseConfig().SSHPort {
			cfg.SSHPort = "22"
		}
		cfg.SSHFallbackPorts = nil
		if cfg.Lume.WorkRoot != "" {
			cfg.WorkRoot = cfg.Lume.WorkRoot
		}
		if !IsTargetExplicit(cfg) && (cfg.TargetOS == "" || cfg.TargetOS == targetLinux) {
			cfg.TargetOS = targetMacOS
		}
		if !cfg.ServerTypeExplicit && cfg.Lume.Base != "" {
			cfg.ServerType = cfg.Lume.Base
		}
		return nil
	}
	if cfg.Provider == "apple-vm" || cfg.Provider == "applevm" {
		if cfg.AppleVM.User != "" {
			cfg.SSHUser = cfg.AppleVM.User
		}
		if cfg.SSHPort == "" || cfg.SSHPort == baseConfig().SSHPort {
			cfg.SSHPort = "22"
		}
		cfg.SSHFallbackPorts = nil
		base := baseConfig()
		if cfg.AppleVM.WorkRoot != "" && (IsDefaultWorkRoot(cfg.WorkRoot) || cfg.AppleVM.WorkRoot != base.AppleVM.WorkRoot) {
			cfg.WorkRoot = cfg.AppleVM.WorkRoot
		}
		if cfg.TargetOS == "" {
			cfg.TargetOS = targetLinux
		}
		if !cfg.ServerTypeExplicit && cfg.AppleVM.Image != "" {
			cfg.ServerType = redactRemoteURL(cfg.AppleVM.Image)
		}
		return nil
	}
	if cfg.Provider == "incus" {
		base := baseConfig()
		if cfg.Incus.User != "" && (cfg.SSHUser == "" || cfg.SSHUser == base.SSHUser || cfg.Incus.User != base.Incus.User) {
			cfg.SSHUser = cfg.Incus.User
		}
		if cfg.SSHPort == "" || cfg.SSHPort == base.SSHPort {
			cfg.SSHPort = blank(cfg.Incus.ProxyListenPort, "22")
		}
		cfg.SSHFallbackPorts = nil
		if cfg.Incus.WorkRoot != "" && (isDefaultWorkRoot(cfg.WorkRoot) || cfg.Incus.WorkRoot != base.Incus.WorkRoot) {
			cfg.WorkRoot = cfg.Incus.WorkRoot
		}
		if cfg.TargetOS == "" {
			cfg.TargetOS = targetLinux
		}
		if !cfg.ServerTypeExplicit {
			cfg.ServerType = incusServerTypeForConfig(*cfg)
		}
		return nil
	}
	if cfg.Provider == "coder" {
		base := baseConfig()
		if cfg.SSHUser == "" || cfg.SSHUser == base.SSHUser {
			cfg.SSHUser = "coder"
		}
		if cfg.SSHPort == "" || cfg.SSHPort == base.SSHPort {
			cfg.SSHPort = "22"
		}
		cfg.SSHFallbackPorts = nil
		if !isDefaultWorkRoot(cfg.WorkRoot) && (cfg.Coder.WorkRoot == "" || cfg.Coder.WorkRoot == base.Coder.WorkRoot) {
			cfg.Coder.WorkRoot = cfg.WorkRoot
		} else if cfg.Coder.WorkRoot == "" {
			cfg.Coder.WorkRoot = base.Coder.WorkRoot
		}
		if cfg.Coder.WorkRoot != "" {
			cfg.WorkRoot = cfg.Coder.WorkRoot
		}
		if cfg.TargetOS == "" {
			cfg.TargetOS = targetLinux
		}
		return nil
	}
	if cfg.Provider == "nomad" {
		if !IsTargetExplicit(cfg) {
			cfg.TargetOS = targetLinux
		}
		if cfg.Nomad.Workdir != "" {
			cfg.WorkRoot = cfg.Nomad.Workdir
		}
		cfg.SSHFallbackPorts = nil
		return nil
	}
	if cfg.Provider == "firecracker" {
		base := baseConfig()
		if cfg.Firecracker.User != "" && (cfg.SSHUser == "" || cfg.SSHUser == base.SSHUser || cfg.Firecracker.User != base.Firecracker.User) {
			cfg.SSHUser = cfg.Firecracker.User
		}
		if cfg.SSHPort == "" || cfg.SSHPort == base.SSHPort {
			cfg.SSHPort = "22"
		}
		cfg.SSHFallbackPorts = nil
		if cfg.Firecracker.WorkRoot != "" && (isDefaultWorkRoot(cfg.WorkRoot) || cfg.Firecracker.WorkRoot != base.Firecracker.WorkRoot) {
			cfg.WorkRoot = cfg.Firecracker.WorkRoot
		}
		if cfg.TargetOS == "" {
			cfg.TargetOS = targetLinux
		}
		if !cfg.ServerTypeExplicit {
			cfg.ServerType = firecrackerServerTypeForConfig(*cfg)
		}
		return nil
	}
	if cfg.Provider != "proxmox" {
		if cfg.Provider == "xcp-ng" {
			if cfg.XCPNg.User != "" {
				cfg.SSHUser = cfg.XCPNg.User
			}
			if cfg.XCPNg.WorkRoot != "" {
				cfg.WorkRoot = cfg.XCPNg.WorkRoot
			}
			return nil
		}
		if cfg.Provider != "parallels" {
			return nil
		}
		if cfg.Parallels.Template != "" && !cfg.parallelsTemplateApplied {
			if err := ApplyParallelsTemplateConfig(cfg, cfg.Parallels.Template); err != nil {
				return err
			}
		}
		if cfg.Parallels.User != "" {
			cfg.SSHUser = cfg.Parallels.User
		}
		if cfg.Parallels.WorkRoot != "" {
			cfg.WorkRoot = cfg.Parallels.WorkRoot
		}
		return nil
	}
	if cfg.Proxmox.User != "" {
		cfg.SSHUser = cfg.Proxmox.User
	}
	if cfg.Proxmox.WorkRoot != "" {
		cfg.WorkRoot = cfg.Proxmox.WorkRoot
	}
	return nil
}

func applySingleProviderTargetDefault(cfg *Config) {
	if cfg == nil {
		return
	}
	provider, err := ProviderFor(cfg.Provider)
	if err != nil {
		return
	}
	providerName := provider.Name()
	if IsTargetExplicit(cfg) {
		cfg.inferredTargetProvider = ""
		return
	}
	if cfg.inferredTargetProvider != "" && cfg.inferredTargetProvider != providerName {
		cfg.TargetOS = targetLinux
		cfg.inferredTargetProvider = ""
		if cfg.explicitWindowsMode != "" {
			cfg.WindowsMode = cfg.explicitWindowsMode
		} else {
			cfg.WindowsMode = windowsModeNormal
		}
	}
	if cfg.TargetOS != "" && cfg.TargetOS != targetLinux {
		return
	}
	spec := provider.Spec()
	if len(spec.Targets) != 1 {
		return
	}
	target := spec.Targets[0]
	if strings.TrimSpace(target.OS) == "" {
		return
	}
	cfg.TargetOS = strings.TrimSpace(target.OS)
	cfg.inferredTargetProvider = providerName
	if cfg.TargetOS == targetWindows {
		if strings.TrimSpace(target.WindowsMode) != "" {
			cfg.WindowsMode = strings.TrimSpace(target.WindowsMode)
		}
	} else if cfg.explicitWindowsMode == "" {
		cfg.WindowsMode = windowsModeNormal
	}
}

func prepareProviderDefaults(cfg *Config) {
	provider, err := ProviderFor(cfg.Provider)
	if err != nil {
		return
	}
	providerName := provider.Name()
	if cfg.providerDefaultsApplied != "" && cfg.providerDefaultsApplied != providerName {
		if cfg.providerDefaultsApplied == parallelsProvider {
			cfg.parallelsTemplateApplied = false
		}
		resetProviderDerivedDefaults(cfg)
		if !IsTargetExplicit(cfg) && cfg.inferredTargetProvider != "" {
			cfg.TargetOS = targetLinux
			cfg.inferredTargetProvider = ""
			if cfg.explicitWindowsMode != "" {
				cfg.WindowsMode = cfg.explicitWindowsMode
			} else {
				cfg.WindowsMode = windowsModeNormal
			}
		}
	}
	cfg.providerDefaultsApplied = providerName
}

func resetProviderDerivedDefaults(cfg *Config) {
	base := baseConfig()
	if cfg.explicitSSHUser != "" {
		cfg.SSHUser = cfg.explicitSSHUser
	} else {
		cfg.SSHUser = base.SSHUser
	}
	if cfg.explicitSSHPort != "" {
		cfg.SSHPort = cfg.explicitSSHPort
	} else {
		cfg.SSHPort = base.SSHPort
	}
	if !cfg.sshFallbackPortsExplicit {
		cfg.SSHFallbackPorts = append([]string(nil), base.SSHFallbackPorts...)
	} else {
		cfg.SSHFallbackPorts = append([]string(nil), cfg.explicitSSHFallbackPorts...)
	}
	if cfg.explicitWorkRoot != "" {
		cfg.WorkRoot = cfg.explicitWorkRoot
	} else {
		cfg.WorkRoot = base.WorkRoot
	}
	if !cfg.locationExplicit {
		cfg.Location = base.Location
	}
	if !cfg.imageExplicit {
		cfg.Image = base.Image
	}
	if !cfg.ServerTypeExplicit {
		cfg.ServerType = base.ServerType
	}
}

func applyOSImageProviderDefaults(cfg *Config, force bool) {
	if normalizeTargetOS(cfg.TargetOS) != targetLinux {
		return
	}
	hetznerImage, azureImage, gcpImage, linodeImage, isloImage, containerImage, err := osImageDefaultProviderImagesForArchitecture(cfg.OSImage, effectiveArchitectureForConfig(*cfg))
	if err != nil {
		return
	}
	multipassImage, err := osImageDefaultMultipassImage(cfg.OSImage)
	if err != nil {
		return
	}
	appleVMImage, err := osImageDefaultAppleVMImage(cfg.OSImage)
	if err != nil {
		return
	}
	appleVMSHA256, err := osImageDefaultAppleVMSHA256(cfg.OSImage)
	if err != nil {
		return
	}
	base := baseConfig()
	wasOSDefault := cfg.osImageProviderDefaults != ""
	if force || cfg.Image == "" || (!cfg.imageExplicit && (cfg.Image == base.Image || wasOSDefault)) {
		cfg.Image = hetznerImage
	}
	if force || cfg.AzureImage == "" || (!cfg.azureImageExplicit && (cfg.AzureImage == base.AzureImage || wasOSDefault)) {
		cfg.AzureImage = azureImage
	}
	if force || cfg.GCPImage == "" || (!cfg.gcpImageExplicit && (cfg.GCPImage == base.GCPImage || wasOSDefault)) {
		cfg.GCPImage = gcpImage
	}
	if force || cfg.Linode.Image == "" || (!cfg.linodeImageExplicit && (cfg.Linode.Image == base.Linode.Image || wasOSDefault)) {
		cfg.Linode.Image = linodeImage
	}
	if force || cfg.Islo.Image == "" || (!cfg.isloImageExplicit && (cfg.Islo.Image == base.Islo.Image || wasOSDefault)) {
		cfg.Islo.Image = isloImage
	}
	if force || cfg.LocalContainer.Image == "" || (!cfg.localContainerImageExplicit && (cfg.LocalContainer.Image == base.LocalContainer.Image || wasOSDefault)) {
		cfg.LocalContainer.Image = containerImage
	}
	if force || cfg.AppleContainer.Image == "" || (!cfg.appleContainerImageExplicit && (cfg.AppleContainer.Image == base.AppleContainer.Image || wasOSDefault)) {
		cfg.AppleContainer.Image = containerImage
	}
	if force || cfg.AppleVM.Image == "" || (!cfg.appleVMImageExplicit && (cfg.AppleVM.Image == base.AppleVM.Image || wasOSDefault)) {
		cfg.AppleVM.Image = appleVMImage
	}
	if !cfg.appleVMImageSHA256Explicit && (force || (cfg.AppleVM.ImageSHA256 == "" && cfg.AppleVM.Image == appleVMImage) || (!cfg.appleVMImageExplicit && (cfg.AppleVM.ImageSHA256 == "" || wasOSDefault))) {
		cfg.AppleVM.ImageSHA256 = appleVMSHA256
	}
	if force || cfg.Multipass.Image == "" || (!cfg.multipassImageExplicit && (cfg.Multipass.Image == base.Multipass.Image || wasOSDefault)) {
		cfg.Multipass.Image = multipassImage
	}
	cfg.osImageProviderDefaults = cfg.OSImage
}

func baseConfig() Config {
	home, _ := os.UserHomeDir()
	sshKey := ""
	if home != "" {
		sshKey = filepath.Join(home, ".ssh", "id_ed25519")
	}

	class := "beast"
	provider := "hetzner"
	osImage := defaultOSImage
	hetznerImage, azureImage, gcpImage, linodeImage, isloImage, containerImage, _ := osImageDefaultProviderImages(osImage)
	multipassImage, _ := osImageDefaultMultipassImage(osImage)
	return Config{
		Profile:                 "default",
		Provider:                provider,
		providerSelectionSource: providerSelectionCompiledDefault,
		TargetOS:                "linux",
		Architecture:            ArchitectureAMD64,
		OSImage:                 osImage,
		WindowsMode:             "normal",
		DesktopEnv:              desktopEnvXFCE,
		Network:                 NetworkAuto,
		Class:                   class,
		ServerType:              "",
		BrokerMode:              BrokerModeManaged,
		BrokerAutoWebVNC:        true,
		Location:                "fsn1",
		Image:                   hetznerImage,
		AWSRegion:               "eu-west-1",
		AWSRootGB:               400,
		AWSLambdaMicroVM: AWSLambdaMicroVMConfig{
			Workdir: "/workspace/crabbox",
		},
		AzureBackend:       "vm",
		AzureLocation:      "eastus",
		AzureResourceGroup: "crabbox-leases",
		AzureImage:         azureImage,
		AzureOSDisk:        AzureOSDiskManaged,
		AzureVNet:          "crabbox-vnet",
		AzureSubnet:        "crabbox-subnet",
		AzureNSG:           "crabbox-nsg",
		AzureDynamicSessions: AzureDynamicSessionsConfig{
			APIVersion:  "2025-02-02-preview",
			Workdir:     "/workspace/crabbox",
			TimeoutSecs: 1800,
		},
		GCPZone:    "europe-west2-a",
		GCPImage:   gcpImage,
		GCPNetwork: "default",
		GCPTags:    []string{"crabbox-ssh"},
		GCPRootGB:  400,
		Linode: LinodeConfig{
			Region: "us-ord",
			Image:  linodeImage,
			Type:   "g6-standard-1",
		},
		GitHubCodespaces: GitHubCodespacesConfig{
			APIURL:          "https://api.github.com",
			GHPath:          "gh",
			Machine:         "basicLinux32gb",
			IdleTimeout:     30 * time.Minute,
			RetentionPeriod: 7 * 24 * time.Hour,
			DeleteOnRelease: true,
			WorkRoot:        "/workspaces/crabbox",
		},
		Lambda: LambdaConfig{
			Region:      "us-west-1",
			Type:        "gpu_1x_a10",
			ImageFamily: "lambda-stack-24-04",
		},
		OVH: OVHConfig{
			Endpoint: "https://api.us.ovhcloud.com/1.0",
			Image:    "Ubuntu 24.04",
			Flavor:   "b3-8",
		},
		Scaleway: ScalewayConfig{
			Region: "fr-par",
			Zone:   "fr-par-1",
			Image:  "ubuntu_noble",
			Type:   "DEV1-S",
		},
		Incus: IncusConfig{
			Remote:          "local",
			Project:         "",
			InstanceType:    "container",
			Image:           "images:ubuntu/24.04/cloud",
			User:            "crabbox",
			WorkRoot:        defaultPOSIXWorkRoot,
			DeleteOnRelease: true,
			StartTimeout:    10 * time.Minute,
			LaunchPort:      "22",
			ProxyListenHost: "127.0.0.1",
			ProxyDevice:     "crabbox-ssh",
		},
		SSHUser:          "crabbox",
		SSHKey:           sshKey,
		SSHPort:          "2222",
		SSHFallbackPorts: []string{"22"},
		ProviderKey:      "crabbox-steipete",
		WorkRoot:         defaultPOSIXWorkRoot,
		TTL:              90 * time.Minute,
		IdleTimeout:      30 * time.Minute,
		Sync: SyncConfig{
			Delete:      true,
			Checksum:    false,
			GitSeed:     true,
			Fingerprint: true,
			Timeout:     15 * time.Minute,
			WarnFiles:   50_000,
			WarnBytes:   5 * 1024 * 1024 * 1024,
			FailFiles:   150_000,
			FailBytes:   20 * 1024 * 1024 * 1024,
		},
		EnvAllow: []string{"CI", "NODE_OPTIONS"},
		Capacity: CapacityConfig{
			Market:   "spot",
			Strategy: "most-available",
			Fallback: "on-demand-after-120s",
			Hints:    true,
		},
		Actions: ActionsConfig{
			RunnerVersion: "latest",
			Ephemeral:     true,
		},
		KubeVirt: KubeVirtConfig{
			Kubectl:         "kubectl",
			Virtctl:         "virtctl",
			Namespace:       "default",
			SSHUser:         "crabbox",
			SSHPort:         "22",
			WorkRoot:        "/home/crabbox/crabbox",
			DeleteOnRelease: true,
		},
		SealosDevbox: SealosDevboxConfig{
			Kubectl:        "kubectl",
			Namespace:      "default",
			CPU:            "2",
			Memory:         "4Gi",
			StorageLimit:   "20Gi",
			Network:        "SSHGate",
			SSHGatewayPort: "2233",
			SSHUser:        "devbox",
			WorkRoot:       "/home/devbox/project",
		},
		AgentSandbox: AgentSandboxConfig{
			Kubectl:             "kubectl",
			Namespace:           "default",
			Workdir:             "/workspace/crabbox",
			SandboxReadyTimeout: 180 * time.Second,
			PodReadyTimeout:     180 * time.Second,
			ExecTimeoutSecs:     600,
			DeleteOnRelease:     true,
		},
		External: ExternalConfig{
			WorkRoot: defaultPOSIXWorkRoot,
		},
		Namespace: NamespaceConfig{
			Image:               "builtin:base",
			WorkRoot:            "/workspaces/crabbox",
			AutoStopIdleTimeout: 30 * time.Minute,
		},
		NamespaceInstance: NamespaceInstanceConfig{
			CLIPath:  "nsc",
			WorkRoot: "/work/crabbox",
			Bare:     true,
		},
		Phala: PhalaConfig{
			CLIPath:      "phala",
			InstanceType: "tdx.small",
			// The dstack --dev-os guest roots on a read-only squashfs; /work is not
			// writable. /var/volatile is a writable tmpfs on every dstack guest.
			WorkRoot: "/var/volatile/crabbox",
		},
		Boxd: BoxdConfig{
			APIURL:          "https://app.boxd.sh",
			WorkRoot:        "/home/boxd/crabbox",
			DeleteOnRelease: true,
		},
		Coder: CoderConfig{
			CLIPath:         "coder",
			WorkspacePrefix: "crabbox-",
			WorkRoot:        "/home/coder/crabbox",
			Wait:            "yes",
		},
		Morph: MorphConfig{
			APIURL:         "https://cloud.morph.so",
			SSHGatewayHost: "ssh.cloud.morph.so",
			WorkRoot:       "/tmp/crabbox",
			WakeOnSSH:      true,
		},
		Orgo: OrgoConfig{
			APIBase:    "https://www.orgo.ai/api",
			RAMGB:      4,
			CPUs:       1,
			DiskGB:     8,
			Resolution: "1280x720x24",
		},
		Daytona: DaytonaConfig{
			APIURL:           "https://app.daytona.io/api",
			User:             "daytona",
			WorkRoot:         "/home/daytona/crabbox",
			SSHGatewayHost:   "ssh.app.daytona.io",
			SSHAccessMinutes: 30,
		},
		E2B: E2BConfig{
			APIURL:   "https://api.e2b.app",
			Domain:   "e2b.app",
			Template: "base",
			Workdir:  "crabbox",
		},
		CubeSandbox: CubeSandboxConfig{
			APIURL:        "http://127.0.0.1:3000",
			Domain:        "cube.app",
			Template:      "",
			Workdir:       "crabbox",
			ProxyPortHTTP: 80,
		},
		ExeDev: ExeDevConfig{
			ControlHost: "exe.dev",
			CPUs:        2,
			Memory:      "4GB",
			Disk:        "10GB",
			NoEmail:     true,
		},
		Railway: RailwayConfig{
			APIURL: "https://backboard.railway.com/graphql/v2",
		},
		FastAPICloud: FastAPICloudConfig{
			APIURL: "https://api.fastapicloud.com/api/v1",
		},
		UnikraftCloud: UnikraftCloudConfig{
			Metro: "fra",
		},
		Runpod: RunpodConfig{
			APIURL:     "https://rest.runpod.io/v1",
			CloudType:  "SECURE",
			InstanceID: "NVIDIA L4,NVIDIA RTX 4000 Ada Generation,NVIDIA RTX A4000,NVIDIA GeForce RTX 3090,NVIDIA GeForce RTX 4090,NVIDIA RTX A5000,NVIDIA RTX A4500",
			Image:      "runpod/pytorch:2.8.0-py3.11-cuda12.8.1-cudnn-devel-ubuntu22.04",
			DiskGB:     20,
		},
		Vast: VastConfig{
			APIURL:        "https://console.vast.ai/api/v0",
			InstanceType:  "ondemand",
			Image:         "nvidia/cuda:12.8.1-cudnn-devel-ubuntu22.04",
			Runtype:       "ssh_direct",
			DiskGB:        20,
			Order:         "dlperf_per_dphtotal desc",
			User:          "root",
			WorkRoot:      defaultPOSIXWorkRoot,
			ReleaseAction: "destroy",
		},
		NvidiaBrev: NvidiaBrevConfig{
			CLI:           "brev",
			GPUName:       "A100",
			Mode:          "vm",
			ReleaseAction: "delete",
			Target:        "container",
			WorkRoot:      "/tmp/crabbox",
		},
		Nebius: NebiusConfig{
			CLI:            "nebius",
			Platform:       "cpu-d3",
			Preset:         "4vcpu-16gb",
			ImageFamily:    "ubuntu24.04-driverless",
			DiskType:       "network_ssd",
			DiskSizeGiB:    50,
			User:           "crabbox",
			PublicIP:       "dynamic",
			RecoveryPolicy: "fail",
		},
		Hostinger: HostingerConfig{
			APIURL:         "https://developers.hostinger.com",
			HostnamePrefix: "crabbox",
			User:           "root",
			ReleaseAction:  "stop",
		},
		Islo: IsloConfig{
			BaseURL:  "https://api.islo.dev",
			Image:    isloImage,
			Workdir:  "crabbox",
			VCPUs:    2,
			MemoryMB: 4096,
			DiskGB:   20,
		},
		Freestyle: FreestyleConfig{
			APIURL:  "https://api.freestyle.sh",
			Workdir: "crabbox",
		},
		Tenki: TenkiConfig{
			CLIPath:  "tenki",
			WorkRoot: "/home/tenki/crabbox",
		},
		Tensorlake: TensorlakeConfig{
			APIURL:   "https://api.tensorlake.ai",
			CLIPath:  "tensorlake",
			Workdir:  "/workspace/crabbox",
			CPUs:     1.0,
			MemoryMB: 1024,
			DiskMB:   10240,
		},
		Cua: CuaConfig{
			Image:             "ubuntu:24.04",
			Kind:              "container",
			Workdir:           "/workspace/crabbox",
			ExecTimeoutSecs:   600,
			BridgeCommand:     "python3",
			SDKPackage:        "cua",
			SDKImport:         "cua",
			SDKFallbackImport: "cua_sandbox",
		},
		OpenComputer: OpenComputerConfig{
			// APIURL is intentionally unset here so the `oc` config file's
			// api_url is honored before the built-in default; the provider
			// applies the default (https://app.opencomputer.dev) as the final
			// fallback in newOCAPIClient.
			Workdir:         "/workspace/crabbox",
			ExecTimeoutSecs: 3600,
		},
		CodeSandbox: CodeSandboxConfig{
			Workdir:                  "/project/workspace",
			Privacy:                  "private",
			AutomaticWakeupHTTP:      true,
			AutomaticWakeupWebSocket: false,
			BridgeCommand:            "node",
			SDKPackage:               "@codesandbox/sdk@2.4.2",
			DoctorListLimit:          1,
			OperationTimeoutSecs:     30,
		},
		OpenSandbox: OpenSandboxConfig{
			// APIURL is intentionally unset here so repository YAML cannot
			// redirect a shell-provided API key. The provider requires an
			// explicit trusted endpoint from flags or environment.
			Image:           "ubuntu:24.04",
			Workdir:         "/workspace/crabbox",
			CPU:             "1",
			Memory:          "2Gi",
			ExecTimeoutSecs: 600,
			PlatformOS:      "linux",
			PlatformArch:    "amd64",
		},
		Nomad: NomadConfig{
			TokenEnv:          "NOMAD_TOKEN",
			Task:              "crabbox",
			Driver:            "docker",
			Image:             "ubuntu:24.04",
			Workdir:           "/workspace/crabbox",
			Datacenters:       []string{"dc1"},
			CPU:               1000,
			MemoryMB:          2048,
			DiskMB:            1024,
			AllocReadyTimeout: 5 * time.Minute,
			EvalTimeout:       5 * time.Minute,
			ExecTimeoutSecs:   600,
		},
		Blaxel: BlaxelConfig{
			APIURL:          "https://api.blaxel.ai",
			Image:           "ubuntu:24.04",
			Workdir:         "/workspace/crabbox",
			ExecTimeoutSecs: 600,
		},
		VercelSandbox: defaultVercelSandboxConfig(),
		CloudflareSandbox: CloudflareSandboxConfig{
			Workdir:         "/workspace/crabbox",
			ExecTimeoutSecs: 600,
		},
		Superserve: SuperserveConfig{
			BaseURL:         "https://api.superserve.ai",
			Template:        "superserve/base",
			Workdir:         "/workspace/crabbox",
			ExecTimeoutSecs: 600,
		},
		Crownest: CrownestConfig{
			APIURL:      "https://api.crownest.dev",
			Template:    "python-node",
			TimeoutSecs: 600,
		},
		DockerSandbox: DockerSandboxConfig{
			CLIPath: "sbx",
			Agent:   "shell",
		},
		AnthropicSRT: AnthropicSRTConfig{
			CLIPath: "srt",
		},
		CloudRunSandbox: CloudRunSandboxConfig{
			CLIPath: "/usr/local/gcp/bin/sandbox",
			Workdir: "/tmp/crabbox",
			Write:   true,
			Rootfs:  "/",
		},
		Modal: ModalConfig{
			App:     "crabbox",
			Image:   "python:3.13-slim",
			Workdir: "/workspace/crabbox",
			Python:  "python3",
		},
		UpstashBox: UpstashBoxConfig{
			BaseURL: "https://us-east-1.box.upstash.com",
			Runtime: "node",
			Size:    "small",
			Workdir: "/workspace/home/crabbox",
		},
		Smolvm: SmolvmConfig{
			BaseURL:  "https://api.smolmachines.com",
			Image:    "alpine",
			Workdir:  "/workspace",
			CPUs:     2,
			MemoryMB: 2048,
			Network:  "open",
		},
		AsciiBox: AsciiBoxConfig{
			BaseURL: "https://ascii.dev",
			CLIPath: "box",
			Workdir: "/home/user/crabbox",
		},
		Cloudflare: CloudflareConfig{
			Workdir: "/workspace/crabbox",
		},
		CloudflareDynamicWorkers: CloudflareDynamicWorkersConfig{
			CompatibilityDate: DefaultCloudflareDynamicWorkersCompatibilityDate,
			CacheMode:         "stable",
			Egress:            "blocked",
			TimeoutSecs:       60,
			Metadata:          map[string]string{},
		},
		Proxmox: ProxmoxConfig{
			User:      "crabbox",
			WorkRoot:  defaultPOSIXWorkRoot,
			FullClone: true,
		},
		Firecracker: FirecrackerConfig{
			Binary:          "firecracker",
			Kernel:          "/var/lib/crabbox/firecracker/vmlinux",
			RootFS:          "/var/lib/crabbox/firecracker/rootfs.ext4",
			User:            "crabbox",
			WorkRoot:        defaultPOSIXWorkRoot,
			CPUs:            4,
			MemoryMiB:       4096,
			DiskMiB:         16384,
			Network:         "cni",
			CNINetwork:      "crabbox-firecracker",
			CNIConfDir:      "/etc/cni/conf.d",
			CNIBinDir:       "/opt/cni/bin",
			LaunchTimeout:   2 * time.Minute,
			DeleteOnRelease: true,
		},
		XCPNg: XCPNgConfig{
			User:     "crabbox",
			WorkRoot: defaultPOSIXWorkRoot,
		},
		Parallels: ParallelsConfig{
			CloneMode:      "linked",
			User:           "crabbox",
			StartupTimeout: 15 * time.Minute,
		},
		Sprites: SpritesConfig{
			APIURL:   "https://api.sprites.dev",
			WorkRoot: "/home/sprite/crabbox",
		},
		LocalContainer: LocalContainerConfig{
			Runtime: "docker",
			Image:   containerImage,
			User:    "crabbox",
			Network: "bridge",
		},
		AppleContainer: AppleContainerConfig{
			CLIPath:  "container",
			Image:    containerImage,
			User:     "crabbox",
			WorkRoot: "/work/crabbox",
		},
		AppleVM: AppleVMConfig{
			Image:       osImageSpecs[osImage].AppleVMImage,
			ImageSHA256: osImageSpecs[osImage].AppleVMSHA256,
			User:        "crabbox",
			WorkRoot:    "/work/crabbox",
			CPUs:        4,
			MemoryMiB:   8192,
			DiskGiB:     30,
		},
		MXC: MXCConfig{
			CLIPath:     "wxc-exec.exe",
			Version:     "0.6.0-alpha",
			Containment: "processcontainer",
			Network:     "block",
		},
		Multipass: MultipassConfig{
			CLIPath:       "multipass",
			Image:         multipassImage,
			User:          "crabbox",
			WorkRoot:      defaultPOSIXWorkRoot,
			CPUs:          4,
			Memory:        "8G",
			Disk:          "30G",
			LaunchTimeout: 20 * time.Minute,
		},
		Machine0: Machine0Config{
			CLIPath:       "machine0",
			Image:         "ubuntu-24-04-loaded",
			Size:          "large",
			Region:        "eu",
			ReleasePolicy: "destroy",
			CreateTimeout: 15 * time.Minute,
			PollInterval:  60 * time.Second,
		},
		Tart: TartConfig{
			Image:    DefaultTartImage,
			User:     "admin",
			WorkRoot: "/Users/admin/crabbox",
			CPUs:     4,
			Memory:   8192,
		},
		Lume: LumeConfig{
			CLIPath:  "lume",
			Base:     "crabbox-macos-golden",
			User:     "lume",
			WorkRoot: "/Users/lume/crabbox",
		},
		HyperV: HyperVConfig{
			User:     "crabbox",
			WorkRoot: defaultWindowsWorkRoot,
			CPUs:     4,
			Memory:   8192,
			Switch:   "Default Switch",
		},
		WindowsSandbox: WindowsSandboxConfig{
			Workdir:            `C:\crabbox-work`,
			Networking:         "Enable",
			VGPU:               "Disable",
			Clipboard:          "Disable",
			ProtectedClient:    "Default",
			AudioInput:         "Disable",
			VideoInput:         "Disable",
			PrinterRedirection: "Disable",
		},
		Tailscale: TailscaleConfig{
			Tags:             []string{"tag:crabbox"},
			HostnameTemplate: "crabbox-{slug}",
			AuthKeyEnv:       "CRABBOX_TAILSCALE_AUTH_KEY",
		},
		Cache: CacheConfig{
			Pnpm:   true,
			Npm:    true,
			Docker: true,
			Git:    true,
			MaxGB:  80,
		},
	}
}
