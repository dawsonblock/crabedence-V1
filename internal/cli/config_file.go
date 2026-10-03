package cli

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"gopkg.in/yaml.v3"
)

func applyCloudflareFileConfig(cfg *Config, file *fileCloudflareConfig, source credentialValueSource) {
	if file == nil {
		return
	}
	if file.APIURL != "" {
		cfg.Cloudflare.APIURL = file.APIURL
		cfg.credentialProvenance.cloudflareAPIURL = source
	}
	if file.Token != "" {
		cfg.Cloudflare.Token = file.Token
		cfg.credentialProvenance.cloudflareToken = source
	}
	if file.Workdir != "" {
		cfg.Cloudflare.Workdir = file.Workdir
	}
}

func applyOptional[T any](target, value *T) {
	if value != nil {
		*target = *value
	}
}

func applyCloudflareSandboxFileConfig(cfg *Config, file *fileCloudflareSandboxConfig, trusted bool) error {
	if file == nil {
		return nil
	}
	if trusted {
		applyOptional(&cfg.CloudflareSandbox.BridgeURL, file.BridgeURL)
		applyOptional(&cfg.CloudflareSandbox.BridgeURL, file.URL)
		applyOptional(&cfg.CloudflareSandbox.Token, file.Token)
	}
	applyOptional(&cfg.CloudflareSandbox.Workdir, file.Workdir)
	if file.ExecTimeoutSecs != nil {
		if *file.ExecTimeoutSecs < 0 {
			return exit(2, "cloudflare-sandbox execTimeoutSecs must be non-negative")
		}
		cfg.CloudflareSandbox.ExecTimeoutSecs = *file.ExecTimeoutSecs
	}
	applyOptional(&cfg.CloudflareSandbox.ForgetMissing, file.ForgetMissing)
	return nil
}

func applyCloudflareDynamicWorkersFileConfig(cfg *Config, file *fileCloudflareDynamicWorkersConfig, trusted bool) {
	if file == nil {
		return
	}
	if trusted {
		if file.LoaderURL != "" {
			cfg.CloudflareDynamicWorkers.LoaderURL = file.LoaderURL
		}
		if file.URL != "" {
			cfg.CloudflareDynamicWorkers.LoaderURL = file.URL
		}
		if file.Token != "" {
			cfg.CloudflareDynamicWorkers.Token = file.Token
		}
	}
	if file.CompatibilityDate != "" {
		cfg.CloudflareDynamicWorkers.CompatibilityDate = file.CompatibilityDate
	}
	if len(file.CompatibilityFlags) > 0 {
		cfg.CloudflareDynamicWorkers.CompatibilityFlags = append([]string(nil), file.CompatibilityFlags...)
	}
	if file.CacheMode != "" {
		cfg.CloudflareDynamicWorkers.CacheMode = file.CacheMode
	}
	if file.Egress != "" && (trusted || strings.EqualFold(strings.TrimSpace(file.Egress), "blocked")) {
		cfg.CloudflareDynamicWorkers.Egress = file.Egress
	}
	if trusted {
		if file.CPUMs > 0 {
			cfg.CloudflareDynamicWorkers.CPUMs = file.CPUMs
		}
		if file.Subrequests > 0 {
			cfg.CloudflareDynamicWorkers.Subrequests = file.Subrequests
		}
		if file.TimeoutSecs > 0 {
			cfg.CloudflareDynamicWorkers.TimeoutSecs = file.TimeoutSecs
		}
	} else {
		cfg.CloudflareDynamicWorkers.repositoryCPUMsCap = positiveMinimum(
			cfg.CloudflareDynamicWorkers.repositoryCPUMsCap,
			file.CPUMs,
		)
		cfg.CloudflareDynamicWorkers.repositorySubrequestsCap = positiveMinimum(
			cfg.CloudflareDynamicWorkers.repositorySubrequestsCap,
			file.Subrequests,
		)
		cfg.CloudflareDynamicWorkers.repositoryTimeoutSecsCap = positiveMinimum(
			cfg.CloudflareDynamicWorkers.repositoryTimeoutSecsCap,
			file.TimeoutSecs,
		)
		applyCloudflareDynamicWorkersRepositoryCaps(cfg)
	}
	if len(file.Metadata) > 0 {
		cfg.CloudflareDynamicWorkers.Metadata = map[string]string{}
		for key, value := range file.Metadata {
			key = strings.TrimSpace(key)
			if key != "" {
				cfg.CloudflareDynamicWorkers.Metadata[key] = value
			}
		}
	}
}

func applyCloudflareDynamicWorkersRepositoryCaps(cfg *Config) {
	dynamicWorkers := &cfg.CloudflareDynamicWorkers
	if dynamicWorkers.repositoryCPUMsCap > 0 &&
		(dynamicWorkers.CPUMs > 0 || dynamicWorkers.repositoryCPUMsCapActive) {
		if dynamicWorkers.CPUMs <= 0 {
			dynamicWorkers.CPUMs = dynamicWorkers.repositoryCPUMsCap
		} else {
			dynamicWorkers.CPUMs = min(dynamicWorkers.CPUMs, dynamicWorkers.repositoryCPUMsCap)
		}
		dynamicWorkers.repositoryCPUMsCapActive = true
	}
	if dynamicWorkers.repositorySubrequestsCap > 0 &&
		(dynamicWorkers.Subrequests > 0 || dynamicWorkers.repositorySubrequestsCapActive) {
		if dynamicWorkers.Subrequests <= 0 {
			dynamicWorkers.Subrequests = dynamicWorkers.repositorySubrequestsCap
		} else {
			dynamicWorkers.Subrequests = min(
				dynamicWorkers.Subrequests,
				dynamicWorkers.repositorySubrequestsCap,
			)
		}
		dynamicWorkers.repositorySubrequestsCapActive = true
	}
	if dynamicWorkers.repositoryTimeoutSecsCap > 0 &&
		(dynamicWorkers.TimeoutSecs > 0 || dynamicWorkers.repositoryTimeoutSecsCapActive) {
		if dynamicWorkers.TimeoutSecs <= 0 {
			dynamicWorkers.TimeoutSecs = dynamicWorkers.repositoryTimeoutSecsCap
		} else {
			dynamicWorkers.TimeoutSecs = min(
				dynamicWorkers.TimeoutSecs,
				dynamicWorkers.repositoryTimeoutSecsCap,
			)
		}
		dynamicWorkers.repositoryTimeoutSecsCapActive = true
	}
}

func positiveMinimum(current, candidate int) int {
	if candidate <= 0 {
		return current
	}
	if current <= 0 {
		return candidate
	}
	return min(current, candidate)
}

func configPaths() []string {
	if explicit := os.Getenv("CRABBOX_CONFIG"); explicit != "" {
		return []string{explicit}
	}
	paths := make([]string, 0, 3)
	if userPath := userConfigPath(); userPath != "" {
		paths = append(paths, userPath)
	}
	for _, path := range []string{"crabbox.yaml", ".crabbox.yaml"} {
		if _, err := os.Stat(path); err == nil {
			paths = append(paths, path)
		}
	}
	return paths
}

func userConfigPath() string {
	dir, err := os.UserConfigDir()
	if err != nil {
		return ""
	}
	return filepath.Join(dir, "crabbox", "config.yaml")
}

func readFileConfig(path string) (fileConfig, error) {
	var cfg fileConfig
	data, err := os.ReadFile(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return cfg, nil
		}
		return cfg, exit(2, "read config %s: %v", path, err)
	}
	if len(data) == 0 {
		return cfg, nil
	}
	if err := yaml.Unmarshal(data, &cfg); err != nil {
		return cfg, exit(2, "parse config %s: %v", path, err)
	}
	return cfg, nil
}

func writeUserFileConfig(cfg fileConfig) (string, error) {
	path := writableConfigPath()
	if path == "" {
		return "", exit(2, "user config directory is unavailable")
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return "", exit(2, "create config directory: %v", err)
	}
	data, err := yaml.Marshal(cfg)
	if err != nil {
		return "", err
	}
	if err := writeUserFileConfigAtomic(path, data, replaceClaimFile, fsyncDir); err != nil {
		return "", exit(2, "write config %s: %v", path, err)
	}
	return path, nil
}

func writeUserFileConfigAtomic(path string, data []byte, replaceFile func(string, string) error, syncDirectory func(string)) error {
	writePath, err := resolveConfigWritePath(path)
	if err != nil {
		return err
	}
	dir := filepath.Dir(writePath)
	tmp, err := os.CreateTemp(dir, "."+filepath.Base(path)+".tmp-*")
	if err != nil {
		return err
	}
	tmpPath := tmp.Name()
	removeTemp := true
	defer func() {
		if removeTemp {
			_ = os.Remove(tmpPath)
		}
	}()
	if err := tmp.Chmod(0o600); err != nil {
		_ = tmp.Close()
		return err
	}
	if _, err := tmp.Write(data); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Sync(); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	if err := replaceFile(tmpPath, writePath); err != nil {
		return err
	}
	removeTemp = false
	syncDirectory(dir)
	return nil
}

func resolveConfigWritePath(path string) (string, error) {
	writePath := path
	for i := 0; i < 255; i++ {
		info, err := os.Lstat(writePath)
		if err != nil {
			if errors.Is(err, os.ErrNotExist) {
				return writePath, nil
			}
			return "", err
		}
		if info.Mode()&os.ModeSymlink == 0 {
			return writePath, nil
		}
		target, err := os.Readlink(writePath)
		if err != nil {
			return "", err
		}
		if !filepath.IsAbs(target) {
			target = filepath.Join(filepath.Dir(writePath), target)
		}
		writePath = target
	}
	return "", fmt.Errorf("resolve config path %s: too many symbolic links", path)
}

func configFilePermissionProblem(path string) string {
	if path == "" {
		return ""
	}
	info, err := os.Stat(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return ""
		}
		return err.Error()
	}
	if info.Mode().Perm()&0o077 != 0 {
		return fmt.Sprintf("permissions %04o want 0600", info.Mode().Perm())
	}
	return ""
}

func writableConfigPath() string {
	if explicit := os.Getenv("CRABBOX_CONFIG"); explicit != "" {
		return explicit
	}
	return userConfigPath()
}

type configPathTrust struct {
	trusted        bool
	repositoryRoot string
}

func applyConfigFile(cfg *Config, path string, trust configPathTrust) error {
	file, err := readFileConfig(path)
	if err != nil {
		return err
	}
	if !trust.trusted && trust.repositoryRoot != "" {
		cfg.credentialProvenance.repositoryRoot = trust.repositoryRoot
	}
	return applyFileConfigWithTrustAndProviderSource(cfg, file, trust.trusted, providerSelectionSourceForConfigPath(trust))
}

func applyFileConfig(cfg *Config, file fileConfig) error {
	return applyFileConfigWithTrustAndProviderSource(cfg, file, true, providerSelectionUserConfig)
}

func classifyConfigPath(path string) configPathTrust {
	if sameConfigPath(path, userConfigPath()) {
		return configPathTrust{trusted: true}
	}
	boundary, _ := findRepositoryBoundary()
	root, _ := filepath.Abs(boundary.root)
	if explicit := strings.TrimSpace(os.Getenv("CRABBOX_CONFIG")); explicit != "" &&
		sameConfigPath(path, explicit) && !configPathWithinRoot(path, root) {
		return configPathTrust{trusted: true}
	}
	return configPathTrust{repositoryRoot: root}
}

func sameConfigPath(left, right string) bool {
	return left != "" && right != "" && filepath.Clean(left) == filepath.Clean(right)
}

func configPathWithinRoot(path, root string) bool {
	if path == "" || root == "" {
		return false
	}
	pathAbs, err := filepath.Abs(path)
	if err != nil {
		return false
	}
	rootAbs, err := filepath.Abs(root)
	if err != nil {
		return false
	}
	if pathWithinRoot(pathAbs, rootAbs) {
		return true
	}
	resolvedPath, pathErr := filepath.EvalSymlinks(pathAbs)
	resolvedRoot, rootErr := filepath.EvalSymlinks(rootAbs)
	return pathErr == nil && rootErr == nil && pathWithinRoot(resolvedPath, resolvedRoot)
}

func pathWithinRoot(path, root string) bool {
	rel, err := filepath.Rel(root, path)
	return err == nil && rel != ".." && !strings.HasPrefix(rel, ".."+string(filepath.Separator)) && !filepath.IsAbs(rel)
}

func inlineSSHPublicKey(value string) bool {
	fields := strings.Fields(value)
	if len(fields) < 2 {
		return false
	}
	switch fields[0] {
	case "ssh-ed25519", "ssh-rsa", "ecdsa-sha2-nistp256", "ecdsa-sha2-nistp384", "ecdsa-sha2-nistp521", "sk-ssh-ed25519@openssh.com", "sk-ecdsa-sha2-nistp256@openssh.com":
		return true
	default:
		return false
	}
}

func applyFileConfigWithTrust(cfg *Config, file fileConfig, trusted bool) error {
	source := providerSelectionRepoConfig
	if trusted {
		source = providerSelectionUserConfig
	}
	return applyFileConfigWithTrustAndProviderSource(cfg, file, trusted, source)
}

func applyFileConfigWithTrustAndProviderSource(cfg *Config, file fileConfig, trusted bool, providerSource providerSelectionSource) error {
	credentialSource := credentialSourceForFile(trusted)
	if !trusted && cfg.credentialProvenance.repositoryRoot == "" {
		if root, err := os.Getwd(); err == nil {
			cfg.credentialProvenance.repositoryRoot = root
		}
	}
	if file.Profile != "" {
		cfg.Profile = file.Profile
	}
	if file.Provider != "" {
		setProviderSelection(cfg, file.Provider, providerSource)
		cfg.brokerProvider = ""
	}
	if file.Target != "" {
		cfg.TargetOS = file.Target
		cfg.targetExplicit = true
	}
	if file.TargetOS != "" {
		cfg.TargetOS = file.TargetOS
		cfg.targetExplicit = true
	}
	if file.Architecture != "" {
		cfg.Architecture = file.Architecture
		cfg.architectureExplicit = true
	}
	if file.OSImage != "" {
		cfg.OSImage = file.OSImage
		cfg.osImageExplicit = true
		if normalized, err := normalizeOSImage(file.OSImage); err == nil {
			cfg.OSImage = normalized
			applyOSImageProviderDefaults(cfg, false)
		}
	}
	if file.Windows != nil && file.Windows.Mode != "" {
		cfg.WindowsMode = file.Windows.Mode
		cfg.explicitWindowsMode = file.Windows.Mode
	}
	applyOptional(&cfg.Desktop, file.Desktop)
	if file.DesktopEnv != "" {
		cfg.DesktopEnv = file.DesktopEnv
	}
	applyOptional(&cfg.Browser, file.Browser)
	applyOptional(&cfg.Code, file.Code)
	if file.Network != "" {
		cfg.Network = NetworkMode(strings.ToLower(strings.TrimSpace(file.Network)))
	}
	if file.Class != "" {
		cfg.Class = file.Class
		MarkClassExplicit(cfg)
	}
	if file.ServerType != "" {
		cfg.ServerType = file.ServerType
		cfg.ServerTypeExplicit = true
	}
	if file.Coordinator != "" {
		cfg.Coordinator = file.Coordinator
		cfg.credentialProvenance.coordinator = credentialSource
	}
	if file.CoordinatorToken != "" {
		cfg.CoordToken = file.CoordinatorToken
		cfg.credentialProvenance.coordToken = credentialSource
	}
	if file.HostID != "" {
		cfg.HostID = file.HostID
	}
	if file.Broker != nil {
		if file.Broker.URL != "" {
			cfg.Coordinator = file.Broker.URL
			cfg.credentialProvenance.coordinator = credentialSource
		}
		if file.Broker.Token != "" {
			cfg.CoordToken = file.Broker.Token
			cfg.credentialProvenance.coordToken = credentialSource
		}
		if file.Broker.Mode != "" {
			cfg.BrokerMode = BrokerMode(file.Broker.Mode)
		}
		applyOptional(&cfg.BrokerAutoWebVNC, file.Broker.AutoWebVNC)
		if trusted && len(file.Broker.LoginRedirectOrigins) > 0 {
			cfg.BrokerLoginRedirectOrigins = normalizeList(file.Broker.LoginRedirectOrigins)
		}
		if file.Broker.AdminToken != "" {
			cfg.CoordAdminToken = file.Broker.AdminToken
			cfg.credentialProvenance.coordAdminToken = credentialSource
		}
		if file.Broker.Provider != "" {
			setProviderSelection(cfg, file.Broker.Provider, providerSource)
			cfg.brokerProvider = file.Broker.Provider
		}
		if file.Broker.Access != nil {
			if file.Broker.Access.ClientID != "" {
				cfg.Access.ClientID = file.Broker.Access.ClientID
				cfg.credentialProvenance.accessClientID = credentialSource
			}
			if file.Broker.Access.ClientSecret != "" {
				cfg.Access.ClientSecret = file.Broker.Access.ClientSecret
				cfg.credentialProvenance.accessClientSecret = credentialSource
			}
			if file.Broker.Access.Token != "" {
				cfg.Access.Token = file.Broker.Access.Token
				cfg.credentialProvenance.accessToken = credentialSource
			}
		}
	}
	if file.Hetzner != nil {
		if file.Hetzner.Location != "" {
			cfg.Location = file.Hetzner.Location
			cfg.locationExplicit = true
		}
		if file.Hetzner.Image != "" {
			cfg.Image = file.Hetzner.Image
			cfg.imageExplicit = true
		}
		if file.Hetzner.SSHKey != "" {
			cfg.ProviderKey = file.Hetzner.SSHKey
		}
	}
	if file.DigitalOcean != nil {
		if file.DigitalOcean.Region != "" {
			cfg.DigitalOcean.Region = file.DigitalOcean.Region
		}
		if file.DigitalOcean.Image != "" {
			cfg.DigitalOcean.Image = file.DigitalOcean.Image
			cfg.digitalOceanImageExplicit = true
		}
		if file.DigitalOcean.VPCUUID != "" {
			cfg.DigitalOcean.VPCUUID = file.DigitalOcean.VPCUUID
		}
		if len(file.DigitalOcean.SSHCIDRs) > 0 {
			cfg.DigitalOcean.SSHCIDRs = file.DigitalOcean.SSHCIDRs
		}
	}
	if file.Vultr != nil {
		if file.Vultr.Region != "" {
			cfg.Vultr.Region = file.Vultr.Region
		}
		if file.Vultr.OS != "" {
			cfg.Vultr.OS = file.Vultr.OS
		}
		if file.Vultr.Image != "" {
			cfg.Vultr.Image = file.Vultr.Image
		}
		if file.Vultr.Snapshot != "" {
			cfg.Vultr.Snapshot = file.Vultr.Snapshot
		}
		if file.Vultr.FirewallGroup != "" {
			cfg.Vultr.FirewallGroup = file.Vultr.FirewallGroup
		}
		if len(file.Vultr.VPCIDs) > 0 {
			cfg.Vultr.VPCIDs = file.Vultr.VPCIDs
		}
		if len(file.Vultr.SSHCIDRs) > 0 {
			cfg.Vultr.SSHCIDRs = file.Vultr.SSHCIDRs
		}
		if file.Vultr.UserScheme != "" {
			cfg.Vultr.UserScheme = file.Vultr.UserScheme
		}
	}
	if file.Linode != nil {
		if file.Linode.Region != "" {
			cfg.Linode.Region = file.Linode.Region
		}
		if file.Linode.Image != "" {
			cfg.Linode.Image = file.Linode.Image
			cfg.linodeImageExplicit = true
		}
		if file.Linode.Type != "" {
			cfg.Linode.Type = file.Linode.Type
			cfg.linodeTypeExplicit = true
		}
		if file.Linode.FirewallID != "" {
			cfg.Linode.FirewallID = file.Linode.FirewallID
		}
		if len(file.Linode.SSHCIDRs) > 0 {
			cfg.Linode.SSHCIDRs = file.Linode.SSHCIDRs
		}
	}
	if file.GitHubCodespaces != nil {
		if trusted && file.GitHubCodespaces.APIURL != "" {
			cfg.GitHubCodespaces.APIURL = file.GitHubCodespaces.APIURL
		}
		if trusted && file.GitHubCodespaces.GHPath != "" {
			cfg.GitHubCodespaces.GHPath = expandUserPath(file.GitHubCodespaces.GHPath)
		}
		if trusted && file.GitHubCodespaces.Repo != "" {
			cfg.GitHubCodespaces.Repo = file.GitHubCodespaces.Repo
		}
		if file.GitHubCodespaces.Ref != "" {
			cfg.GitHubCodespaces.Ref = file.GitHubCodespaces.Ref
		}
		if file.GitHubCodespaces.Machine != "" {
			cfg.GitHubCodespaces.Machine = file.GitHubCodespaces.Machine
		}
		if file.GitHubCodespaces.DevcontainerPath != "" {
			cfg.GitHubCodespaces.DevcontainerPath = file.GitHubCodespaces.DevcontainerPath
		}
		if file.GitHubCodespaces.WorkingDirectory != "" {
			cfg.GitHubCodespaces.WorkingDirectory = file.GitHubCodespaces.WorkingDirectory
		}
		if file.GitHubCodespaces.Geo != "" {
			cfg.GitHubCodespaces.Geo = file.GitHubCodespaces.Geo
		}
		if trusted {
			applyLeaseDuration(&cfg.GitHubCodespaces.IdleTimeout, file.GitHubCodespaces.IdleTimeout)
			if applyNonNegativeLeaseDuration(&cfg.GitHubCodespaces.RetentionPeriod, file.GitHubCodespaces.RetentionPeriod) {
				MarkGitHubCodespacesRetentionExplicit(cfg)
			}
		}
		if trusted && file.GitHubCodespaces.DeleteOnRelease != nil {
			cfg.GitHubCodespaces.DeleteOnRelease = *file.GitHubCodespaces.DeleteOnRelease
			MarkDeleteOnReleaseExplicit(cfg, "github-codespaces")
		}
		if file.GitHubCodespaces.WorkRoot != "" {
			cfg.GitHubCodespaces.WorkRoot = file.GitHubCodespaces.WorkRoot
		}
	}
	if file.Lambda != nil {
		lambdaImageSet := false
		lambdaImageFamilySet := false
		if file.Lambda.Region != "" {
			cfg.Lambda.Region = file.Lambda.Region
		}
		if file.Lambda.Type != "" {
			cfg.Lambda.Type = file.Lambda.Type
			cfg.lambdaTypeExplicit = true
		}
		if file.Lambda.Image != "" {
			cfg.Lambda.Image = file.Lambda.Image
			cfg.lambdaImageExplicit = true
			lambdaImageSet = true
		}
		if file.Lambda.ImageFamily != "" {
			cfg.Lambda.ImageFamily = file.Lambda.ImageFamily
			cfg.lambdaImageFamilyExplicit = true
			lambdaImageFamilySet = true
		}
		if lambdaImageSet && !lambdaImageFamilySet {
			cfg.Lambda.ImageFamily = ""
		}
		if file.Lambda.FirewallRuleset != "" {
			cfg.Lambda.FirewallRuleset = file.Lambda.FirewallRuleset
		}
		if len(file.Lambda.SSHCIDRs) > 0 {
			cfg.Lambda.SSHCIDRs = file.Lambda.SSHCIDRs
		}
		if len(file.Lambda.FilesystemNames) > 0 {
			cfg.Lambda.FilesystemNames = file.Lambda.FilesystemNames
		}
		if len(file.Lambda.FilesystemMounts) > 0 {
			cfg.Lambda.FilesystemMounts = file.Lambda.FilesystemMounts
		}
	}
	if file.Nebius != nil {
		if trusted && file.Nebius.CLI != "" {
			cfg.Nebius.CLI = file.Nebius.CLI
		}
		if trusted && file.Nebius.Profile != "" {
			cfg.Nebius.Profile = file.Nebius.Profile
		}
		if file.Nebius.ParentID != "" {
			cfg.Nebius.ParentID = file.Nebius.ParentID
		}
		if file.Nebius.SubnetID != "" {
			cfg.Nebius.SubnetID = file.Nebius.SubnetID
		}
		if file.Nebius.Platform != "" {
			cfg.Nebius.Platform = file.Nebius.Platform
		}
		if file.Nebius.Preset != "" {
			cfg.Nebius.Preset = file.Nebius.Preset
		}
		if file.Nebius.ImageFamily != "" {
			cfg.Nebius.ImageFamily = file.Nebius.ImageFamily
		}
		if file.Nebius.DiskType != "" {
			cfg.Nebius.DiskType = file.Nebius.DiskType
		}
		if file.Nebius.DiskSizeGiB > 0 {
			cfg.Nebius.DiskSizeGiB = file.Nebius.DiskSizeGiB
		}
		if file.Nebius.User != "" {
			cfg.Nebius.User = file.Nebius.User
		}
		if file.Nebius.PublicIP != "" {
			cfg.Nebius.PublicIP = file.Nebius.PublicIP
		}
		if len(file.Nebius.SecurityGroupIDs) > 0 {
			cfg.Nebius.SecurityGroupIDs = file.Nebius.SecurityGroupIDs
		}
		if trusted && file.Nebius.ServiceAccountID != "" {
			cfg.Nebius.ServiceAccountID = file.Nebius.ServiceAccountID
		}
		if file.Nebius.RecoveryPolicy != "" {
			cfg.Nebius.RecoveryPolicy = file.Nebius.RecoveryPolicy
		}
	}
	if file.OVH != nil {
		if trusted && file.OVH.Endpoint != "" {
			cfg.OVH.Endpoint = file.OVH.Endpoint
		}
		if file.OVH.ProjectID != "" {
			cfg.OVH.ProjectID = file.OVH.ProjectID
		}
		if file.OVH.Region != "" {
			cfg.OVH.Region = file.OVH.Region
		}
		if file.OVH.Image != "" {
			cfg.OVH.Image = file.OVH.Image
			cfg.ovhImageExplicit = true
		}
		if file.OVH.Flavor != "" {
			cfg.OVH.Flavor = file.OVH.Flavor
		}
	}
	if file.Scaleway != nil {
		if file.Scaleway.Region != "" {
			cfg.Scaleway.Region = file.Scaleway.Region
			cfg.scalewayRegionExplicit = true
		}
		if file.Scaleway.Zone != "" {
			cfg.Scaleway.Zone = file.Scaleway.Zone
			cfg.scalewayZoneExplicit = true
		}
		if file.Scaleway.Image != "" {
			cfg.Scaleway.Image = file.Scaleway.Image
			cfg.scalewayImageExplicit = true
		}
		if file.Scaleway.Type != "" {
			cfg.Scaleway.Type = file.Scaleway.Type
			cfg.scalewayTypeExplicit = true
		}
		if file.Scaleway.ProjectID != "" {
			cfg.Scaleway.ProjectID = file.Scaleway.ProjectID
		}
		if file.Scaleway.OrganizationID != "" {
			cfg.Scaleway.OrganizationID = file.Scaleway.OrganizationID
		}
		if file.Scaleway.SecurityGroup != "" {
			cfg.Scaleway.SecurityGroup = file.Scaleway.SecurityGroup
		}
		if len(file.Scaleway.SSHCIDRs) > 0 {
			cfg.Scaleway.SSHCIDRs = file.Scaleway.SSHCIDRs
		}
	}
	if file.TencentCloud != nil {
		if file.TencentCloud.Region != "" {
			cfg.TencentCloud.Region = file.TencentCloud.Region
			cfg.tencentCloudRegionExplicit = true
		}
		if file.TencentCloud.Zone != "" {
			cfg.TencentCloud.Zone = file.TencentCloud.Zone
			cfg.tencentCloudZoneExplicit = true
		}
		if file.TencentCloud.Image != "" {
			cfg.TencentCloud.Image = file.TencentCloud.Image
			cfg.tencentCloudImageExplicit = true
		}
		if file.TencentCloud.Type != "" {
			cfg.TencentCloud.Type = file.TencentCloud.Type
			cfg.tencentCloudTypeExplicit = true
		}
		if file.TencentCloud.VPCID != "" {
			cfg.TencentCloud.VPCID = file.TencentCloud.VPCID
		}
		if file.TencentCloud.SubnetID != "" {
			cfg.TencentCloud.SubnetID = file.TencentCloud.SubnetID
		}
		if file.TencentCloud.SecurityGroupID != "" {
			cfg.TencentCloud.SecurityGroupID = file.TencentCloud.SecurityGroupID
		}
		if len(file.TencentCloud.SSHCIDRs) > 0 {
			cfg.TencentCloud.SSHCIDRs = file.TencentCloud.SSHCIDRs
		}
		if file.TencentCloud.RootGB > 0 {
			cfg.TencentCloud.RootGB = file.TencentCloud.RootGB
		}
		if file.TencentCloud.InternetChargeType != "" {
			cfg.TencentCloud.InternetChargeType = file.TencentCloud.InternetChargeType
		}
		if file.TencentCloud.InternetMaxBandwidthOut > 0 {
			cfg.TencentCloud.InternetMaxBandwidthOut = file.TencentCloud.InternetMaxBandwidthOut
		}
		if trusted && file.TencentCloud.APIEndpoint != "" {
			cfg.TencentCloud.APIEndpoint = file.TencentCloud.APIEndpoint
		}
	}
	if file.AWS != nil {
		if file.AWS.Region != "" {
			cfg.AWSRegion = file.AWS.Region
		}
		if file.AWS.AMI != "" {
			cfg.AWSAMI = file.AWS.AMI
		}
		if file.AWS.SecurityGroupID != "" {
			cfg.AWSSGID = file.AWS.SecurityGroupID
		}
		if file.AWS.SubnetID != "" {
			cfg.AWSSubnetID = file.AWS.SubnetID
		}
		if file.AWS.InstanceProfile != "" {
			cfg.AWSProfile = file.AWS.InstanceProfile
		}
		if file.AWS.RootGB > 0 {
			cfg.AWSRootGB = file.AWS.RootGB
		}
		if len(file.AWS.SSHCIDRs) > 0 {
			cfg.AWSSSHCIDRs = file.AWS.SSHCIDRs
		}
		if file.AWS.MacHostID != "" {
			cfg.AWSMacHostID = file.AWS.MacHostID
			if cfg.HostID == "" {
				cfg.HostID = file.AWS.MacHostID
			}
		}
	}
	if file.AWSLambdaMicroVM != nil {
		if file.AWSLambdaMicroVM.Image != "" {
			cfg.AWSLambdaMicroVM.Image = file.AWSLambdaMicroVM.Image
		}
		if file.AWSLambdaMicroVM.ImageVersion != "" {
			cfg.AWSLambdaMicroVM.ImageVersion = file.AWSLambdaMicroVM.ImageVersion
		}
		if file.AWSLambdaMicroVM.ExecutionRoleARN != "" {
			cfg.AWSLambdaMicroVM.ExecutionRoleARN = file.AWSLambdaMicroVM.ExecutionRoleARN
		}
		if file.AWSLambdaMicroVM.Workdir != "" {
			cfg.AWSLambdaMicroVM.Workdir = file.AWSLambdaMicroVM.Workdir
		}
		if file.AWSLambdaMicroVM.IngressConnectors != nil {
			cfg.AWSLambdaMicroVM.IngressConnectors = append([]string(nil), (*file.AWSLambdaMicroVM.IngressConnectors)...)
		}
		if file.AWSLambdaMicroVM.EgressConnectors != nil {
			cfg.AWSLambdaMicroVM.EgressConnectors = append([]string(nil), (*file.AWSLambdaMicroVM.EgressConnectors)...)
		}
		applyOptional(&cfg.AWSLambdaMicroVM.ForgetMissing, file.AWSLambdaMicroVM.ForgetMissing)
	}
	if file.Azure != nil {
		if file.Azure.Backend != "" {
			cfg.AzureBackend = file.Azure.Backend
		}
		if file.Azure.SubscriptionID != "" {
			cfg.AzureSubscription = file.Azure.SubscriptionID
		}
		if file.Azure.TenantID != "" {
			cfg.AzureTenant = file.Azure.TenantID
		}
		if file.Azure.ClientID != "" {
			cfg.AzureClientID = file.Azure.ClientID
		}
		if file.Azure.Location != "" {
			cfg.AzureLocation = file.Azure.Location
		}
		if file.Azure.ResourceGroup != "" {
			cfg.AzureResourceGroup = file.Azure.ResourceGroup
		}
		if file.Azure.Image != "" {
			cfg.AzureImage = file.Azure.Image
			cfg.azureImageExplicit = true
		}
		if file.Azure.OSDisk != "" {
			cfg.AzureOSDisk = file.Azure.OSDisk
			cfg.AzureOSDiskExplicit = true
		}
		if file.Azure.SnapshotSKU != "" {
			cfg.AzureSnapshotSKU = file.Azure.SnapshotSKU
		}
		if file.Azure.OSDiskSKU != "" {
			cfg.AzureOSDiskSKU = file.Azure.OSDiskSKU
		}
		if file.Azure.VNet != "" {
			cfg.AzureVNet = file.Azure.VNet
		}
		if file.Azure.Subnet != "" {
			cfg.AzureSubnet = file.Azure.Subnet
		}
		if file.Azure.NSG != "" {
			cfg.AzureNSG = file.Azure.NSG
		}
		if len(file.Azure.SSHCIDRs) > 0 {
			cfg.AzureSSHCIDRs = file.Azure.SSHCIDRs
		}
		if file.Azure.Network != "" {
			cfg.AzureNetwork = file.Azure.Network
		}
	}
	if file.AzureDynamicSessions != nil {
		if file.AzureDynamicSessions.Endpoint != "" {
			cfg.AzureDynamicSessions.Endpoint = file.AzureDynamicSessions.Endpoint
			cfg.credentialProvenance.azSessionsEndpoint = credentialSource
		}
		if file.AzureDynamicSessions.Pool != "" {
			cfg.AzureDynamicSessions.Pool = file.AzureDynamicSessions.Pool
		}
		if file.AzureDynamicSessions.APIVersion != "" {
			cfg.AzureDynamicSessions.APIVersion = file.AzureDynamicSessions.APIVersion
		}
		if file.AzureDynamicSessions.Workdir != "" {
			cfg.AzureDynamicSessions.Workdir = file.AzureDynamicSessions.Workdir
		}
		if file.AzureDynamicSessions.TimeoutSecs > 0 {
			cfg.AzureDynamicSessions.TimeoutSecs = file.AzureDynamicSessions.TimeoutSecs
		}
	}
	if file.GCP != nil {
		if file.GCP.Project != "" {
			cfg.GCPProject = file.GCP.Project
			cfg.gcpProjectExplicit = true
		}
		if file.GCP.Zone != "" {
			cfg.GCPZone = file.GCP.Zone
			cfg.gcpZoneExplicit = true
		}
		if file.GCP.Image != "" {
			cfg.GCPImage = file.GCP.Image
			cfg.gcpImageExplicit = true
		}
		if file.GCP.Network != "" {
			cfg.GCPNetwork = file.GCP.Network
			cfg.gcpNetworkExplicit = true
		}
		if file.GCP.Subnet != "" {
			cfg.GCPSubnet = file.GCP.Subnet
		}
		if len(file.GCP.Tags) > 0 {
			cfg.GCPTags = file.GCP.Tags
			cfg.gcpTagsExplicit = true
		}
		if len(file.GCP.SSHCIDRs) > 0 {
			cfg.GCPSSHCIDRs = file.GCP.SSHCIDRs
		}
		if file.GCP.RootGB > 0 {
			cfg.GCPRootGB = file.GCP.RootGB
			cfg.gcpRootGBExplicit = true
		}
		if file.GCP.ServiceAccount != "" {
			cfg.GCPServiceAccount = file.GCP.ServiceAccount
		}
	}
	if file.Incus != nil {
		if file.Incus.Remote != "" {
			cfg.Incus.Remote = file.Incus.Remote
		}
		if file.Incus.Project != "" {
			cfg.Incus.Project = file.Incus.Project
		}
		if file.Incus.Address != "" {
			cfg.Incus.Address = file.Incus.Address
		}
		if file.Incus.Socket != "" {
			cfg.Incus.Socket = expandUserPath(file.Incus.Socket)
		}
		if file.Incus.InstanceType != "" {
			cfg.Incus.InstanceType = file.Incus.InstanceType
		}
		if file.Incus.Image != "" {
			cfg.Incus.Image = file.Incus.Image
		}
		if file.Incus.Profile != "" {
			cfg.Incus.Profile = file.Incus.Profile
		}
		if file.Incus.User != "" {
			cfg.Incus.User = file.Incus.User
		}
		if file.Incus.WorkRoot != "" {
			cfg.Incus.WorkRoot = file.Incus.WorkRoot
		}
		if file.Incus.DeleteOnRelease != nil {
			cfg.Incus.DeleteOnRelease = *file.Incus.DeleteOnRelease
			MarkDeleteOnReleaseExplicit(cfg, "incus")
		}
		if file.Incus.StartTimeout != "" {
			applyLeaseDuration(&cfg.Incus.StartTimeout, file.Incus.StartTimeout)
		}
		if file.Incus.LaunchPort != "" {
			cfg.Incus.LaunchPort = file.Incus.LaunchPort
		}
		if file.Incus.ProxyListenHost != "" {
			cfg.Incus.ProxyListenHost = file.Incus.ProxyListenHost
		}
		if file.Incus.ProxyListenPort != "" {
			cfg.Incus.ProxyListenPort = file.Incus.ProxyListenPort
		}
		if file.Incus.ProxyDevice != "" {
			cfg.Incus.ProxyDevice = file.Incus.ProxyDevice
		}
		if file.Incus.TLSServerCert != "" {
			cfg.Incus.TLSServerCert = expandUserPath(file.Incus.TLSServerCert)
		}
		applyOptional(&cfg.Incus.InsecureTLS, file.Incus.InsecureTLS)
		if file.Incus.RemoteImageServer != "" {
			cfg.Incus.RemoteImageServer = file.Incus.RemoteImageServer
		}
	}
	if file.Proxmox != nil {
		if file.Proxmox.APIURL != "" {
			cfg.Proxmox.APIURL = file.Proxmox.APIURL
			cfg.credentialProvenance.proxmoxAPIURL = credentialSource
		}
		if file.Proxmox.TokenID != "" {
			cfg.Proxmox.TokenID = file.Proxmox.TokenID
			cfg.credentialProvenance.proxmoxTokenID = credentialSource
		}
		if file.Proxmox.TokenSecret != "" {
			cfg.Proxmox.TokenSecret = file.Proxmox.TokenSecret
			cfg.credentialProvenance.proxmoxTokenSecret = credentialSource
		}
		if file.Proxmox.Node != "" {
			cfg.Proxmox.Node = file.Proxmox.Node
		}
		if file.Proxmox.TemplateID > 0 {
			cfg.Proxmox.TemplateID = file.Proxmox.TemplateID
		}
		if file.Proxmox.Storage != "" {
			cfg.Proxmox.Storage = file.Proxmox.Storage
		}
		if file.Proxmox.Pool != "" {
			cfg.Proxmox.Pool = file.Proxmox.Pool
		}
		if file.Proxmox.Bridge != "" {
			cfg.Proxmox.Bridge = file.Proxmox.Bridge
		}
		if file.Proxmox.User != "" {
			cfg.Proxmox.User = file.Proxmox.User
		}
		if file.Proxmox.WorkRoot != "" {
			cfg.Proxmox.WorkRoot = file.Proxmox.WorkRoot
		}
		applyOptional(&cfg.Proxmox.FullClone, file.Proxmox.FullClone)
		if file.Proxmox.InsecureTLS != nil {
			cfg.Proxmox.InsecureTLS = *file.Proxmox.InsecureTLS
			cfg.credentialProvenance.proxmoxInsecureTLS = credentialSource
		}
	}
	if file.Firecracker != nil {
		if trusted && file.Firecracker.Binary != "" {
			cfg.Firecracker.Binary = expandUserPath(file.Firecracker.Binary)
		}
		if trusted && file.Firecracker.Jailer != "" {
			cfg.Firecracker.Jailer = expandUserPath(file.Firecracker.Jailer)
		}
		if trusted && file.Firecracker.Kernel != "" {
			cfg.Firecracker.Kernel = expandUserPath(file.Firecracker.Kernel)
		}
		if trusted && file.Firecracker.RootFS != "" {
			cfg.Firecracker.RootFS = expandUserPath(file.Firecracker.RootFS)
		}
		if file.Firecracker.User != "" {
			cfg.Firecracker.User = file.Firecracker.User
		}
		if file.Firecracker.WorkRoot != "" {
			cfg.Firecracker.WorkRoot = file.Firecracker.WorkRoot
		}
		applyOptional(&cfg.Firecracker.CPUs, file.Firecracker.CPUs)
		applyOptional(&cfg.Firecracker.MemoryMiB, file.Firecracker.MemoryMiB)
		applyOptional(&cfg.Firecracker.DiskMiB, file.Firecracker.DiskMiB)
		if trusted && file.Firecracker.Network != "" {
			cfg.Firecracker.Network = file.Firecracker.Network
		}
		if trusted && file.Firecracker.CNINetwork != "" {
			cfg.Firecracker.CNINetwork = file.Firecracker.CNINetwork
		}
		if trusted && file.Firecracker.CNIConfDir != "" {
			cfg.Firecracker.CNIConfDir = expandUserPath(file.Firecracker.CNIConfDir)
		}
		if trusted && file.Firecracker.CNIBinDir != "" {
			cfg.Firecracker.CNIBinDir = expandUserPath(file.Firecracker.CNIBinDir)
		}
		if file.Firecracker.LaunchTimeout != "" {
			applyLeaseDuration(&cfg.Firecracker.LaunchTimeout, file.Firecracker.LaunchTimeout)
		}
		if file.Firecracker.DeleteOnRelease != nil {
			cfg.Firecracker.DeleteOnRelease = *file.Firecracker.DeleteOnRelease
			MarkDeleteOnReleaseExplicit(cfg, "firecracker")
		}
	}
	if file.XCPNg != nil {
		// Project config is repository-controlled. Do not let it redirect
		// or replace inherited user or environment XAPI credentials.
		if trusted && file.XCPNg.APIURL != "" {
			cfg.XCPNg.APIURL = file.XCPNg.APIURL
		}
		if trusted && file.XCPNg.Username != "" {
			cfg.XCPNg.Username = file.XCPNg.Username
		}
		if trusted && file.XCPNg.Password != "" {
			cfg.XCPNg.Password = file.XCPNg.Password
		}
		if file.XCPNg.Template != "" {
			cfg.XCPNg.Template = file.XCPNg.Template
			if file.XCPNg.TemplateUUID == "" {
				cfg.XCPNg.TemplateUUID = ""
			}
		}
		if file.XCPNg.TemplateUUID != "" {
			cfg.XCPNg.TemplateUUID = file.XCPNg.TemplateUUID
			if file.XCPNg.Template == "" {
				cfg.XCPNg.Template = ""
			}
		}
		if file.XCPNg.SR != "" {
			cfg.XCPNg.SR = file.XCPNg.SR
			if file.XCPNg.SRUUID == "" {
				cfg.XCPNg.SRUUID = ""
			}
		}
		if file.XCPNg.SRUUID != "" {
			cfg.XCPNg.SRUUID = file.XCPNg.SRUUID
			if file.XCPNg.SR == "" {
				cfg.XCPNg.SR = ""
			}
		}
		if file.XCPNg.Network != "" {
			cfg.XCPNg.Network = file.XCPNg.Network
			if file.XCPNg.NetworkUUID == "" {
				cfg.XCPNg.NetworkUUID = ""
			}
		}
		if file.XCPNg.NetworkUUID != "" {
			cfg.XCPNg.NetworkUUID = file.XCPNg.NetworkUUID
			if file.XCPNg.Network == "" {
				cfg.XCPNg.Network = ""
			}
		}
		if file.XCPNg.Host != "" {
			cfg.XCPNg.Host = file.XCPNg.Host
		}
		if file.XCPNg.User != "" {
			cfg.XCPNg.User = file.XCPNg.User
		}
		if file.XCPNg.WorkRoot != "" {
			cfg.XCPNg.WorkRoot = file.XCPNg.WorkRoot
		}
		if trusted && file.XCPNg.InsecureTLS != nil {
			cfg.XCPNg.InsecureTLS = *file.XCPNg.InsecureTLS
		}
	}
	if file.Parallels != nil {
		if file.Parallels.Template != "" {
			cfg.Parallels.Template = file.Parallels.Template
		}
		if file.Parallels.Source != "" {
			cfg.Parallels.Source = file.Parallels.Source
		}
		if file.Parallels.SourceID != "" {
			cfg.Parallels.SourceID = file.Parallels.SourceID
		}
		if file.Parallels.SourceSnapshot != "" {
			cfg.Parallels.SourceSnapshot = file.Parallels.SourceSnapshot
		}
		if file.Parallels.SourceSnapshotID != "" {
			cfg.Parallels.SourceSnapshotID = file.Parallels.SourceSnapshotID
		}
		if file.Parallels.CloneMode != "" {
			cfg.Parallels.CloneMode = file.Parallels.CloneMode
		}
		if file.Parallels.Host != "" {
			cfg.Parallels.Host = file.Parallels.Host
			cfg.credentialProvenance.parallelsHost = credentialSource
		}
		if file.Parallels.HostUser != "" {
			cfg.Parallels.HostUser = file.Parallels.HostUser
		}
		if file.Parallels.HostKey != "" {
			cfg.Parallels.HostKey = expandUserPath(file.Parallels.HostKey)
			cfg.credentialProvenance.parallelsHostKey = credentialSource
		}
		if file.Parallels.VMRoot != "" {
			cfg.Parallels.VMRoot = expandUserPath(file.Parallels.VMRoot)
		}
		if file.Parallels.User != "" {
			cfg.Parallels.User = file.Parallels.User
		}
		if file.Parallels.WorkRoot != "" {
			cfg.Parallels.WorkRoot = file.Parallels.WorkRoot
		}
		applyLeaseDuration(&cfg.Parallels.StartupTimeout, file.Parallels.StartupTimeout)
		if len(file.Parallels.Templates) > 0 {
			if cfg.Parallels.Templates == nil {
				cfg.Parallels.Templates = map[string]ParallelsTemplateConfig{}
			}
			for name, template := range file.Parallels.Templates {
				name = strings.TrimSpace(name)
				if name == "" {
					continue
				}
				merged := applyFileParallelsTemplateConfig(cfg.Parallels.Templates[name], template)
				if template.Host != "" {
					merged.hostSource = credentialSource
				}
				if template.HostKey != "" {
					merged.hostKeySource = credentialSource
				}
				cfg.Parallels.Templates[name] = merged
			}
		}
		if len(file.Parallels.Hosts) > 0 {
			cfg.Parallels.Hosts = cfg.Parallels.Hosts[:0]
			for _, host := range file.Parallels.Hosts {
				merged := applyFileParallelsHostConfig(host)
				if host.Host != "" {
					merged.hostSource = credentialSource
				}
				if host.Key != "" {
					merged.keySource = credentialSource
				}
				cfg.Parallels.Hosts = append(cfg.Parallels.Hosts, merged)
			}
		}
	}
	if file.SSH != nil {
		if file.SSH.User != "" {
			cfg.SSHUser = file.SSH.User
			MarkSSHUserExplicit(cfg)
		}
		if file.SSH.Key != "" {
			cfg.SSHKey = expandUserPath(file.SSH.Key)
			MarkSSHKeyExplicit(cfg)
			cfg.credentialProvenance.sshKey = credentialSource
		}
		if file.SSH.Port != "" {
			cfg.SSHPort = file.SSH.Port
			MarkSSHPortExplicit(cfg)
		}
		if file.SSH.FallbackPorts != nil {
			cfg.SSHFallbackPorts = normalizeList(*file.SSH.FallbackPorts)
			cfg.sshFallbackPortsExplicit = true
			cfg.explicitSSHFallbackPorts = append([]string(nil), cfg.SSHFallbackPorts...)
		}
	}
	if file.WorkRoot != "" {
		cfg.WorkRoot = file.WorkRoot
		cfg.explicitWorkRoot = file.WorkRoot
	}
	applyLeaseDuration(&cfg.TTL, file.TTL)
	applyLeaseDuration(&cfg.IdleTimeout, file.IdleTimeout)
	if file.Lease != nil {
		applyLeaseDuration(&cfg.TTL, file.Lease.TTL)
		applyLeaseDuration(&cfg.IdleTimeout, file.Lease.IdleTimeout)
	}
	if file.Sync != nil {
		cfg.Sync.Excludes = appendOrderedStrings(cfg.Sync.Excludes, file.Sync.Exclude...)
		cfg.Sync.Excludes = appendOrderedStrings(cfg.Sync.Excludes, file.Sync.Excludes...)
		cfg.Sync.Includes = appendUniqueStrings(cfg.Sync.Includes, file.Sync.Include...)
		cfg.Sync.Includes = appendUniqueStrings(cfg.Sync.Includes, file.Sync.Includes...)
		applyOptional(&cfg.Sync.Delete, file.Sync.Delete)
		applyOptional(&cfg.Sync.Checksum, file.Sync.Checksum)
		applyOptional(&cfg.Sync.GitSeed, file.Sync.GitSeed)
		applyOptional(&cfg.Sync.GitOverlay, file.Sync.GitOverlay)
		applyOptional(&cfg.Sync.Fingerprint, file.Sync.Fingerprint)
		if file.Sync.BaseRef != "" {
			cfg.Sync.BaseRef = file.Sync.BaseRef
		}
		if file.Sync.Timeout != "" {
			if timeout, err := time.ParseDuration(file.Sync.Timeout); err == nil {
				cfg.Sync.Timeout = timeout
			}
		}
		if file.Sync.WarnFiles > 0 {
			cfg.Sync.WarnFiles = file.Sync.WarnFiles
		}
		if file.Sync.WarnBytes > 0 {
			cfg.Sync.WarnBytes = file.Sync.WarnBytes
		}
		if file.Sync.FailFiles > 0 {
			cfg.Sync.FailFiles = file.Sync.FailFiles
		}
		if file.Sync.FailBytes > 0 {
			cfg.Sync.FailBytes = file.Sync.FailBytes
		}
		applyOptional(&cfg.Sync.AllowLarge, file.Sync.AllowLarge)
	}
	if file.Run != nil && file.Run.PreflightTools != nil {
		cfg.Run.PreflightTools = normalizePreflightToolNames(file.Run.PreflightTools)
	}
	if file.Env != nil && file.Env.Allow != nil {
		cfg.EnvAllow = appendUniqueStrings(nil, file.Env.Allow...)
	}
	if file.Capacity != nil {
		if file.Capacity.Market != "" {
			cfg.Capacity.Market = file.Capacity.Market
			MarkCapacityMarketExplicit(cfg)
		}
		if file.Capacity.Strategy != "" {
			cfg.Capacity.Strategy = file.Capacity.Strategy
		}
		if file.Capacity.Fallback != "" {
			cfg.Capacity.Fallback = file.Capacity.Fallback
		}
		if len(file.Capacity.Regions) > 0 {
			cfg.Capacity.Regions = appendUniqueStrings(nil, file.Capacity.Regions...)
		}
		if len(file.Capacity.AvailabilityZones) > 0 {
			cfg.Capacity.AvailabilityZones = appendUniqueStrings(nil, file.Capacity.AvailabilityZones...)
		}
		applyOptional(&cfg.Capacity.Hints, file.Capacity.Hints)
	}
	if file.Actions != nil {
		if file.Actions.Repo != "" {
			cfg.Actions.Repo = file.Actions.Repo
		}
		if file.Actions.Workflow != "" {
			cfg.Actions.Workflow = file.Actions.Workflow
		}
		if file.Actions.Job != "" {
			cfg.Actions.Job = file.Actions.Job
		}
		if file.Actions.Ref != "" {
			cfg.Actions.Ref = file.Actions.Ref
		}
		if len(file.Actions.Fields) > 0 {
			cfg.Actions.Fields = appendUniqueStrings(nil, file.Actions.Fields...)
		}
		if len(file.Actions.RunnerLabels) > 0 {
			cfg.Actions.RunnerLabels = appendUniqueStrings(nil, file.Actions.RunnerLabels...)
		}
		if file.Actions.RunnerVersion != "" {
			cfg.Actions.RunnerVersion = file.Actions.RunnerVersion
		}
		applyOptional(&cfg.Actions.Ephemeral, file.Actions.Ephemeral)
	}
	if file.Blacksmith != nil {
		if file.Blacksmith.Org != "" {
			cfg.Blacksmith.Org = file.Blacksmith.Org
		}
		if file.Blacksmith.Workflow != "" {
			cfg.Blacksmith.Workflow = file.Blacksmith.Workflow
		}
		if file.Blacksmith.Job != "" {
			cfg.Blacksmith.Job = file.Blacksmith.Job
		}
		if file.Blacksmith.Ref != "" {
			cfg.Blacksmith.Ref = file.Blacksmith.Ref
		}
		applyLeaseDuration(&cfg.Blacksmith.IdleTimeout, file.Blacksmith.IdleTimeout)
		applyOptional(&cfg.Blacksmith.Debug, file.Blacksmith.Debug)
	}
	if file.KubeVirt != nil {
		if file.KubeVirt.Kubectl != "" {
			cfg.KubeVirt.Kubectl = expandUserPath(file.KubeVirt.Kubectl)
		}
		if file.KubeVirt.Virtctl != "" {
			cfg.KubeVirt.Virtctl = expandUserPath(file.KubeVirt.Virtctl)
		}
		if file.KubeVirt.Kubeconfig != "" {
			cfg.KubeVirt.Kubeconfig = expandUserPath(file.KubeVirt.Kubeconfig)
		}
		if file.KubeVirt.Context != "" {
			cfg.KubeVirt.Context = file.KubeVirt.Context
		}
		if file.KubeVirt.Namespace != "" {
			cfg.KubeVirt.Namespace = file.KubeVirt.Namespace
		}
		if file.KubeVirt.Template != "" {
			cfg.KubeVirt.Template = expandUserPath(file.KubeVirt.Template)
		}
		if file.KubeVirt.SSHUser != "" {
			cfg.KubeVirt.SSHUser = file.KubeVirt.SSHUser
		}
		if trusted && file.KubeVirt.SSHKey != "" {
			cfg.KubeVirt.SSHKey = expandUserPath(file.KubeVirt.SSHKey)
		}
		if file.KubeVirt.SSHPublicKey != "" && (trusted || inlineSSHPublicKey(file.KubeVirt.SSHPublicKey)) {
			cfg.KubeVirt.SSHPublicKey = expandUserPath(file.KubeVirt.SSHPublicKey)
		}
		if file.KubeVirt.SSHPort != "" {
			cfg.KubeVirt.SSHPort = file.KubeVirt.SSHPort
		}
		if file.KubeVirt.WorkRoot != "" {
			cfg.KubeVirt.WorkRoot = file.KubeVirt.WorkRoot
		}
		if file.KubeVirt.DeleteOnRelease != nil {
			cfg.KubeVirt.DeleteOnRelease = *file.KubeVirt.DeleteOnRelease
			MarkDeleteOnReleaseExplicit(cfg, "kubevirt")
		}
	}
	if file.SealosDevbox != nil {
		if trusted && file.SealosDevbox.Kubectl != "" {
			cfg.SealosDevbox.Kubectl = expandUserPath(file.SealosDevbox.Kubectl)
		}
		if trusted && file.SealosDevbox.Kubeconfig != "" {
			cfg.SealosDevbox.Kubeconfig = expandUserPath(file.SealosDevbox.Kubeconfig)
		}
		if trusted && file.SealosDevbox.Context != "" {
			cfg.SealosDevbox.Context = file.SealosDevbox.Context
		}
		if trusted && file.SealosDevbox.Namespace != "" {
			cfg.SealosDevbox.Namespace = file.SealosDevbox.Namespace
		}
		if trusted && file.SealosDevbox.Image != "" {
			cfg.SealosDevbox.Image = file.SealosDevbox.Image
		}
		if trusted && file.SealosDevbox.TemplateID != "" {
			cfg.SealosDevbox.TemplateID = file.SealosDevbox.TemplateID
		}
		if trusted && file.SealosDevbox.CPU != "" {
			cfg.SealosDevbox.CPU = file.SealosDevbox.CPU
		}
		if trusted && file.SealosDevbox.Memory != "" {
			cfg.SealosDevbox.Memory = file.SealosDevbox.Memory
		}
		if trusted && file.SealosDevbox.StorageLimit != "" {
			cfg.SealosDevbox.StorageLimit = file.SealosDevbox.StorageLimit
		}
		if trusted && file.SealosDevbox.Network != "" {
			cfg.SealosDevbox.Network = file.SealosDevbox.Network
		}
		if trusted && file.SealosDevbox.SSHGatewayHost != "" {
			cfg.SealosDevbox.SSHGatewayHost = file.SealosDevbox.SSHGatewayHost
		}
		if trusted && file.SealosDevbox.SSHGatewayPort != "" {
			cfg.SealosDevbox.SSHGatewayPort = file.SealosDevbox.SSHGatewayPort
		}
		if trusted && file.SealosDevbox.SSHUser != "" {
			cfg.SealosDevbox.SSHUser = file.SealosDevbox.SSHUser
		}
		if trusted && file.SealosDevbox.WorkRoot != "" {
			cfg.SealosDevbox.WorkRoot = file.SealosDevbox.WorkRoot
			MarkSealosDevboxWorkRootExplicit(cfg)
		}
		if trusted && file.SealosDevbox.NodeHost != "" {
			cfg.SealosDevbox.NodeHost = file.SealosDevbox.NodeHost
		}
		if file.SealosDevbox.DeleteOnRelease != nil {
			cfg.SealosDevbox.DeleteOnRelease = *file.SealosDevbox.DeleteOnRelease
			MarkDeleteOnReleaseExplicit(cfg, "sealos-devbox")
		}
	}
	if file.AgentSandbox != nil {
		if trusted && file.AgentSandbox.Kubectl != "" {
			cfg.AgentSandbox.Kubectl = file.AgentSandbox.Kubectl
		}
		if trusted && file.AgentSandbox.Kubeconfig != "" {
			cfg.AgentSandbox.Kubeconfig = expandUserPath(file.AgentSandbox.Kubeconfig)
		}
		if trusted && file.AgentSandbox.Context != "" {
			cfg.AgentSandbox.Context = file.AgentSandbox.Context
		}
		if trusted && file.AgentSandbox.Namespace != "" {
			cfg.AgentSandbox.Namespace = file.AgentSandbox.Namespace
		}
		if trusted && file.AgentSandbox.WarmPool != "" {
			cfg.AgentSandbox.WarmPool = file.AgentSandbox.WarmPool
		}
		if trusted && file.AgentSandbox.Container != "" {
			cfg.AgentSandbox.Container = file.AgentSandbox.Container
		}
		if trusted && file.AgentSandbox.Workdir != "" {
			cfg.AgentSandbox.Workdir = file.AgentSandbox.Workdir
		}
		if file.AgentSandbox.SandboxReadyTimeout != "" {
			applyLeaseDuration(&cfg.AgentSandbox.SandboxReadyTimeout, file.AgentSandbox.SandboxReadyTimeout)
		}
		if file.AgentSandbox.PodReadyTimeout != "" {
			applyLeaseDuration(&cfg.AgentSandbox.PodReadyTimeout, file.AgentSandbox.PodReadyTimeout)
		}
		if file.AgentSandbox.ExecTimeoutSecs != nil {
			if *file.AgentSandbox.ExecTimeoutSecs < 0 {
				return exit(2, "agentSandbox execTimeoutSecs must be non-negative")
			}
			cfg.AgentSandbox.ExecTimeoutSecs = *file.AgentSandbox.ExecTimeoutSecs
		}
		if file.AgentSandbox.DeleteOnRelease != nil {
			cfg.AgentSandbox.DeleteOnRelease = *file.AgentSandbox.DeleteOnRelease
			MarkDeleteOnReleaseExplicit(cfg, "agent-sandbox")
		}
		applyOptional(&cfg.AgentSandbox.ForgetMissing, file.AgentSandbox.ForgetMissing)
	}
	if file.External != nil {
		if file.External.Command != "" {
			cfg.External.Command = file.External.Command
		}
		if len(file.External.Args) > 0 {
			cfg.External.Args = append([]string(nil), file.External.Args...)
		}
		if file.External.Config != nil {
			cfg.External.Config = file.External.Config
			cfg.credentialProvenance.externalConfig = credentialSource
		}
		applyOptional(&cfg.External.Capabilities, file.External.Capabilities)
		if file.External.Lifecycle != nil {
			cfg.External.Lifecycle = *file.External.Lifecycle
			cfg.credentialProvenance.externalLifecycle = credentialSource
		}
		if file.External.Connection != nil {
			PreserveExternalDesktopChildEnvironmentBoundary(cfg)
			cfg.External.Connection = *file.External.Connection
			ssh := cfg.External.Connection.SSH
			cfg.credentialProvenance.externalConnection = credentialSource
			cfg.credentialProvenance.externalSSHConnection = credentialSource
			if trusted {
				targetOS, windowsMode := normalizedExternalDesktopTarget(*cfg)
				outputContract, outputContractOK := externalProviderOutputContract(cfg.External)
				if ssh.TrustProviderOutput && !outputContractOK {
					return exit(2, "external provider-output contract must be JSON encodable")
				}
				cfg.credentialProvenance.externalApproved = externalCredentialApproval{
					resource:           cfg.External.Connection.ResourceName,
					host:               ssh.Host,
					proxy:              ssh.ProxyCommand,
					allowEnv:           ssh.AllowEnv,
					envSSH:             ssh,
					providerOutput:     ssh.TrustProviderOutput,
					desktopUsername:    strings.TrimSpace(cfg.External.Connection.Desktop.Username),
					desktopEnv:         cfg.External.Connection.Desktop.PasswordEnv,
					desktopTarget:      targetOS,
					desktopWindowsMode: windowsMode,
					outputContract:     outputContract,
				}
				cfg.credentialProvenance.externalApproved.envSSH.FallbackPorts = append([]string(nil), ssh.FallbackPorts...)
			}
			cfg.credentialProvenance.externalResource = credentialDestinationSource(
				cfg.External.Connection.ResourceName, cfg.credentialProvenance.externalApproved.resource, credentialSource,
			)
			cfg.credentialProvenance.externalSSHHost = credentialDestinationSource(
				ssh.Host, cfg.credentialProvenance.externalApproved.host, credentialSource,
			)
			cfg.credentialProvenance.externalSSHProxy = credentialDestinationSource(
				ssh.ProxyCommand, cfg.credentialProvenance.externalApproved.proxy, credentialSource,
			)
			cfg.credentialProvenance.externalSSHAllowEnv = credentialSourceForBool(ssh.AllowEnv, credentialSource)
			cfg.credentialProvenance.externalDesktopUser = credentialDestinationSource(
				cfg.External.Connection.Desktop.Username,
				cfg.credentialProvenance.externalApproved.desktopUsername,
				credentialSource,
			)
			cfg.credentialProvenance.externalDesktopEnv = credentialDestinationSource(
				cfg.External.Connection.Desktop.PasswordEnv,
				cfg.credentialProvenance.externalApproved.desktopEnv,
				credentialSource,
			)
			if !trusted && ssh.AllowEnv && cfg.credentialProvenance.externalApproved.allowEnv &&
				externalSSHEnvApprovalMatches(cfg.External.Connection, cfg.credentialProvenance.externalApproved) {
				cfg.credentialProvenance.externalSSHAllowEnv = credentialSourceTrustedFile
			}
		}
		if file.External.WorkRoot != "" {
			cfg.External.WorkRoot = file.External.WorkRoot
		}
		if file.External.RoutingFile != "" {
			cfg.External.RoutingFile = file.External.RoutingFile
			cfg.credentialProvenance.externalRouting = credentialSource
		}
		if cfg.External.Connection.SSH.TrustProviderOutput {
			outputContract, outputContractOK := externalProviderOutputContract(cfg.External)
			if trusted {
				if !outputContractOK {
					return exit(2, "external provider-output contract must be JSON encodable")
				}
				cfg.credentialProvenance.externalApproved.providerOutput = true
				cfg.credentialProvenance.externalApproved.outputContract = outputContract
				cfg.credentialProvenance.externalSSHOutput = credentialSourceTrustedFile
			} else {
				cfg.credentialProvenance.externalSSHOutput = credentialSourceRepository
				if cfg.credentialProvenance.externalApproved.providerOutput &&
					outputContractOK && outputContract == cfg.credentialProvenance.externalApproved.outputContract {
					cfg.credentialProvenance.externalSSHOutput = credentialSourceTrustedFile
				}
			}
		}
		if trusted && (file.External.Lifecycle != nil || file.External.Connection != nil) {
			cfg.credentialProvenance.externalArgvApproval = externalLifecycleCredentialApproval{}
			if externalLifecycleAllowsConfigArgv(cfg.External.Lifecycle) {
				contract, ok := externalLifecycleContract(cfg.External)
				if !ok {
					return exit(2, "external lifecycle config-argv contract must be JSON encodable")
				}
				cfg.credentialProvenance.externalArgvApproval = externalLifecycleCredentialApproval{
					configArgv: true,
					contract:   contract,
				}
			}
		}
	}
	if file.Namespace != nil {
		if file.Namespace.Image != "" {
			cfg.Namespace.Image = file.Namespace.Image
		}
		if file.Namespace.Size != "" {
			cfg.Namespace.Size = file.Namespace.Size
		}
		if file.Namespace.Repository != "" {
			cfg.Namespace.Repository = file.Namespace.Repository
		}
		if file.Namespace.Site != "" {
			cfg.Namespace.Site = file.Namespace.Site
		}
		if file.Namespace.VolumeSizeGB > 0 {
			cfg.Namespace.VolumeSizeGB = file.Namespace.VolumeSizeGB
		}
		applyLeaseDuration(&cfg.Namespace.AutoStopIdleTimeout, file.Namespace.AutoStopIdleTimeout)
		if file.Namespace.WorkRoot != "" {
			cfg.Namespace.WorkRoot = file.Namespace.WorkRoot
		}
		if file.Namespace.DeleteOnRelease != nil {
			cfg.Namespace.DeleteOnRelease = *file.Namespace.DeleteOnRelease
			MarkDeleteOnReleaseExplicit(cfg, "namespace-devbox")
		}
	}
	if file.NamespaceInstance != nil {
		if trusted {
			if file.NamespaceInstance.CLIPath != "" {
				cfg.NamespaceInstance.CLIPath = expandUserPath(file.NamespaceInstance.CLIPath)
			}
			if file.NamespaceInstance.Region != "" {
				cfg.NamespaceInstance.Region = file.NamespaceInstance.Region
			}
			if file.NamespaceInstance.Endpoint != "" {
				cfg.NamespaceInstance.Endpoint = file.NamespaceInstance.Endpoint
			}
			if file.NamespaceInstance.Keychain != "" {
				cfg.NamespaceInstance.Keychain = file.NamespaceInstance.Keychain
			}
			if file.NamespaceInstance.Volumes != nil {
				cfg.NamespaceInstance.Volumes = append([]string(nil), file.NamespaceInstance.Volumes...)
			}
		}
		if file.NamespaceInstance.MachineType != "" {
			cfg.NamespaceInstance.MachineType = file.NamespaceInstance.MachineType
		}
		applyLeaseDuration(&cfg.NamespaceInstance.Duration, file.NamespaceInstance.Duration)
		if file.NamespaceInstance.WorkRoot != "" {
			cfg.NamespaceInstance.WorkRoot = file.NamespaceInstance.WorkRoot
		}
		applyOptional(&cfg.NamespaceInstance.Bare, file.NamespaceInstance.Bare)
	}
	if file.Phala != nil {
		if trusted {
			if file.Phala.CLIPath != "" {
				cfg.Phala.CLIPath = expandUserPath(file.Phala.CLIPath)
			}
			if file.Phala.NodeID != "" {
				cfg.Phala.NodeID = file.Phala.NodeID
			}
			if file.Phala.Compose != "" {
				cfg.Phala.Compose = expandUserPath(file.Phala.Compose)
			}
		}
		if file.Phala.InstanceType != "" {
			cfg.Phala.InstanceType = file.Phala.InstanceType
			MarkPhalaInstanceTypeExplicit(cfg)
		}
		if file.Phala.WorkRoot != "" {
			cfg.Phala.WorkRoot = file.Phala.WorkRoot
		}
		// attest is read from untrusted config ONLY when it tightens security
		// (enabling the TDX attestation gate). Disabling it (attest: false)
		// requires trusted config, the local --phala-skip-attestation flag, or the
		// env var, so an untrusted repo config can never weaken the security gate.
		if file.Phala.Attest != nil && (trusted || *file.Phala.Attest) {
			value := *file.Phala.Attest
			cfg.Phala.Attest = &value
		}
	}
	if file.Boxd != nil {
		// Only trusted config can redirect credentials or organization billing.
		if trusted {
			if file.Boxd.APIURL != "" {
				cfg.Boxd.APIURL = file.Boxd.APIURL
			}
			if file.Boxd.Org != "" {
				cfg.Boxd.Org = file.Boxd.Org
			}
		}
		if file.Boxd.WorkRoot != "" {
			cfg.Boxd.WorkRoot = file.Boxd.WorkRoot
			MarkBoxdWorkRootExplicit(cfg)
		}
		if file.Boxd.DeleteOnRelease != nil {
			cfg.Boxd.DeleteOnRelease = *file.Boxd.DeleteOnRelease
			MarkDeleteOnReleaseExplicit(cfg, "boxd")
		}
	}
	if file.Coder != nil {
		if file.Coder.CLIPath != "" {
			cfg.Coder.CLIPath = expandUserPath(file.Coder.CLIPath)
		}
		if file.Coder.Template != "" {
			cfg.Coder.Template = file.Coder.Template
		}
		if file.Coder.Preset != "" {
			cfg.Coder.Preset = file.Coder.Preset
		}
		if file.Coder.WorkspacePrefix != "" {
			cfg.Coder.WorkspacePrefix = file.Coder.WorkspacePrefix
		}
		if file.Coder.WorkRoot != "" {
			cfg.Coder.WorkRoot = file.Coder.WorkRoot
		}
		applyOptional(&cfg.Coder.DeleteOnRelease, file.Coder.DeleteOnRelease)
		if file.Coder.Wait != "" {
			cfg.Coder.Wait = file.Coder.Wait
		}
		applyOptional(&cfg.Coder.UseParameterDefaults, file.Coder.UseParameterDefaults)
		if len(file.Coder.Parameters) > 0 {
			cfg.Coder.Parameters = normalizeList(file.Coder.Parameters)
		}
		if file.Coder.RichParameterFile != "" {
			cfg.Coder.RichParameterFile = expandUserPath(file.Coder.RichParameterFile)
		}
	}
	if file.Morph != nil {
		if file.Morph.APIKey != "" {
			cfg.Morph.APIKey = file.Morph.APIKey
			cfg.credentialProvenance.morphAPIKey = credentialSource
		}
		if file.Morph.APIURL != "" {
			cfg.Morph.APIURL = file.Morph.APIURL
			cfg.credentialProvenance.morphAPIURL = credentialSource
		}
		if file.Morph.Snapshot != "" {
			cfg.Morph.Snapshot = file.Morph.Snapshot
		}
		if file.Morph.SSHGatewayHost != "" {
			cfg.Morph.SSHGatewayHost = file.Morph.SSHGatewayHost
			cfg.credentialProvenance.morphSSHGatewayHost = credentialSource
		}
		if file.Morph.WorkRoot != "" {
			cfg.Morph.WorkRoot = file.Morph.WorkRoot
		}
		if file.Morph.DeleteOnRelease != nil {
			cfg.Morph.DeleteOnRelease = *file.Morph.DeleteOnRelease
			MarkDeleteOnReleaseExplicit(cfg, "morph")
		}
		applyOptional(&cfg.Morph.WakeOnSSH, file.Morph.WakeOnSSH)
	}
	if file.Daytona != nil {
		if file.Daytona.APIURL != "" {
			cfg.Daytona.APIURL = file.Daytona.APIURL
			cfg.credentialProvenance.daytonaAPIURL = credentialSource
		}
		if file.Daytona.Snapshot != "" {
			cfg.Daytona.Snapshot = file.Daytona.Snapshot
		}
		if file.Daytona.Target != "" {
			cfg.Daytona.Target = file.Daytona.Target
		}
		if file.Daytona.User != "" {
			cfg.Daytona.User = file.Daytona.User
		}
		if file.Daytona.WorkRoot != "" {
			cfg.Daytona.WorkRoot = file.Daytona.WorkRoot
		}
		if file.Daytona.SSHGatewayHost != "" {
			cfg.Daytona.SSHGatewayHost = file.Daytona.SSHGatewayHost
			cfg.credentialProvenance.daytonaSSHGateway = credentialSource
		}
		if file.Daytona.SSHAccessMinutes > 0 {
			cfg.Daytona.SSHAccessMinutes = file.Daytona.SSHAccessMinutes
		}
	}
	if file.E2B != nil {
		if file.E2B.APIURL != "" {
			cfg.E2B.APIURL = file.E2B.APIURL
			cfg.credentialProvenance.e2bAPIURL = credentialSource
		}
		if file.E2B.Domain != "" {
			cfg.E2B.Domain = file.E2B.Domain
			cfg.credentialProvenance.e2bDomain = credentialSource
		}
		if file.E2B.Template != "" {
			cfg.E2B.Template = file.E2B.Template
		}
		if file.E2B.Workdir != "" {
			cfg.E2B.Workdir = file.E2B.Workdir
		}
		if file.E2B.User != "" {
			cfg.E2B.User = file.E2B.User
		}
	}
	if file.CubeSandbox != nil {
		if file.CubeSandbox.APIURL != "" {
			cfg.CubeSandbox.APIURL = file.CubeSandbox.APIURL
			cfg.credentialProvenance.cubeSandboxAPIURL = credentialSource
		}
		if file.CubeSandbox.Domain != "" {
			cfg.CubeSandbox.Domain = file.CubeSandbox.Domain
			cfg.credentialProvenance.cubeSandboxDomain = credentialSource
		}
		if file.CubeSandbox.Template != "" {
			cfg.CubeSandbox.Template = file.CubeSandbox.Template
		}
		if file.CubeSandbox.Workdir != "" {
			cfg.CubeSandbox.Workdir = file.CubeSandbox.Workdir
		}
		if file.CubeSandbox.User != "" {
			cfg.CubeSandbox.User = file.CubeSandbox.User
		}
		if file.CubeSandbox.ProxyNodeIP != "" {
			cfg.CubeSandbox.ProxyNodeIP = file.CubeSandbox.ProxyNodeIP
			cfg.credentialProvenance.cubeSandboxProxyNode = credentialSource
		}
		if file.CubeSandbox.ProxyPortHTTP > 0 {
			cfg.CubeSandbox.ProxyPortHTTP = file.CubeSandbox.ProxyPortHTTP
			cfg.credentialProvenance.cubeSandboxProxyPort = credentialSource
		}
		if file.CubeSandbox.ProxyScheme != "" {
			cfg.CubeSandbox.ProxyScheme = file.CubeSandbox.ProxyScheme
			cfg.credentialProvenance.cubeSandboxProxyProto = credentialSource
		}
	}
	if file.ExeDev != nil {
		if file.ExeDev.ControlHost != "" {
			cfg.ExeDev.ControlHost = file.ExeDev.ControlHost
			cfg.credentialProvenance.exeDevControlHost = credentialSource
		}
		if file.ExeDev.Image != "" {
			cfg.ExeDev.Image = file.ExeDev.Image
		}
		if file.ExeDev.CPUs > 0 {
			cfg.ExeDev.CPUs = file.ExeDev.CPUs
		}
		if file.ExeDev.Memory != "" {
			cfg.ExeDev.Memory = file.ExeDev.Memory
		}
		if file.ExeDev.Disk != "" {
			cfg.ExeDev.Disk = file.ExeDev.Disk
		}
		if file.ExeDev.Command != "" {
			cfg.ExeDev.Command = file.ExeDev.Command
		}
		if file.ExeDev.User != "" {
			cfg.ExeDev.User = file.ExeDev.User
		}
		if file.ExeDev.WorkRoot != "" {
			cfg.ExeDev.WorkRoot = file.ExeDev.WorkRoot
		}
		applyOptional(&cfg.ExeDev.NoEmail, file.ExeDev.NoEmail)
	}
	if file.Railway != nil {
		if file.Railway.APIURL != "" {
			cfg.Railway.APIURL = file.Railway.APIURL
			cfg.credentialProvenance.railwayAPIURL = credentialSource
		}
		if file.Railway.ProjectID != "" {
			cfg.Railway.ProjectID = file.Railway.ProjectID
		}
		if file.Railway.EnvironmentID != "" {
			cfg.Railway.EnvironmentID = file.Railway.EnvironmentID
		}
	}
	if file.FastAPICloud != nil {
		if file.FastAPICloud.APIURL != "" {
			cfg.FastAPICloud.APIURL = file.FastAPICloud.APIURL
			cfg.credentialProvenance.fastAPICloudAPIURL = credentialSource
		}
		if file.FastAPICloud.AppID != "" {
			cfg.FastAPICloud.AppID = file.FastAPICloud.AppID
		}
		if file.FastAPICloud.TeamID != "" {
			cfg.FastAPICloud.TeamID = file.FastAPICloud.TeamID
		}
	}
	if file.UnikraftCloud != nil {
		if file.UnikraftCloud.APIKey != "" {
			cfg.UnikraftCloud.APIKey = file.UnikraftCloud.APIKey
			cfg.credentialProvenance.unikraftCloudAPIKey = credentialSource
		}
		if file.UnikraftCloud.APIURL != "" {
			cfg.UnikraftCloud.APIURL = file.UnikraftCloud.APIURL
			cfg.credentialProvenance.unikraftCloudAPIURL = credentialSource
		}
		if file.UnikraftCloud.Metro != "" {
			cfg.UnikraftCloud.Metro = file.UnikraftCloud.Metro
		}
		if file.UnikraftCloud.Image != "" {
			cfg.UnikraftCloud.Image = file.UnikraftCloud.Image
		}
		if file.UnikraftCloud.MemoryMB > 0 {
			cfg.UnikraftCloud.MemoryMB = file.UnikraftCloud.MemoryMB
		}
	}
	if file.Runpod != nil {
		if file.Runpod.APIURL != "" {
			cfg.Runpod.APIURL = file.Runpod.APIURL
			cfg.credentialProvenance.runpodAPIURL = credentialSource
		}
		if file.Runpod.CloudType != "" {
			cfg.Runpod.CloudType = file.Runpod.CloudType
		}
		if file.Runpod.InstanceID != "" {
			cfg.Runpod.InstanceID = file.Runpod.InstanceID
		}
		if file.Runpod.Image != "" {
			cfg.Runpod.Image = file.Runpod.Image
		}
		if file.Runpod.TemplateID != "" {
			cfg.Runpod.TemplateID = file.Runpod.TemplateID
		}
		if file.Runpod.DiskGB != 0 {
			cfg.Runpod.DiskGB = file.Runpod.DiskGB
		}
		if file.Runpod.User != "" {
			cfg.Runpod.User = file.Runpod.User
		}
		if file.Runpod.WorkRoot != "" {
			cfg.Runpod.WorkRoot = file.Runpod.WorkRoot
		}
	}
	if file.Vast != nil {
		if file.Vast.APIURL != "" {
			cfg.Vast.APIURL = file.Vast.APIURL
			cfg.credentialProvenance.vastAPIURL = credentialSource
		}
		if file.Vast.InstanceType != "" {
			cfg.Vast.InstanceType = file.Vast.InstanceType
		}
		if file.Vast.GPUName != "" {
			cfg.Vast.GPUName = file.Vast.GPUName
		}
		if file.Vast.GPUCount != 0 {
			cfg.Vast.GPUCount = file.Vast.GPUCount
		}
		if file.Vast.Image != "" {
			cfg.Vast.Image = file.Vast.Image
		}
		if file.Vast.TemplateID != "" {
			cfg.Vast.TemplateID = file.Vast.TemplateID
		}
		if file.Vast.Runtype != "" {
			cfg.Vast.Runtype = file.Vast.Runtype
		}
		if file.Vast.DiskGB != 0 {
			cfg.Vast.DiskGB = file.Vast.DiskGB
		}
		applyOptional(&cfg.Vast.MaxDphTotal, file.Vast.MaxDphTotal)
		applyOptional(&cfg.Vast.MinReliability, file.Vast.MinReliability)
		if file.Vast.Order != "" {
			cfg.Vast.Order = file.Vast.Order
		}
		if file.Vast.User != "" {
			cfg.Vast.User = file.Vast.User
		}
		if file.Vast.WorkRoot != "" {
			cfg.Vast.WorkRoot = file.Vast.WorkRoot
			MarkVastWorkRootExplicit(cfg)
		}
		if file.Vast.ReleaseAction != "" {
			cfg.Vast.ReleaseAction = file.Vast.ReleaseAction
			MarkDeleteOnReleaseExplicit(cfg, "vast")
		}
	}
	if file.NvidiaBrev != nil {
		if trusted && file.NvidiaBrev.CLI != "" {
			cfg.NvidiaBrev.CLI = file.NvidiaBrev.CLI
		}
		if file.NvidiaBrev.Org != "" {
			cfg.NvidiaBrev.Org = file.NvidiaBrev.Org
		}
		if file.NvidiaBrev.Type != "" {
			cfg.NvidiaBrev.Type = file.NvidiaBrev.Type
		}
		if file.NvidiaBrev.GPUName != "" {
			cfg.NvidiaBrev.GPUName = file.NvidiaBrev.GPUName
		}
		if file.NvidiaBrev.Provider != "" {
			cfg.NvidiaBrev.Provider = file.NvidiaBrev.Provider
		}
		if file.NvidiaBrev.Mode != "" {
			cfg.NvidiaBrev.Mode = file.NvidiaBrev.Mode
		}
		if file.NvidiaBrev.Launchable != "" {
			cfg.NvidiaBrev.Launchable = file.NvidiaBrev.Launchable
		}
		if file.NvidiaBrev.StartupScript != "" &&
			(trusted || !strings.HasPrefix(strings.TrimSpace(file.NvidiaBrev.StartupScript), "@")) {
			cfg.NvidiaBrev.StartupScript = file.NvidiaBrev.StartupScript
		}
		if file.NvidiaBrev.ReleaseAction != "" {
			cfg.NvidiaBrev.ReleaseAction = file.NvidiaBrev.ReleaseAction
			MarkDeleteOnReleaseExplicit(cfg, "nvidia-brev")
		}
		if file.NvidiaBrev.Target != "" {
			cfg.NvidiaBrev.Target = file.NvidiaBrev.Target
		}
		if file.NvidiaBrev.User != "" {
			cfg.NvidiaBrev.User = file.NvidiaBrev.User
		}
		if file.NvidiaBrev.WorkRoot != "" {
			cfg.NvidiaBrev.WorkRoot = file.NvidiaBrev.WorkRoot
			MarkNvidiaBrevWorkRootExplicit(cfg)
		}
	}
	if file.Hostinger != nil {
		if trusted && file.Hostinger.APIToken != "" {
			cfg.Hostinger.APIToken = file.Hostinger.APIToken
		}
		if trusted && file.Hostinger.APIURL != "" {
			cfg.Hostinger.APIURL = file.Hostinger.APIURL
		}
		if trusted && file.Hostinger.ItemID != "" {
			cfg.Hostinger.ItemID = file.Hostinger.ItemID
		}
		if trusted && file.Hostinger.PaymentMethodID != "" {
			cfg.Hostinger.PaymentMethodID = file.Hostinger.PaymentMethodID
		}
		if trusted && file.Hostinger.TemplateID != "" {
			cfg.Hostinger.TemplateID = file.Hostinger.TemplateID
		}
		if trusted && file.Hostinger.DataCenterID != "" {
			cfg.Hostinger.DataCenterID = file.Hostinger.DataCenterID
		}
		if file.Hostinger.HostnamePrefix != "" {
			cfg.Hostinger.HostnamePrefix = file.Hostinger.HostnamePrefix
		}
		if file.Hostinger.User != "" {
			cfg.Hostinger.User = file.Hostinger.User
			MarkHostingerUserExplicit(cfg)
		}
		if file.Hostinger.WorkRoot != "" {
			cfg.Hostinger.WorkRoot = file.Hostinger.WorkRoot
			MarkHostingerWorkRootExplicit(cfg)
		}
		if file.Hostinger.AllowPurchase != nil && (trusted || !*file.Hostinger.AllowPurchase) {
			cfg.Hostinger.AllowPurchase = *file.Hostinger.AllowPurchase
		}
		if file.Hostinger.ReleaseAction != "" {
			cfg.Hostinger.ReleaseAction = file.Hostinger.ReleaseAction
		}
	}
	if file.Wandb != nil {
		if file.Wandb.APIKey != "" {
			cfg.Wandb.APIKey = file.Wandb.APIKey
		}
		if file.Wandb.DefaultImage != "" {
			cfg.Wandb.DefaultImage = file.Wandb.DefaultImage
		}
		if file.Wandb.MaxLifetimeSeconds > 0 {
			cfg.Wandb.MaxLifetimeSeconds = file.Wandb.MaxLifetimeSeconds
		}
	}
	if file.Orgo != nil {
		if trusted && file.Orgo.APIKey != "" {
			cfg.Orgo.APIKey = file.Orgo.APIKey
			cfg.credentialProvenance.orgoAPIKey = credentialSource
		}
		if file.Orgo.APIBase != "" {
			cfg.Orgo.APIBase = file.Orgo.APIBase
			cfg.credentialProvenance.orgoAPIBase = credentialSource
		}
		if file.Orgo.WorkspaceID != "" {
			cfg.Orgo.WorkspaceID = file.Orgo.WorkspaceID
		}
		if file.Orgo.RAMGB > 0 {
			cfg.Orgo.RAMGB = file.Orgo.RAMGB
		}
		if file.Orgo.CPUs > 0 {
			cfg.Orgo.CPUs = file.Orgo.CPUs
		}
		if file.Orgo.DiskGB > 0 {
			cfg.Orgo.DiskGB = file.Orgo.DiskGB
		}
		if file.Orgo.Resolution != "" {
			cfg.Orgo.Resolution = file.Orgo.Resolution
		}
	}
	if file.Islo != nil {
		if file.Islo.BaseURL != "" {
			cfg.Islo.BaseURL = file.Islo.BaseURL
			cfg.credentialProvenance.isloBaseURL = credentialSource
		}
		if file.Islo.Image != "" {
			cfg.Islo.Image = file.Islo.Image
			cfg.isloImageExplicit = true
		}
		if file.Islo.Workdir != "" {
			cfg.Islo.Workdir = file.Islo.Workdir
		}
		if file.Islo.GatewayProfile != "" {
			cfg.Islo.GatewayProfile = file.Islo.GatewayProfile
		}
		if file.Islo.SnapshotName != "" {
			cfg.Islo.SnapshotName = file.Islo.SnapshotName
		}
		if file.Islo.VCPUs > 0 {
			cfg.Islo.VCPUs = file.Islo.VCPUs
			cfg.isloVCPUsExplicit = true
		}
		if file.Islo.MemoryMB > 0 {
			cfg.Islo.MemoryMB = file.Islo.MemoryMB
			cfg.isloMemoryMBExplicit = true
		}
		if file.Islo.DiskGB > 0 {
			cfg.Islo.DiskGB = file.Islo.DiskGB
			cfg.isloDiskGBExplicit = true
		}
	}
	if file.Freestyle != nil {
		if file.Freestyle.APIURL != "" {
			cfg.Freestyle.APIURL = file.Freestyle.APIURL
		}
		if file.Freestyle.Workdir != "" {
			cfg.Freestyle.Workdir = file.Freestyle.Workdir
		}
		if file.Freestyle.VCPUs > 0 {
			cfg.Freestyle.VCPUs = file.Freestyle.VCPUs
		}
		if file.Freestyle.MemoryGB > 0 {
			cfg.Freestyle.MemoryGB = file.Freestyle.MemoryGB
		}
	}
	if file.Tenki != nil {
		if file.Tenki.CLIPath != "" {
			cfg.Tenki.CLIPath = file.Tenki.CLIPath
		}
		if file.Tenki.Endpoint != "" {
			cfg.Tenki.Endpoint = file.Tenki.Endpoint
			cfg.credentialProvenance.tenkiEndpoint = credentialSource
		}
		if file.Tenki.Gateway != "" {
			cfg.Tenki.Gateway = file.Tenki.Gateway
			cfg.credentialProvenance.tenkiGateway = credentialSource
		}
		if file.Tenki.Workspace != "" {
			cfg.Tenki.Workspace = file.Tenki.Workspace
		}
		if file.Tenki.Project != "" {
			cfg.Tenki.Project = file.Tenki.Project
		}
		if file.Tenki.Image != "" {
			cfg.Tenki.Image = file.Tenki.Image
		}
		if file.Tenki.Snapshot != "" {
			cfg.Tenki.Snapshot = file.Tenki.Snapshot
		}
		if file.Tenki.WorkRoot != "" {
			cfg.Tenki.WorkRoot = file.Tenki.WorkRoot
		}
		if file.Tenki.CPUs > 0 {
			cfg.Tenki.CPUs = file.Tenki.CPUs
		}
		if file.Tenki.MemoryMB > 0 {
			cfg.Tenki.MemoryMB = file.Tenki.MemoryMB
		}
		if file.Tenki.DiskGB > 0 {
			cfg.Tenki.DiskGB = file.Tenki.DiskGB
		}
	}
	if file.Tensorlake != nil {
		if file.Tensorlake.APIURL != "" {
			cfg.Tensorlake.APIURL = file.Tensorlake.APIURL
			cfg.credentialProvenance.tensorlakeAPIURL = credentialSource
		}
		if file.Tensorlake.CLIPath != "" {
			cfg.Tensorlake.CLIPath = file.Tensorlake.CLIPath
		}
		if file.Tensorlake.Image != "" {
			cfg.Tensorlake.Image = file.Tensorlake.Image
		}
		if file.Tensorlake.Snapshot != "" {
			cfg.Tensorlake.Snapshot = file.Tensorlake.Snapshot
		}
		if file.Tensorlake.OrganizationID != "" {
			cfg.Tensorlake.OrganizationID = file.Tensorlake.OrganizationID
		}
		if file.Tensorlake.ProjectID != "" {
			cfg.Tensorlake.ProjectID = file.Tensorlake.ProjectID
		}
		if file.Tensorlake.Namespace != "" {
			cfg.Tensorlake.Namespace = file.Tensorlake.Namespace
		}
		if file.Tensorlake.Workdir != "" {
			cfg.Tensorlake.Workdir = file.Tensorlake.Workdir
		}
		if file.Tensorlake.CPUs > 0 {
			cfg.Tensorlake.CPUs = file.Tensorlake.CPUs
		}
		if file.Tensorlake.MemoryMB > 0 {
			cfg.Tensorlake.MemoryMB = file.Tensorlake.MemoryMB
		}
		if file.Tensorlake.DiskMB > 0 {
			cfg.Tensorlake.DiskMB = file.Tensorlake.DiskMB
		}
		if file.Tensorlake.TimeoutSecs > 0 {
			cfg.Tensorlake.TimeoutSecs = file.Tensorlake.TimeoutSecs
		}
		applyOptional(&cfg.Tensorlake.NoInternet, file.Tensorlake.NoInternet)
	}
	if file.Cua != nil {
		applyOptional(&cfg.Cua.Image, file.Cua.Image)
		applyOptional(&cfg.Cua.Kind, file.Cua.Kind)
		applyOptional(&cfg.Cua.Region, file.Cua.Region)
		applyOptional(&cfg.Cua.Workdir, file.Cua.Workdir)
		if file.Cua.VCPUs != nil {
			if *file.Cua.VCPUs < 0 {
				return exit(2, "cua vcpus must be non-negative")
			}
			cfg.Cua.VCPUs = *file.Cua.VCPUs
		}
		if file.Cua.MemoryMB != nil {
			if *file.Cua.MemoryMB < 0 {
				return exit(2, "cua memoryMB must be non-negative")
			}
			cfg.Cua.MemoryMB = *file.Cua.MemoryMB
		}
		if file.Cua.DiskGB != nil {
			if *file.Cua.DiskGB < 0 {
				return exit(2, "cua diskGB must be non-negative")
			}
			cfg.Cua.DiskGB = *file.Cua.DiskGB
		}
		if file.Cua.StartupTimeoutSecs != nil {
			if *file.Cua.StartupTimeoutSecs < 0 {
				return exit(2, "cua startupTimeoutSecs must be non-negative")
			}
			cfg.Cua.StartupTimeoutSecs = *file.Cua.StartupTimeoutSecs
		}
		if file.Cua.ExecTimeoutSecs != nil {
			if *file.Cua.ExecTimeoutSecs < 0 {
				return exit(2, "cua execTimeoutSecs must be non-negative")
			}
			cfg.Cua.ExecTimeoutSecs = *file.Cua.ExecTimeoutSecs
		}
		if trusted && file.Cua.BridgeCommand != nil {
			cfg.Cua.BridgeCommand = *file.Cua.BridgeCommand
		}
		if trusted && file.Cua.SDKPackage != nil {
			cfg.Cua.SDKPackage = *file.Cua.SDKPackage
		}
		if trusted && file.Cua.SDKImport != nil {
			cfg.Cua.SDKImport = *file.Cua.SDKImport
		}
		if trusted && file.Cua.SDKFallbackImport != nil {
			cfg.Cua.SDKFallbackImport = *file.Cua.SDKFallbackImport
		}
	}
	if file.OpenComputer != nil {
		if file.OpenComputer.Workdir != "" {
			cfg.OpenComputer.Workdir = file.OpenComputer.Workdir
		}
		applyOptional(&cfg.OpenComputer.CPU, file.OpenComputer.CPU)
		applyOptional(&cfg.OpenComputer.MemoryMB, file.OpenComputer.MemoryMB)
		applyOptional(&cfg.OpenComputer.TimeoutSecs, file.OpenComputer.TimeoutSecs)
		applyOptional(&cfg.OpenComputer.ExecTimeoutSecs, file.OpenComputer.ExecTimeoutSecs)
		applyOptional(&cfg.OpenComputer.Burst, file.OpenComputer.Burst)
	}
	if file.CodeSandbox != nil {
		applyOptional(&cfg.CodeSandbox.TemplateID, file.CodeSandbox.TemplateID)
		applyOptional(&cfg.CodeSandbox.Workdir, file.CodeSandbox.Workdir)
		applyOptional(&cfg.CodeSandbox.VMTier, file.CodeSandbox.VMTier)
		applyOptional(&cfg.CodeSandbox.Privacy, file.CodeSandbox.Privacy)
		if file.CodeSandbox.HibernationTimeoutSecs != nil {
			if *file.CodeSandbox.HibernationTimeoutSecs < 0 {
				return exit(2, "codesandbox hibernationTimeoutSecs must be non-negative")
			}
			cfg.CodeSandbox.HibernationTimeoutSecs = *file.CodeSandbox.HibernationTimeoutSecs
		}
		applyOptional(&cfg.CodeSandbox.AutomaticWakeupHTTP, file.CodeSandbox.AutomaticWakeupHTTP)
		applyOptional(&cfg.CodeSandbox.AutomaticWakeupWebSocket, file.CodeSandbox.AutomaticWakeupWebSocket)
		if trusted && file.CodeSandbox.BridgeCommand != nil {
			cfg.CodeSandbox.BridgeCommand = *file.CodeSandbox.BridgeCommand
		}
		if trusted && file.CodeSandbox.SDKPackage != nil {
			cfg.CodeSandbox.SDKPackage = *file.CodeSandbox.SDKPackage
		}
		if file.CodeSandbox.DoctorListLimit != nil {
			if *file.CodeSandbox.DoctorListLimit < 0 {
				return exit(2, "codesandbox doctorListLimit must be non-negative")
			}
			cfg.CodeSandbox.DoctorListLimit = *file.CodeSandbox.DoctorListLimit
		}
		if file.CodeSandbox.OperationTimeoutSecs != nil {
			if *file.CodeSandbox.OperationTimeoutSecs < 0 {
				return exit(2, "codesandbox operationTimeoutSecs must be non-negative")
			}
			cfg.CodeSandbox.OperationTimeoutSecs = *file.CodeSandbox.OperationTimeoutSecs
		}
	}
	if file.OpenSandbox != nil {
		applyOptional(&cfg.OpenSandbox.Image, file.OpenSandbox.Image)
		applyOptional(&cfg.OpenSandbox.Workdir, file.OpenSandbox.Workdir)
		applyOptional(&cfg.OpenSandbox.CPU, file.OpenSandbox.CPU)
		applyOptional(&cfg.OpenSandbox.Memory, file.OpenSandbox.Memory)
		if file.OpenSandbox.TimeoutSecs != nil {
			if *file.OpenSandbox.TimeoutSecs < 0 {
				return exit(2, "opensandbox timeoutSecs must be non-negative")
			}
			cfg.OpenSandbox.TimeoutSecs = *file.OpenSandbox.TimeoutSecs
		}
		if file.OpenSandbox.ExecTimeoutSecs != nil {
			if *file.OpenSandbox.ExecTimeoutSecs < 0 {
				return exit(2, "opensandbox execTimeoutSecs must be non-negative")
			}
			cfg.OpenSandbox.ExecTimeoutSecs = *file.OpenSandbox.ExecTimeoutSecs
		}
		applyOptional(&cfg.OpenSandbox.PlatformOS, file.OpenSandbox.PlatformOS)
		applyOptional(&cfg.OpenSandbox.PlatformArch, file.OpenSandbox.PlatformArch)
		applyOptional(&cfg.OpenSandbox.SecureAccess, file.OpenSandbox.SecureAccess)
		applyOptional(&cfg.OpenSandbox.UseServerProxy, file.OpenSandbox.UseServerProxy)
	}
	if file.Nomad != nil {
		if trusted && file.Nomad.Address != "" {
			cfg.Nomad.Address = file.Nomad.Address
			cfg.credentialProvenance.nomadAddress = credentialSource
		}
		if trusted && file.Nomad.TokenEnv != "" {
			cfg.Nomad.TokenEnv = file.Nomad.TokenEnv
			cfg.credentialProvenance.nomadTokenEnv = credentialSource
		}
		if trusted && file.Nomad.CACert != "" {
			cfg.Nomad.CACert = expandUserPath(file.Nomad.CACert)
		}
		if trusted && file.Nomad.CAPath != "" {
			cfg.Nomad.CAPath = expandUserPath(file.Nomad.CAPath)
		}
		if trusted && file.Nomad.ClientCert != "" {
			cfg.Nomad.ClientCert = expandUserPath(file.Nomad.ClientCert)
		}
		if trusted && file.Nomad.ClientKey != "" {
			cfg.Nomad.ClientKey = expandUserPath(file.Nomad.ClientKey)
		}
		if trusted && file.Nomad.TLSServerName != "" {
			cfg.Nomad.TLSServerName = file.Nomad.TLSServerName
		}
		if trusted && file.Nomad.SkipVerify != nil {
			cfg.Nomad.SkipVerify = *file.Nomad.SkipVerify
		}
		if trusted {
			if file.Nomad.Region != "" {
				cfg.Nomad.Region = file.Nomad.Region
			}
			if file.Nomad.Namespace != "" {
				cfg.Nomad.Namespace = file.Nomad.Namespace
			}
			applyOptional(&cfg.Nomad.Task, file.Nomad.Task)
			applyOptional(&cfg.Nomad.Driver, file.Nomad.Driver)
			applyOptional(&cfg.Nomad.Image, file.Nomad.Image)
			applyOptional(&cfg.Nomad.Workdir, file.Nomad.Workdir)
			if file.Nomad.JobSpecTemplate != "" {
				cfg.Nomad.JobSpecTemplate = expandUserPath(file.Nomad.JobSpecTemplate)
			}
			if file.Nomad.NodePool != "" {
				cfg.Nomad.NodePool = file.Nomad.NodePool
			}
			if len(file.Nomad.Datacenters) > 0 {
				cfg.Nomad.Datacenters = normalizeList(file.Nomad.Datacenters)
			}
			if file.Nomad.CPU != nil {
				if *file.Nomad.CPU < 0 {
					return exit(2, "nomad cpu must be non-negative")
				}
				cfg.Nomad.CPU = *file.Nomad.CPU
			}
			if file.Nomad.MemoryMB != nil {
				if *file.Nomad.MemoryMB < 0 {
					return exit(2, "nomad memoryMB must be non-negative")
				}
				cfg.Nomad.MemoryMB = *file.Nomad.MemoryMB
			}
			if file.Nomad.DiskMB != nil {
				if *file.Nomad.DiskMB < 0 {
					return exit(2, "nomad diskMB must be non-negative")
				}
				cfg.Nomad.DiskMB = *file.Nomad.DiskMB
			}
			if file.Nomad.AllocReadyTimeout != "" {
				applyLeaseDuration(&cfg.Nomad.AllocReadyTimeout, file.Nomad.AllocReadyTimeout)
			}
			if file.Nomad.EvalTimeout != "" {
				applyLeaseDuration(&cfg.Nomad.EvalTimeout, file.Nomad.EvalTimeout)
			}
			if file.Nomad.ExecTimeoutSecs != nil {
				if *file.Nomad.ExecTimeoutSecs < 0 {
					return exit(2, "nomad execTimeoutSecs must be non-negative")
				}
				cfg.Nomad.ExecTimeoutSecs = *file.Nomad.ExecTimeoutSecs
			}
		}
	}
	if file.Blaxel != nil {
		if trusted && file.Blaxel.APIURL != "" {
			cfg.Blaxel.APIURL = file.Blaxel.APIURL
		}
		if trusted && file.Blaxel.Workspace != "" {
			cfg.Blaxel.Workspace = file.Blaxel.Workspace
		}
		if file.Blaxel.Region != "" {
			cfg.Blaxel.Region = file.Blaxel.Region
		}
		applyOptional(&cfg.Blaxel.Image, file.Blaxel.Image)
		if file.Blaxel.MemoryMB != nil {
			if *file.Blaxel.MemoryMB < 0 {
				return exit(2, "blaxel memoryMB must be non-negative")
			}
			cfg.Blaxel.MemoryMB = *file.Blaxel.MemoryMB
		}
		if file.Blaxel.TTL != "" {
			cfg.Blaxel.TTL = file.Blaxel.TTL
		}
		if file.Blaxel.IdleTTL != "" {
			cfg.Blaxel.IdleTTL = file.Blaxel.IdleTTL
		}
		applyOptional(&cfg.Blaxel.Workdir, file.Blaxel.Workdir)
		if file.Blaxel.ExecTimeoutSecs != nil {
			if *file.Blaxel.ExecTimeoutSecs < 0 {
				return exit(2, "blaxel execTimeoutSecs must be non-negative")
			}
			cfg.Blaxel.ExecTimeoutSecs = *file.Blaxel.ExecTimeoutSecs
		}
		applyOptional(&cfg.Blaxel.ForgetMissing, file.Blaxel.ForgetMissing)
	}
	if err := cfg.VercelSandbox.applyFile(file.VercelSandbox); err != nil {
		return err
	}
	if file.Superserve != nil {
		if trusted && strings.TrimSpace(file.Superserve.BaseURL) != "" {
			cfg.Superserve.BaseURL = file.Superserve.BaseURL
		}
		applyOptional(&cfg.Superserve.Template, file.Superserve.Template)
		applyOptional(&cfg.Superserve.Snapshot, file.Superserve.Snapshot)
		applyOptional(&cfg.Superserve.Workdir, file.Superserve.Workdir)
		if file.Superserve.TimeoutSecs != nil {
			if *file.Superserve.TimeoutSecs < 0 {
				return exit(2, "superserve timeoutSecs must be non-negative")
			}
			cfg.Superserve.TimeoutSecs = *file.Superserve.TimeoutSecs
		}
		if file.Superserve.ExecTimeoutSecs != nil {
			if *file.Superserve.ExecTimeoutSecs < 0 {
				return exit(2, "superserve execTimeoutSecs must be non-negative")
			}
			cfg.Superserve.ExecTimeoutSecs = *file.Superserve.ExecTimeoutSecs
		}
		if file.Superserve.NetworkAllowOut != nil {
			cfg.Superserve.NetworkAllowOut = normalizeList(file.Superserve.NetworkAllowOut)
		}
		if file.Superserve.NetworkDenyOut != nil {
			cfg.Superserve.NetworkDenyOut = normalizeList(file.Superserve.NetworkDenyOut)
		}
		applyOptional(&cfg.Superserve.ForgetMissing, file.Superserve.ForgetMissing)
	}
	if file.Crownest != nil {
		if trusted && strings.TrimSpace(file.Crownest.APIURL) != "" {
			cfg.Crownest.APIURL = file.Crownest.APIURL
		}
		applyOptional(&cfg.Crownest.ProjectID, file.Crownest.ProjectID)
		applyOptional(&cfg.Crownest.Template, file.Crownest.Template)
		if file.Crownest.TimeoutSecs != nil {
			if *file.Crownest.TimeoutSecs < 0 {
				return exit(2, "crownest timeoutSecs must be non-negative")
			}
			cfg.Crownest.TimeoutSecs = *file.Crownest.TimeoutSecs
		}
		applyOptional(&cfg.Crownest.ForgetMissing, file.Crownest.ForgetMissing)
	}
	if file.DockerSandbox != nil {
		if file.DockerSandbox.CLIPath != "" {
			cfg.DockerSandbox.CLIPath = file.DockerSandbox.CLIPath
		}
		if file.DockerSandbox.Agent != "" {
			cfg.DockerSandbox.Agent = file.DockerSandbox.Agent
		}
		applyOptional(&cfg.DockerSandbox.Template, file.DockerSandbox.Template)
		if file.DockerSandbox.CPUs != nil {
			if *file.DockerSandbox.CPUs < 0 {
				return exit(2, "docker-sandbox cpus must be non-negative")
			}
			cfg.DockerSandbox.CPUs = *file.DockerSandbox.CPUs
		}
		applyOptional(&cfg.DockerSandbox.Memory, file.DockerSandbox.Memory)
		applyOptional(&cfg.DockerSandbox.Clone, file.DockerSandbox.Clone)
		applyOptional(&cfg.DockerSandbox.Workdir, file.DockerSandbox.Workdir)
		if file.DockerSandbox.ExtraWorkspaces != nil {
			cfg.DockerSandbox.ExtraWorkspaces = append([]string(nil), (*file.DockerSandbox.ExtraWorkspaces)...)
		}
		if file.DockerSandbox.MCP != nil {
			cfg.DockerSandbox.MCP = append([]string(nil), (*file.DockerSandbox.MCP)...)
		}
		if file.DockerSandbox.Kit != nil {
			cfg.DockerSandbox.Kit = append([]string(nil), (*file.DockerSandbox.Kit)...)
		}
	}
	if file.AnthropicSRT != nil {
		if file.AnthropicSRT.CLIPath != "" {
			cfg.AnthropicSRT.CLIPath = file.AnthropicSRT.CLIPath
		}
		applyOptional(&cfg.AnthropicSRT.Settings, file.AnthropicSRT.Settings)
		applyOptional(&cfg.AnthropicSRT.Debug, file.AnthropicSRT.Debug)
	}
	if file.CloudRunSandbox != nil {
		if file.CloudRunSandbox.CLIPath != "" {
			cfg.CloudRunSandbox.CLIPath = file.CloudRunSandbox.CLIPath
		}
		if file.CloudRunSandbox.Workdir != "" {
			cfg.CloudRunSandbox.Workdir = file.CloudRunSandbox.Workdir
		}
		applyOptional(&cfg.CloudRunSandbox.AllowEgress, file.CloudRunSandbox.AllowEgress)
		applyOptional(&cfg.CloudRunSandbox.Write, file.CloudRunSandbox.Write)
		if file.CloudRunSandbox.Rootfs != "" {
			cfg.CloudRunSandbox.Rootfs = file.CloudRunSandbox.Rootfs
		}
	}
	if file.Modal != nil {
		if file.Modal.App != "" {
			cfg.Modal.App = file.Modal.App
		}
		if file.Modal.Image != "" {
			cfg.Modal.Image = file.Modal.Image
		}
		if file.Modal.Workdir != "" {
			cfg.Modal.Workdir = file.Modal.Workdir
		}
		if file.Modal.Python != "" {
			cfg.Modal.Python = file.Modal.Python
		}
		if trusted && file.Modal.Environment != "" {
			cfg.Modal.Environment = file.Modal.Environment
		}
		if trusted && file.Modal.Secrets != nil {
			cfg.Modal.Secrets = append([]string(nil), file.Modal.Secrets...)
		}
	}
	if file.UpstashBox != nil {
		if file.UpstashBox.BaseURL != "" {
			cfg.UpstashBox.BaseURL = file.UpstashBox.BaseURL
			cfg.credentialProvenance.upstashBoxBaseURL = credentialSource
		}
		if file.UpstashBox.Runtime != "" {
			cfg.UpstashBox.Runtime = file.UpstashBox.Runtime
		}
		if file.UpstashBox.Size != "" {
			cfg.UpstashBox.Size = file.UpstashBox.Size
		}
		if file.UpstashBox.Workdir != "" {
			cfg.UpstashBox.Workdir = file.UpstashBox.Workdir
		}
		applyOptional(&cfg.UpstashBox.KeepAlive, file.UpstashBox.KeepAlive)
	}
	if file.Smolvm != nil {
		if file.Smolvm.BaseURL != "" {
			cfg.Smolvm.BaseURL = file.Smolvm.BaseURL
			cfg.credentialProvenance.smolvmBaseURL = credentialSource
		}
		if file.Smolvm.Image != "" {
			cfg.Smolvm.Image = file.Smolvm.Image
		}
		if file.Smolvm.Workdir != "" {
			cfg.Smolvm.Workdir = file.Smolvm.Workdir
		}
		if file.Smolvm.CPUs > 0 {
			cfg.Smolvm.CPUs = file.Smolvm.CPUs
		}
		if file.Smolvm.MemoryMB > 0 {
			cfg.Smolvm.MemoryMB = file.Smolvm.MemoryMB
		}
		if file.Smolvm.Network != "" {
			cfg.Smolvm.Network = file.Smolvm.Network
		}
		applyOptional(&cfg.Smolvm.Keep, file.Smolvm.Keep)
	}
	if file.AsciiBox != nil {
		if file.AsciiBox.BaseURL != "" {
			cfg.AsciiBox.BaseURL = file.AsciiBox.BaseURL
			cfg.credentialProvenance.asciiBoxBaseURL = credentialSource
		}
		if file.AsciiBox.CLIPath != "" {
			cfg.AsciiBox.CLIPath = file.AsciiBox.CLIPath
		}
		if file.AsciiBox.Workdir != "" {
			cfg.AsciiBox.Workdir = file.AsciiBox.Workdir
		}
	}
	applyCloudflareFileConfig(cfg, file.Cloudflare, credentialSource)
	if err := applyCloudflareSandboxFileConfig(cfg, file.CloudflareSandbox, trusted); err != nil {
		return err
	}
	applyCloudflareDynamicWorkersFileConfig(cfg, file.CloudflareDynamicWorkers, trusted)
	if file.Semaphore != nil {
		if file.Semaphore.Host != "" {
			cfg.Semaphore.Host = file.Semaphore.Host
			cfg.credentialProvenance.semaphoreHost = credentialSource
		}
		if file.Semaphore.Token != "" {
			cfg.Semaphore.Token = file.Semaphore.Token
			cfg.credentialProvenance.semaphoreToken = credentialSource
		}
		if file.Semaphore.Project != "" {
			cfg.Semaphore.Project = file.Semaphore.Project
		}
		if file.Semaphore.Machine != "" {
			cfg.Semaphore.Machine = file.Semaphore.Machine
		}
		if file.Semaphore.OSImage != "" {
			cfg.Semaphore.OSImage = file.Semaphore.OSImage
		}
		if file.Semaphore.IdleTimeout != "" {
			cfg.Semaphore.IdleTimeout = file.Semaphore.IdleTimeout
		}
	}
	if file.Sprites != nil {
		if file.Sprites.APIURL != "" {
			cfg.Sprites.APIURL = file.Sprites.APIURL
			cfg.credentialProvenance.spritesAPIURL = credentialSource
		}
		if file.Sprites.WorkRoot != "" {
			cfg.Sprites.WorkRoot = file.Sprites.WorkRoot
		}
	}
	if file.LocalContainer != nil {
		if file.LocalContainer.Runtime != "" {
			cfg.LocalContainer.Runtime = file.LocalContainer.Runtime
			cfg.localContainerRuntimeExplicit = true
		}
		if file.LocalContainer.Image != "" {
			cfg.LocalContainer.Image = file.LocalContainer.Image
			cfg.localContainerImageExplicit = true
		}
		if file.LocalContainer.User != "" {
			cfg.LocalContainer.User = file.LocalContainer.User
		}
		if file.LocalContainer.WorkRoot != "" {
			cfg.LocalContainer.WorkRoot = file.LocalContainer.WorkRoot
			cfg.localContainerRootExplicit = true
		}
		if file.LocalContainer.CPUs > 0 {
			cfg.LocalContainer.CPUs = file.LocalContainer.CPUs
		}
		if file.LocalContainer.Memory != "" {
			cfg.LocalContainer.Memory = file.LocalContainer.Memory
		}
		if file.LocalContainer.Network != "" {
			cfg.LocalContainer.Network = file.LocalContainer.Network
		}
		applyOptional(&cfg.LocalContainer.DockerSocket, file.LocalContainer.DockerSocket)
		// NOTE: localContainer.volumes is intentionally NOT loaded from
		// repo-local config files. Bind mounts expose host paths and must
		// be an explicit CLI action (--local-container-volume), not
		// something an untrusted checkout can request via .crabbox.yaml.
	}
	if file.AppleContainer != nil {
		if file.AppleContainer.CLIPath != "" {
			cfg.AppleContainer.CLIPath = file.AppleContainer.CLIPath
		}
		if file.AppleContainer.Image != "" {
			cfg.AppleContainer.Image = file.AppleContainer.Image
			cfg.appleContainerImageExplicit = true
		}
		if file.AppleContainer.User != "" {
			cfg.AppleContainer.User = file.AppleContainer.User
		}
		if file.AppleContainer.WorkRoot != "" {
			cfg.AppleContainer.WorkRoot = file.AppleContainer.WorkRoot
		}
		if file.AppleContainer.CPUs > 0 {
			cfg.AppleContainer.CPUs = file.AppleContainer.CPUs
		}
		if file.AppleContainer.Memory != "" {
			cfg.AppleContainer.Memory = file.AppleContainer.Memory
		}
		if len(file.AppleContainer.ExtraRunArgs) > 0 {
			cfg.AppleContainer.ExtraRunArgs = append([]string(nil), file.AppleContainer.ExtraRunArgs...)
		}
	}
	if file.AppleVM == nil {
		// Deprecated pre-rename key; appleVM wins when both are present.
		file.AppleVM = file.AppleVZLegacy
	}
	if file.AppleVM != nil {
		if file.AppleVM.HelperPath != "" {
			cfg.AppleVM.HelperPath = file.AppleVM.HelperPath
		}
		if file.AppleVM.Image != "" {
			cfg.AppleVM.Image = file.AppleVM.Image
			cfg.AppleVM.ImageSHA256 = ""
			cfg.appleVMImageExplicit = true
			cfg.appleVMImageSHA256Explicit = false
		}
		if file.AppleVM.ImageSHA256 != "" {
			cfg.AppleVM.ImageSHA256 = file.AppleVM.ImageSHA256
			cfg.appleVMImageSHA256Explicit = true
		}
		if file.AppleVM.User != "" {
			cfg.AppleVM.User = file.AppleVM.User
		}
		if file.AppleVM.WorkRoot != "" {
			cfg.AppleVM.WorkRoot = file.AppleVM.WorkRoot
		}
		if file.AppleVM.CPUs != nil {
			cfg.AppleVM.CPUs = *file.AppleVM.CPUs
			cfg.appleVMCPUsExplicit = true
		}
		if file.AppleVM.MemoryMiB != nil {
			cfg.AppleVM.MemoryMiB = *file.AppleVM.MemoryMiB
			cfg.appleVMMemoryExplicit = true
		}
		if file.AppleVM.DiskGiB != nil {
			cfg.AppleVM.DiskGiB = *file.AppleVM.DiskGiB
			cfg.appleVMDiskExplicit = true
		}
	}
	if file.MXC != nil {
		if file.MXC.CLIPath != "" {
			cfg.MXC.CLIPath = file.MXC.CLIPath
		}
		if file.MXC.Version != "" {
			cfg.MXC.Version = file.MXC.Version
		}
		if file.MXC.Containment != "" {
			cfg.MXC.Containment = file.MXC.Containment
		}
		if file.MXC.Network != "" {
			cfg.MXC.Network = file.MXC.Network
		}
		if file.MXC.ReadOnlyPaths != nil {
			cfg.MXC.ReadOnlyPaths = append([]string(nil), file.MXC.ReadOnlyPaths...)
		}
		if file.MXC.ReadWritePaths != nil {
			cfg.MXC.ReadWritePaths = append([]string(nil), file.MXC.ReadWritePaths...)
		}
		if file.MXC.AllowedHosts != nil {
			cfg.MXC.AllowedHosts = append([]string(nil), file.MXC.AllowedHosts...)
		}
		if file.MXC.BlockedHosts != nil {
			cfg.MXC.BlockedHosts = append([]string(nil), file.MXC.BlockedHosts...)
		}
		applyOptional(&cfg.MXC.AllowDACLMutation, file.MXC.AllowDACLMutation)
		applyOptional(&cfg.MXC.AllowWindowsUI, file.MXC.AllowWindowsUI)
		applyOptional(&cfg.MXC.Experimental, file.MXC.Experimental)
	}
	if file.Multipass != nil {
		if file.Multipass.CLIPath != "" {
			cfg.Multipass.CLIPath = file.Multipass.CLIPath
		}
		if file.Multipass.Image != "" {
			cfg.Multipass.Image = file.Multipass.Image
			cfg.multipassImageExplicit = true
		}
		if file.Multipass.User != "" {
			cfg.Multipass.User = file.Multipass.User
		}
		if file.Multipass.WorkRoot != "" {
			cfg.Multipass.WorkRoot = file.Multipass.WorkRoot
		}
		if file.Multipass.CPUs > 0 {
			cfg.Multipass.CPUs = file.Multipass.CPUs
		}
		if file.Multipass.Memory != "" {
			cfg.Multipass.Memory = file.Multipass.Memory
		}
		if file.Multipass.Disk != "" {
			cfg.Multipass.Disk = file.Multipass.Disk
		}
		if file.Multipass.LaunchTimeout != "" {
			applyLeaseDuration(&cfg.Multipass.LaunchTimeout, file.Multipass.LaunchTimeout)
		}
	}
	if file.Machine0 != nil {
		if file.Machine0.CLIPath != "" {
			cfg.Machine0.CLIPath = file.Machine0.CLIPath
		}
		if file.Machine0.Image != "" {
			cfg.Machine0.Image = file.Machine0.Image
		}
		applyOptional(&cfg.Machine0.ImageVersion, file.Machine0.ImageVersion)
		if file.Machine0.DesktopImage != "" {
			cfg.Machine0.DesktopImage = file.Machine0.DesktopImage
		}
		if file.Machine0.Size != "" {
			cfg.Machine0.Size = file.Machine0.Size
			cfg.Machine0.SizeExplicit = true
		}
		if file.Machine0.Region != "" {
			cfg.Machine0.Region = file.Machine0.Region
		}
		if file.Machine0.Key != "" {
			cfg.Machine0.Key = file.Machine0.Key
		}
		if file.Machine0.WorkRoot != "" {
			cfg.Machine0.WorkRoot = file.Machine0.WorkRoot
		}
		if file.Machine0.ReleasePolicy != "" {
			cfg.Machine0.ReleasePolicy = file.Machine0.ReleasePolicy
		}
		if file.Machine0.CreateTimeout != "" {
			applyLeaseDuration(&cfg.Machine0.CreateTimeout, file.Machine0.CreateTimeout)
		}
		if file.Machine0.PollInterval != "" {
			applyLeaseDuration(&cfg.Machine0.PollInterval, file.Machine0.PollInterval)
		}
	}
	if file.Tart != nil {
		if file.Tart.Image != "" {
			cfg.Tart.Image = file.Tart.Image
			cfg.tartImageExplicit = true
		}
		if file.Tart.User != "" {
			cfg.Tart.User = file.Tart.User
		}
		if file.Tart.Password != "" {
			cfg.Tart.Password = file.Tart.Password
		}
		if file.Tart.WorkRoot != "" {
			cfg.Tart.WorkRoot = file.Tart.WorkRoot
		}
		if file.Tart.CPUs != nil {
			cfg.Tart.CPUs = *file.Tart.CPUs
			cfg.tartCPUsExplicit = true
		}
		if file.Tart.Memory != nil {
			cfg.Tart.Memory = *file.Tart.Memory
			cfg.tartMemoryExplicit = true
		}
		if file.Tart.Disk != nil {
			cfg.Tart.Disk = *file.Tart.Disk
			cfg.tartDiskExplicit = true
		}
	}
	if file.Lume != nil {
		if trusted {
			if file.Lume.CLIPath != "" {
				cfg.Lume.CLIPath = file.Lume.CLIPath
			}
			if file.Lume.Base != "" {
				cfg.Lume.Base = file.Lume.Base
			}
			if file.Lume.Storage != "" {
				cfg.Lume.Storage = file.Lume.Storage
			}
			if file.Lume.User != "" {
				cfg.Lume.User = file.Lume.User
			}
		}
		if file.Lume.WorkRoot != "" {
			cfg.Lume.WorkRoot = file.Lume.WorkRoot
		}
	}
	if file.HyperV != nil {
		if file.HyperV.Image != "" {
			cfg.HyperV.Image = file.HyperV.Image
		}
		if file.HyperV.User != "" {
			cfg.HyperV.User = file.HyperV.User
		}
		if file.HyperV.WorkRoot != "" {
			cfg.HyperV.WorkRoot = file.HyperV.WorkRoot
		}
		if file.HyperV.CPUs > 0 {
			cfg.HyperV.CPUs = file.HyperV.CPUs
		}
		if file.HyperV.Memory > 0 {
			cfg.HyperV.Memory = file.HyperV.Memory
		}
		if file.HyperV.Switch != "" {
			cfg.HyperV.Switch = file.HyperV.Switch
		}
		if file.HyperV.GuestPassword != "" {
			cfg.HyperV.GuestPassword = file.HyperV.GuestPassword
		}
		applyOptional(&cfg.HyperV.InitPassword, file.HyperV.InitPassword)
	}
	if file.WindowsSandbox != nil {
		if file.WindowsSandbox.Workdir != "" {
			cfg.WindowsSandbox.Workdir = file.WindowsSandbox.Workdir
		}
		if trusted {
			if file.WindowsSandbox.TempRoot != "" {
				cfg.WindowsSandbox.TempRoot = expandUserPath(file.WindowsSandbox.TempRoot)
			}
			if file.WindowsSandbox.Networking != "" {
				cfg.WindowsSandbox.Networking = file.WindowsSandbox.Networking
			}
			if file.WindowsSandbox.VGPU != "" {
				cfg.WindowsSandbox.VGPU = file.WindowsSandbox.VGPU
			}
			if file.WindowsSandbox.Clipboard != "" {
				cfg.WindowsSandbox.Clipboard = file.WindowsSandbox.Clipboard
			}
			if file.WindowsSandbox.ProtectedClient != "" {
				cfg.WindowsSandbox.ProtectedClient = file.WindowsSandbox.ProtectedClient
			}
			if file.WindowsSandbox.AudioInput != "" {
				cfg.WindowsSandbox.AudioInput = file.WindowsSandbox.AudioInput
			}
			if file.WindowsSandbox.VideoInput != "" {
				cfg.WindowsSandbox.VideoInput = file.WindowsSandbox.VideoInput
			}
			if file.WindowsSandbox.PrinterRedirection != "" {
				cfg.WindowsSandbox.PrinterRedirection = file.WindowsSandbox.PrinterRedirection
			}
			if file.WindowsSandbox.MemoryMB > 0 {
				cfg.WindowsSandbox.MemoryMB = file.WindowsSandbox.MemoryMB
			}
		}
	}
	if file.Tailscale != nil {
		applyOptional(&cfg.Tailscale.Enabled, file.Tailscale.Enabled)
		if file.Tailscale.Network != "" {
			cfg.Network = NetworkMode(strings.ToLower(strings.TrimSpace(file.Tailscale.Network)))
		}
		if len(file.Tailscale.Tags) > 0 {
			cfg.Tailscale.Tags = normalizeTailscaleTags(file.Tailscale.Tags)
		}
		if file.Tailscale.HostnameTemplate != "" {
			cfg.Tailscale.HostnameTemplate = file.Tailscale.HostnameTemplate
		}
		if file.Tailscale.AuthKeyEnv != "" {
			cfg.Tailscale.AuthKeyEnv = file.Tailscale.AuthKeyEnv
		}
		if file.Tailscale.ExitNode != "" {
			cfg.Tailscale.ExitNode = strings.TrimSpace(file.Tailscale.ExitNode)
		}
		applyOptional(&cfg.Tailscale.ExitNodeAllowLANAccess, file.Tailscale.ExitNodeAllowLANAccess)
	}
	if file.Static != nil {
		if file.Static.ID != "" {
			cfg.Static.ID = file.Static.ID
		}
		if file.Static.Name != "" {
			cfg.Static.Name = file.Static.Name
		}
		if file.Static.Host != "" {
			cfg.Static.Host = file.Static.Host
			cfg.credentialProvenance.staticHost = credentialSource
		}
		if file.Static.User != "" {
			cfg.Static.User = file.Static.User
		}
		if file.Static.Port != "" {
			cfg.Static.Port = file.Static.Port
		}
		if file.Static.WorkRoot != "" {
			cfg.Static.WorkRoot = file.Static.WorkRoot
		}
	}
	if file.Results != nil {
		if file.Results.JUnit != nil {
			cfg.Results.JUnit = appendUniqueStrings(nil, file.Results.JUnit...)
		}
		applyOptional(&cfg.Results.Auto, file.Results.Auto)
		applyOptional(&cfg.Results.FailOnFailures, file.Results.FailOnFailures)
	}
	if file.Shard != nil && file.Shard.MaxCount != nil {
		cfg.Shard.MaxCount = *file.Shard.MaxCount
	}
	if file.Cache != nil {
		applyOptional(&cfg.Cache.Pnpm, file.Cache.Pnpm)
		applyOptional(&cfg.Cache.Npm, file.Cache.Npm)
		applyOptional(&cfg.Cache.Docker, file.Cache.Docker)
		applyOptional(&cfg.Cache.Git, file.Cache.Git)
		if file.Cache.MaxGB > 0 {
			cfg.Cache.MaxGB = file.Cache.MaxGB
		}
		applyOptional(&cfg.Cache.PurgeOnRelease, file.Cache.PurgeOnRelease)
		if file.Cache.Volumes != nil {
			volumes, err := normalizeFileCacheVolumes(*file.Cache.Volumes)
			if err != nil {
				return err
			}
			cfg.Cache.Volumes = volumes
		}
	}
	if len(file.Presets) > 0 {
		if cfg.Presets == nil {
			cfg.Presets = map[string]PresetConfig{}
		}
		for name, preset := range file.Presets {
			name = strings.TrimSpace(name)
			if name != "" {
				cfg.Presets[name] = applyFilePresetConfig(cfg.Presets[name], preset)
			}
		}
	}
	if len(file.ProofTemplates) > 0 {
		if cfg.ProofTemplates == nil {
			cfg.ProofTemplates = map[string]ProofTemplateConfig{}
		}
		for name, tmpl := range file.ProofTemplates {
			name = strings.TrimSpace(name)
			if name != "" {
				cfg.ProofTemplates[name] = applyFileProofTemplateConfig(cfg.ProofTemplates[name], tmpl)
			}
		}
	}
	if len(file.Profiles) > 0 {
		if cfg.Profiles == nil {
			cfg.Profiles = map[string]ProfileConfig{}
		}
		for name, profile := range file.Profiles {
			name = strings.TrimSpace(name)
			if name != "" {
				cfg.Profiles[name] = applyFileProfileConfig(cfg.Profiles[name], profile)
			}
		}
	}
	if len(file.Jobs) > 0 {
		if cfg.Jobs == nil {
			cfg.Jobs = map[string]JobConfig{}
		}
		for name, job := range file.Jobs {
			name = strings.TrimSpace(name)
			if name == "" {
				continue
			}
			cfg.Jobs[name] = applyFileJobConfig(cfg.Jobs[name], job)
		}
	}
	return nil
}

func applyFileProfileConfig(profile ProfileConfig, file fileProfileConfig) ProfileConfig {
	if len(file.Env.Values) > 0 {
		if profile.Env == nil {
			profile.Env = map[string]string{}
		}
		for key, value := range file.Env.Values {
			key = strings.TrimSpace(key)
			if key != "" {
				profile.Env[key] = value
			}
		}
	}
	if len(file.Env.Allow) > 0 {
		profile.EnvAllow = appendUniqueStrings(profile.EnvAllow, file.Env.Allow...)
	}
	if len(file.EnvAllow) > 0 {
		profile.EnvAllow = appendUniqueStrings(profile.EnvAllow, file.EnvAllow...)
	}
	if len(file.ArtifactGlobs) > 0 {
		profile.ArtifactGlobs = appendUniqueStrings(nil, file.ArtifactGlobs...)
	}
	if file.Doctor != nil {
		profile.Doctor = applyFileDoctorProfileConfig(profile.Doctor, *file.Doctor)
	}
	if len(file.Presets) > 0 {
		if profile.Presets == nil {
			profile.Presets = map[string]PresetConfig{}
		}
		for name, preset := range file.Presets {
			name = strings.TrimSpace(name)
			if name != "" {
				profile.Presets[name] = applyFilePresetConfig(profile.Presets[name], preset)
			}
		}
	}
	if len(file.ProofTemplates) > 0 {
		if profile.ProofTemplates == nil {
			profile.ProofTemplates = map[string]ProofTemplateConfig{}
		}
		for name, tmpl := range file.ProofTemplates {
			name = strings.TrimSpace(name)
			if name != "" {
				profile.ProofTemplates[name] = applyFileProofTemplateConfig(profile.ProofTemplates[name], tmpl)
			}
		}
	}
	return profile
}

func applyFileDoctorProfileConfig(doctor DoctorProfileConfig, file fileDoctorProfileConfig) DoctorProfileConfig {
	applyOptional(&doctor.Enabled, file.Enabled)
	if len(file.Tools) > 0 {
		doctor.Tools = normalizePreflightToolNames(file.Tools)
	}
	if file.NodeMajor > 0 {
		doctor.NodeMajor = file.NodeMajor
	}
	if file.MinDiskGB > 0 {
		doctor.MinDiskGB = file.MinDiskGB
	}
	applyOptional(&doctor.RequireDocker, file.RequireDocker)
	applyOptional(&doctor.RequireCompose, file.RequireCompose)
	return doctor
}

func applyFilePresetConfig(preset PresetConfig, file filePresetConfig) PresetConfig {
	if file.Command != "" {
		preset.Command = file.Command
	}
	applyOptional(&preset.Shell, file.Shell)
	if len(file.Env) > 0 {
		if preset.Env == nil {
			preset.Env = map[string]string{}
		}
		for key, value := range file.Env {
			key = strings.TrimSpace(key)
			if key != "" {
				preset.Env[key] = value
			}
		}
	}
	applyOptional(&preset.Preflight, file.Preflight)
	if len(file.ArtifactGlobs) > 0 {
		preset.ArtifactGlobs = appendUniqueStrings(nil, file.ArtifactGlobs...)
	}
	if file.ProofTemplate != "" {
		preset.ProofTemplate = file.ProofTemplate
	}
	return preset
}

func applyFileProofTemplateConfig(tmpl ProofTemplateConfig, file fileProofTemplateConfig) ProofTemplateConfig {
	if file.BehaviorAddressed != "" {
		tmpl.BehaviorAddressed = file.BehaviorAddressed
	}
	if file.RealEnvironmentTested != "" {
		tmpl.RealEnvironmentTested = file.RealEnvironmentTested
	}
	if file.ExactSteps != "" {
		tmpl.ExactSteps = file.ExactSteps
	}
	if file.ObservedResult != "" {
		tmpl.ObservedResult = file.ObservedResult
	}
	if file.NotTested != "" {
		tmpl.NotTested = file.NotTested
	}
	return tmpl
}

func applyFileJobConfig(job JobConfig, file fileJobConfig) JobConfig {
	if file.Provider != "" {
		job.Provider = file.Provider
	}
	if file.Target != "" {
		job.Target = file.Target
	}
	if file.TargetOS != "" {
		job.Target = file.TargetOS
	}
	if file.Windows != nil && file.Windows.Mode != "" {
		job.WindowsMode = file.Windows.Mode
	}
	if file.Profile != "" {
		job.Profile = file.Profile
	}
	if file.Class != "" {
		job.Class = file.Class
	}
	if file.Architecture != "" {
		job.Architecture = file.Architecture
	}
	if file.ServerType != "" {
		job.ServerType = file.ServerType
	}
	if file.Type != "" {
		job.ServerType = file.Type
	}
	if file.Capacity != nil && file.Capacity.Market != "" {
		job.Market = file.Capacity.Market
	}
	if file.Market != "" {
		job.Market = file.Market
	}
	applyLeaseDuration(&job.TTL, file.TTL)
	applyLeaseDuration(&job.IdleTimeout, file.IdleTimeout)
	if file.Desktop != nil {
		value := *file.Desktop
		job.Desktop = &value
	}
	if file.DesktopEnv != "" {
		job.DesktopEnv = file.DesktopEnv
	}
	if file.Browser != nil {
		value := *file.Browser
		job.Browser = &value
	}
	if file.Code != nil {
		value := *file.Code
		job.Code = &value
	}
	if file.Network != "" {
		job.Network = file.Network
	}
	if file.Hydrate != nil {
		applyOptional(&job.Hydrate.Actions, file.Hydrate.Actions)
		applyOptional(&job.Hydrate.GitHubRunner, file.Hydrate.GitHubRunner)
		if file.Hydrate.WaitTimeout != "" {
			if duration, err := time.ParseDuration(file.Hydrate.WaitTimeout); err == nil {
				job.Hydrate.WaitTimeout = duration
			}
		}
		if file.Hydrate.KeepAliveMinutes > 0 {
			job.Hydrate.KeepAliveMinutes = file.Hydrate.KeepAliveMinutes
		}
	}
	if file.Actions != nil {
		if file.Actions.Repo != "" {
			job.Actions.Repo = file.Actions.Repo
		}
		if file.Actions.Workflow != "" {
			job.Actions.Workflow = file.Actions.Workflow
		}
		if file.Actions.Job != "" {
			job.Actions.Job = file.Actions.Job
		}
		if file.Actions.Ref != "" {
			job.Actions.Ref = file.Actions.Ref
		}
		if len(file.Actions.Fields) > 0 {
			job.Actions.Fields = appendUniqueStrings(nil, file.Actions.Fields...)
		}
	}
	applyOptional(&job.Shell, file.Shell)
	if file.Command != "" {
		job.Command = file.Command
	}
	applyOptional(&job.NoSync, file.NoSync)
	applyOptional(&job.SyncOnly, file.SyncOnly)
	if file.Checksum != nil {
		value := *file.Checksum
		job.Checksum = &value
	}
	applyOptional(&job.ForceSyncLarge, file.ForceSyncLarge)
	if len(file.JUnit) > 0 {
		job.JUnit = appendUniqueStrings(nil, file.JUnit...)
	}
	if file.Label != "" {
		job.Label = file.Label
	}
	if len(file.ArtifactGlobs) > 0 {
		job.ArtifactGlobs = appendUniqueStrings(nil, file.ArtifactGlobs...)
	}
	if len(file.RequiredArtifacts) > 0 {
		job.RequiredArtifacts = appendUniqueStrings(nil, file.RequiredArtifacts...)
	}
	if len(file.Downloads) > 0 {
		job.Downloads = appendUniqueStrings(nil, file.Downloads...)
	}
	if file.Stop != "" {
		job.Stop = file.Stop
	}
	return job
}

func applyLeaseDuration(target *time.Duration, value string) {
	if value == "" {
		return
	}
	if parsed, err := time.ParseDuration(value); err == nil && parsed > 0 {
		*target = parsed
	}
}

func applyNonNegativeLeaseDuration(target *time.Duration, value string) bool {
	if value == "" {
		return false
	}
	parsed, err := time.ParseDuration(value)
	if err != nil || parsed < 0 {
		return false
	}
	*target = parsed
	return true
}

// appleVMEnv reads a CRABBOX_APPLE_VM_* variable, falling back to the
// deprecated CRABBOX_APPLE_VZ_* spelling from before the provider rename.

// appleVMEnv reads a CRABBOX_APPLE_VM_* variable, falling back to the
// deprecated CRABBOX_APPLE_VZ_* spelling from before the provider rename.
func appleVMEnv(name string) string {
	if value := os.Getenv("CRABBOX_APPLE_VM_" + name); value != "" {
		return value
	}
	return os.Getenv("CRABBOX_APPLE_VZ_" + name)
}

func applyFileParallelsTemplateConfig(template ParallelsTemplateConfig, file fileParallelsTemplateConfig) ParallelsTemplateConfig {
	if file.Source != "" {
		template.Source = file.Source
	}
	if file.SourceID != "" {
		template.SourceID = file.SourceID
	}
	if file.SourceSnapshot != "" {
		template.SourceSnapshot = file.SourceSnapshot
	}
	if file.SourceSnapshotID != "" {
		template.SourceSnapshotID = file.SourceSnapshotID
	}
	if file.Target != "" {
		template.TargetOS = file.Target
	}
	if file.TargetOS != "" {
		template.TargetOS = file.TargetOS
	}
	if file.WindowsMode != "" {
		template.WindowsMode = file.WindowsMode
	}
	if file.CloneMode != "" {
		template.CloneMode = file.CloneMode
	}
	if file.Host != "" {
		template.Host = file.Host
	}
	if file.HostUser != "" {
		template.HostUser = file.HostUser
	}
	if file.HostKey != "" {
		template.HostKey = expandUserPath(file.HostKey)
	}
	if file.VMRoot != "" {
		template.VMRoot = expandUserPath(file.VMRoot)
	}
	if file.User != "" {
		template.User = file.User
	}
	if file.WorkRoot != "" {
		template.WorkRoot = file.WorkRoot
	}
	return template
}

func applyFileParallelsHostConfig(file fileParallelsHostConfig) ParallelsHostConfig {
	return ParallelsHostConfig{
		Name:    strings.TrimSpace(file.Name),
		Host:    strings.TrimSpace(file.Host),
		User:    strings.TrimSpace(file.User),
		Key:     expandUserPath(strings.TrimSpace(file.Key)),
		VMRoot:  expandUserPath(strings.TrimSpace(file.VMRoot)),
		Targets: append([]string(nil), file.Targets...),
		MaxVMs:  file.MaxVMs,
	}
}

func ApplyParallelsTemplateConfig(cfg *Config, name string) error {
	name = strings.TrimSpace(name)
	if name == "" {
		return nil
	}
	template, ok := cfg.Parallels.Templates[name]
	if !ok {
		return exit(2, "parallels template %q not found", name)
	}
	cfg.Parallels.Template = name
	if template.Source != "" {
		cfg.Parallels.Source = template.Source
		cfg.Parallels.SourceID = ""
	}
	if template.SourceID != "" {
		cfg.Parallels.SourceID = template.SourceID
	}
	if template.SourceSnapshot != "" {
		cfg.Parallels.SourceSnapshot = template.SourceSnapshot
		cfg.Parallels.SourceSnapshotID = ""
	}
	if template.SourceSnapshotID != "" {
		cfg.Parallels.SourceSnapshotID = template.SourceSnapshotID
	}
	if template.TargetOS != "" {
		cfg.TargetOS = normalizeTargetOS(template.TargetOS)
		if !IsTargetExplicit(cfg) {
			cfg.inferredTargetProvider = parallelsProvider
		}
	}
	if template.WindowsMode != "" {
		cfg.WindowsMode = template.WindowsMode
	}
	if template.CloneMode != "" {
		cfg.Parallels.CloneMode = template.CloneMode
	}
	if template.Host != "" {
		cfg.Parallels.Host = template.Host
		cfg.credentialProvenance.parallelsHost = template.hostSource
	}
	if template.HostUser != "" {
		cfg.Parallels.HostUser = template.HostUser
	}
	if template.HostKey != "" {
		cfg.Parallels.HostKey = template.HostKey
		cfg.credentialProvenance.parallelsHostKey = template.hostKeySource
	}
	if template.VMRoot != "" {
		cfg.Parallels.VMRoot = template.VMRoot
	}
	if template.User != "" {
		cfg.Parallels.User = template.User
		cfg.SSHUser = template.User
	}
	if template.WorkRoot != "" {
		cfg.Parallels.WorkRoot = template.WorkRoot
		cfg.WorkRoot = template.WorkRoot
	}
	cfg.parallelsTemplateApplied = true
	return nil
}
