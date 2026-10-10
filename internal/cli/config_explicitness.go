package cli

import "strings"

func MarkIsloImageExplicit(cfg *Config) {
	cfg.isloImageExplicit = true
}

func MarkCapacityMarketExplicit(cfg *Config) {
	cfg.capacityMarketExplicit = true
}

func CapacityMarketExplicit(cfg Config) bool {
	return cfg.capacityMarketExplicit
}

func IsloImageExplicit(cfg Config) bool {
	return cfg.isloImageExplicit
}

func MarkIsloVCPUsExplicit(cfg *Config) {
	cfg.isloVCPUsExplicit = true
}

func IsloVCPUsExplicit(cfg Config) bool {
	return cfg.isloVCPUsExplicit
}

func MarkIsloMemoryMBExplicit(cfg *Config) {
	cfg.isloMemoryMBExplicit = true
}

func IsloMemoryMBExplicit(cfg Config) bool {
	return cfg.isloMemoryMBExplicit
}

func MarkIsloDiskGBExplicit(cfg *Config) {
	cfg.isloDiskGBExplicit = true
}

func IsloDiskGBExplicit(cfg Config) bool {
	return cfg.isloDiskGBExplicit
}

func MarkLocalContainerImageExplicit(cfg *Config) {
	cfg.localContainerImageExplicit = true
}

func MarkLocalContainerRuntimeExplicit(cfg *Config) {
	cfg.localContainerRuntimeExplicit = true
}

func LocalContainerRuntimeExplicit(cfg Config) bool {
	return cfg.localContainerRuntimeExplicit
}

func MarkLocalContainerWorkRootExplicit(cfg *Config) {
	cfg.localContainerRootExplicit = true
}

func LocalContainerWorkRootExplicit(cfg Config) bool {
	return cfg.localContainerRootExplicit
}

func MarkAppleContainerImageExplicit(cfg *Config) {
	cfg.appleContainerImageExplicit = true
}

func AppleContainerImageExplicit(cfg Config) bool {
	return cfg.appleContainerImageExplicit
}

func MarkAppleVMImageExplicit(cfg *Config) {
	cfg.appleVMImageExplicit = true
	cfg.appleVMImageSHA256Explicit = false
}

func AppleVMImageExplicit(cfg Config) bool {
	return cfg.appleVMImageExplicit
}

func MarkAppleVMImageSHA256Explicit(cfg *Config) {
	cfg.appleVMImageSHA256Explicit = true
}

func AppleVMCPUsExplicit(cfg Config) bool {
	return cfg.appleVMCPUsExplicit
}

func MarkAppleVMCPUsExplicit(cfg *Config) {
	cfg.appleVMCPUsExplicit = true
}

func AppleVMMemoryExplicit(cfg Config) bool {
	return cfg.appleVMMemoryExplicit
}

func MarkAppleVMMemoryExplicit(cfg *Config) {
	cfg.appleVMMemoryExplicit = true
}

func AppleVMDiskExplicit(cfg Config) bool {
	return cfg.appleVMDiskExplicit
}

func MarkAppleVMDiskExplicit(cfg *Config) {
	cfg.appleVMDiskExplicit = true
}

func MarkMultipassImageExplicit(cfg *Config) {
	cfg.multipassImageExplicit = true
}

func MarkTartImageExplicit(cfg *Config) {
	cfg.tartImageExplicit = true
}

func IsTartDiskExplicit(cfg *Config) bool {
	return cfg.tartDiskExplicit
}

func MarkTartDiskExplicit(cfg *Config) {
	cfg.tartDiskExplicit = true
}

func IsTartCPUsExplicit(cfg *Config) bool {
	return cfg.tartCPUsExplicit
}

func MarkTartCPUsExplicit(cfg *Config) {
	cfg.tartCPUsExplicit = true
}

func IsTartMemoryExplicit(cfg *Config) bool {
	return cfg.tartMemoryExplicit
}

func MarkTartMemoryExplicit(cfg *Config) {
	cfg.tartMemoryExplicit = true
}

func IsTargetExplicit(cfg *Config) bool {
	return cfg.targetExplicit
}

func MarkTargetExplicit(cfg *Config) {
	cfg.targetExplicit = true
	cfg.credentialProvenance.externalDesktopTarget = credentialSourceFlag
	if normalizeTargetOS(cfg.TargetOS) != targetWindows {
		cfg.WindowsMode = windowsModeNormal
		cfg.credentialProvenance.externalDesktopMode = credentialSourceFlag
	}
}

func IsSSHUserExplicit(cfg *Config) bool {
	return cfg.explicitSSHUser != ""
}

func MarkSSHUserExplicit(cfg *Config) {
	cfg.explicitSSHUser = cfg.SSHUser
}

func IsSSHKeyExplicit(cfg *Config) bool {
	return cfg != nil && cfg.SSHKey != "" && (cfg.explicitSSHKey != "" || cfg.SSHKey != baseConfig().SSHKey)
}

func MarkSSHKeyExplicit(cfg *Config) {
	cfg.explicitSSHKey = cfg.SSHKey
}

func IsSSHPortExplicit(cfg *Config) bool {
	return cfg.explicitSSHPort != ""
}

func MarkSSHPortExplicit(cfg *Config) {
	cfg.explicitSSHPort = cfg.SSHPort
}

func IsWorkRootExplicit(cfg *Config) bool {
	return cfg.explicitWorkRoot != ""
}

func MarkWorkRootExplicit(cfg *Config) {
	cfg.explicitWorkRoot = cfg.WorkRoot
}

func IsBoxdWorkRootExplicit(cfg *Config) bool {
	return cfg.boxdWorkRootExplicit
}

func MarkBoxdWorkRootExplicit(cfg *Config) {
	cfg.boxdWorkRootExplicit = true
}

func IsSealosDevboxWorkRootExplicit(cfg *Config) bool {
	return cfg != nil && cfg.sealosDevboxWorkRootExplicit
}

func MarkSealosDevboxWorkRootExplicit(cfg *Config) {
	cfg.sealosDevboxWorkRootExplicit = true
}

func EffectiveSealosDevboxWorkRoot(cfg Config) string {
	if IsSealosDevboxWorkRootExplicit(&cfg) {
		return Blank(strings.TrimSpace(cfg.SealosDevbox.WorkRoot), baseConfig().SealosDevbox.WorkRoot)
	}
	if IsWorkRootExplicit(&cfg) {
		return strings.TrimSpace(cfg.WorkRoot)
	}
	return Blank(strings.TrimSpace(cfg.SealosDevbox.WorkRoot), baseConfig().SealosDevbox.WorkRoot)
}

func IsHostingerWorkRootExplicit(cfg *Config) bool {
	return cfg.hostingerWorkRootExplicit
}

func IsHostingerUserExplicit(cfg *Config) bool {
	return cfg.hostingerUserExplicit
}

func MarkHostingerUserExplicit(cfg *Config) {
	cfg.hostingerUserExplicit = true
}

func MarkHostingerWorkRootExplicit(cfg *Config) {
	cfg.hostingerWorkRootExplicit = true
}

func IsNvidiaBrevWorkRootExplicit(cfg *Config) bool {
	return cfg.nvidiaBrevWorkRootExplicit
}

func MarkNvidiaBrevWorkRootExplicit(cfg *Config) {
	cfg.nvidiaBrevWorkRootExplicit = true
}

func IsVastWorkRootExplicit(cfg *Config) bool {
	return cfg.vastWorkRootExplicit
}

func MarkVastWorkRootExplicit(cfg *Config) {
	cfg.vastWorkRootExplicit = true
}

func EffectiveVastWorkRoot(cfg Config) string {
	workRoot := cfg.Vast.WorkRoot
	if !IsVastWorkRootExplicit(&cfg) && (workRoot == "" || workRoot == defaultPOSIXWorkRoot) && cfg.explicitWorkRoot != "" {
		return cfg.explicitWorkRoot
	}
	if workRoot == "" {
		return defaultPOSIXWorkRoot
	}
	return workRoot
}

func NormalizeVastInstanceType(value string) string {
	return normalizeVastInstanceType(value)
}

func normalizeVastInstanceType(value string) string {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "on-demand", "on_demand":
		return "ondemand"
	default:
		return strings.ToLower(strings.TrimSpace(value))
	}
}

func EffectiveNvidiaBrevWorkRoot(cfg Config) string {
	workRoot := cfg.NvidiaBrev.WorkRoot
	providerDefault := workRoot == "" || workRoot == "/tmp/crabbox"
	if !IsNvidiaBrevWorkRootExplicit(&cfg) && providerDefault && cfg.explicitWorkRoot != "" {
		return cfg.explicitWorkRoot
	}
	if workRoot == "" {
		return "/tmp/crabbox"
	}
	return workRoot
}

func DeleteOnReleaseExplicit(cfg Config, provider string) bool {
	return cfg.deleteOnReleaseExplicit[normalizeProviderName(provider)]
}

func MarkDeleteOnReleaseExplicit(cfg *Config, provider string) {
	if cfg.deleteOnReleaseExplicit == nil {
		cfg.deleteOnReleaseExplicit = map[string]bool{}
	}
	cfg.deleteOnReleaseExplicit[normalizeProviderName(provider)] = true
}

func GitHubCodespacesRetentionExplicit(cfg Config) bool {
	return cfg.githubCodespacesRetentionSet
}

func MarkGitHubCodespacesRetentionExplicit(cfg *Config) {
	cfg.githubCodespacesRetentionSet = true
}

func EffectiveHostingerWorkRoot(cfg Config) string {
	if cfg.Hostinger.WorkRoot != "" {
		return cfg.Hostinger.WorkRoot
	}
	if cfg.explicitWorkRoot != "" {
		return cfg.explicitWorkRoot
	}
	user := strings.TrimSpace(cfg.Hostinger.User)
	if user == "" {
		user = "root"
	}
	return "/home/" + user + "/crabbox"
}
