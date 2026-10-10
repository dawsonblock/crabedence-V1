package cli

import (
	"strconv"
	"strings"
)

func serverTypeForConfig(cfg Config) string {
	if resolved, err := ProviderFor(cfg.Provider); err == nil {
		cfg.Provider = resolved.Name()
		if resolved.Spec().ClassDisposition == ProviderClassDispositionMapped {
			if cfg.ServerTypeExplicit && strings.TrimSpace(cfg.ServerType) != "" {
				return cfg.ServerType
			}
			if override, ok := resolved.(ProviderServerTypeOverrideProvider); ok {
				if serverType, selected := override.ServerTypeOverrideForConfig(cfg); selected {
					return serverType
				}
			}
		}
		if typer, ok := resolved.(ProviderServerTypeProvider); ok {
			return typer.ServerTypeForConfig(cfg)
		}
	}
	if isBlacksmithProvider(cfg.Provider) || isStaticProvider(cfg.Provider) || cfg.Provider == "islo" || cfg.Provider == "sprites" || cfg.Provider == "local-container" || cfg.Provider == "multipass" {
		return ""
	}
	if cfg.Provider == "e2b" {
		return blank(cfg.E2B.Template, "base")
	}
	if cfg.Provider == "exe-dev" || cfg.Provider == "exedev" || cfg.Provider == "exe" {
		return blank(cfg.ExeDev.Image, "default")
	}
	if cfg.Provider == "modal" {
		return blank(cfg.Modal.Image, "python:3.13-slim")
	}
	if cfg.Provider == "upstash-box" || cfg.Provider == "upstash" {
		return blank(cfg.UpstashBox.Size, "small")
	}
	if cfg.Provider == "daytona" {
		return "snapshot"
	}
	if cfg.Provider == "proxmox" {
		return proxmoxServerTypeForConfig(cfg)
	}
	if cfg.Provider == "firecracker" {
		return firecrackerServerTypeForConfig(cfg)
	}
	if cfg.Provider == "incus" {
		return incusServerTypeForConfig(cfg)
	}
	if cfg.Provider == "parallels" {
		return parallelsServerTypeForConfig(cfg)
	}
	return ""
}

func serverTypeForProviderClass(provider, class string) string {
	if resolved, err := ProviderFor(provider); err == nil {
		provider = resolved.Name()
		if typer, ok := resolved.(ProviderServerTypeProvider); ok {
			return typer.ServerTypeForClass(class)
		}
	}
	if isBlacksmithProvider(provider) || isStaticProvider(provider) || provider == "islo" || provider == "sprites" || provider == "local-container" || provider == "multipass" {
		return ""
	}
	if provider == "e2b" {
		return "base"
	}
	if provider == "exe-dev" {
		return "default"
	}
	if provider == "modal" {
		return "python:3.13-slim"
	}
	if provider == "daytona" {
		return "snapshot"
	}
	if provider == "proxmox" {
		return "template"
	}
	if provider == "firecracker" {
		return "microvm"
	}
	if provider == "incus" {
		return "container"
	}
	if provider == "parallels" {
		return "template"
	}
	return ""
}

func incusServerTypeForConfig(cfg Config) string {
	instanceType := strings.ToLower(strings.TrimSpace(cfg.Incus.InstanceType))
	if instanceType == "" {
		instanceType = "container"
	}
	if image := strings.TrimSpace(cfg.Incus.Image); image != "" {
		return instanceType + ":" + image
	}
	return instanceType
}

func proxmoxServerTypeForConfig(cfg Config) string {
	if cfg.Proxmox.TemplateID > 0 {
		return "template-" + strconv.Itoa(cfg.Proxmox.TemplateID)
	}
	return "template"
}

func firecrackerServerTypeForConfig(_ Config) string {
	return "microvm"
}

func parallelsServerTypeForConfig(cfg Config) string {
	source := strings.TrimSpace(firstNonBlank(cfg.Parallels.Source, cfg.Parallels.SourceID))
	if source == "" {
		if cfg.Parallels.Template != "" {
			return "template-" + normalizeLeaseSlug(cfg.Parallels.Template)
		}
		return "template"
	}
	return "template-" + normalizeLeaseSlug(source)
}

func cloudflareContainerInstanceTypes() []string {
	return []string{"lite", "basic", "standard-1", "standard-2", "standard-3", "standard-4"}
}

func CloudflareContainerInstanceTypes() []string {
	return cloudflareContainerInstanceTypes()
}

func normalizeCloudflareContainerInstanceType(value string) (string, bool) {
	trimmed := strings.ToLower(strings.TrimSpace(value))
	for _, instanceType := range cloudflareContainerInstanceTypes() {
		if trimmed == instanceType {
			return instanceType, true
		}
	}
	return "", false
}

func NormalizeCloudflareContainerInstanceType(value string) (string, bool) {
	return normalizeCloudflareContainerInstanceType(value)
}

func cloudflareContainerInstanceTypeForClass(class string) string {
	provider, err := ProviderFor("cloudflare")
	if err == nil {
		if resolver, ok := provider.(ProviderServerTypeProvider); ok {
			return resolver.ServerTypeForClass(class)
		}
	}
	return strings.TrimSpace(class)
}

func CloudflareContainerInstanceTypeForClass(class string) string {
	return cloudflareContainerInstanceTypeForClass(class)
}

func serverTypeCandidatesForClass(class string) []string {
	cfg := Config{Provider: "hetzner", TargetOS: targetLinux, Architecture: ArchitectureAMD64, Class: class, architectureExplicit: true}
	return hetznerServerTypeCandidatesForConfig(cfg)
}

func hetznerServerTypeCandidatesForConfig(cfg Config) []string {
	if cfg.ServerTypeExplicit {
		if strings.TrimSpace(cfg.ServerType) != "" {
			return []string{cfg.ServerType}
		}
	}
	serverType := concreteStoredServerType(cfg)
	if candidates, matched := providerClassCandidatesForConfig(cfg); matched {
		return appendUniqueExactStrings([]string{serverType}, candidates...)
	}
	if IsCanonicalProviderClass(cfg.Class) {
		if serverType != "" {
			return []string{serverType}
		}
		return nil
	}
	candidates := []string{cfg.Class}
	if serverType == "" || serverType == cfg.Class {
		return candidates
	}
	return append([]string{serverType}, candidates...)
}

func awsInstanceTypeCandidatesForConfig(cfg Config) []string {
	candidates, _ := awsClassCandidatesForConfig(cfg)
	return candidates
}

func awsClassCandidatesForConfig(cfg Config) ([]string, bool) {
	if candidates, matched := providerClassCandidatesForConfig(cfg); matched {
		return candidates, true
	}
	if normalizeTargetOS(cfg.TargetOS) == targetMacOS {
		standard := cfg
		standard.Class = "standard"
		if candidates, matched := providerClassCandidatesForConfig(standard); matched {
			return appendUniqueExactStrings([]string{cfg.Class}, candidates...), false
		}
	}
	if IsCanonicalProviderClass(cfg.Class) {
		if storedType := concreteStoredServerType(cfg); storedType != "" {
			return []string{storedType}, true
		}
		return nil, false
	}
	return appendUniqueExactStrings([]string{concreteStoredServerType(cfg)}, cfg.Class), false
}

func awsInstanceTypeCandidatesForTargetModeArchitectureClass(target, windowsMode, architecture, class string) []string {
	cfg := Config{Provider: "aws", TargetOS: target, WindowsMode: windowsMode, Architecture: architecture, Class: class, architectureExplicit: true}
	return awsInstanceTypeCandidatesForConfig(cfg)
}

func awsMacOSInstanceTypeCandidates() []string {
	return awsInstanceTypeCandidatesForTargetModeArchitectureClass(targetMacOS, windowsModeNormal, ArchitectureAMD64, "standard")
}

func awsInstanceTypeCandidatesForClass(class string) []string {
	return awsInstanceTypeCandidatesForTargetModeArchitectureClass(targetLinux, windowsModeNormal, ArchitectureAMD64, class)
}

func awsInstanceTypeIsARM64(instanceType string) bool {
	name := strings.ToLower(strings.SplitN(instanceType, ".", 2)[0])
	switch name {
	case "a1", "g5g", "hpc7g", "i4g", "im4gn", "is4gen", "t4g", "x2gd":
		return true
	}
	for _, prefix := range []string{"c", "m", "r"} {
		if strings.HasPrefix(name, prefix) && awsGravitonFamilySuffix(strings.TrimPrefix(name, prefix)) {
			return true
		}
	}
	return false
}

func awsGravitonFamilySuffix(value string) bool {
	digitEnd := 0
	for digitEnd < len(value) && value[digitEnd] >= '0' && value[digitEnd] <= '9' {
		digitEnd++
	}
	if digitEnd == 0 {
		return false
	}
	switch value[digitEnd:] {
	case "g", "gd", "gn":
		return true
	default:
		return false
	}
}
