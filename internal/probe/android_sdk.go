package probe

import (
	"os"
	"path/filepath"

	"devpilot/internal/security"
)

// AndroidSDKResult summarizes the Android SDK detection without exposing raw environment values.
type AndroidSDKResult struct {
	EnvSet           bool   `json:"env_set"`
	EnvName          string `json:"env_name"` // "ANDROID_HOME" or "ANDROID_SDK_ROOT"
	DirectoryExists  bool   `json:"directory_exists"`
	HasPlatformTools bool   `json:"has_platform_tools"`
	HasBuildTools    bool   `json:"has_build_tools"`
	HasPlatforms     bool   `json:"has_platforms"`
	RedactedPath     string `json:"redacted_path"`
	Error            string `json:"error,omitempty"`
}

// ProbeAndroidSDK safely inspects the Android SDK setup following Security Rule 3 (never output raw env values).
func ProbeAndroidSDK() AndroidSDKResult {
	res := AndroidSDKResult{}

	sdkPath := os.Getenv("ANDROID_HOME")
	res.EnvName = "ANDROID_HOME"
	if sdkPath != "" {
		res.EnvSet = true
	} else {
		sdkPath = os.Getenv("ANDROID_SDK_ROOT")
		if sdkPath != "" {
			res.EnvName = "ANDROID_SDK_ROOT"
			res.EnvSet = true
		}
	}

	// If neither env var is set, check standard default Android Studio location on Windows
	if sdkPath == "" {
		localApp := os.Getenv("LOCALAPPDATA")
		if localApp != "" {
			defaultLoc := filepath.Join(localApp, "Android", "Sdk")
			if info, err := os.Stat(defaultLoc); err == nil && info.IsDir() {
				sdkPath = defaultLoc
				res.EnvName = "(default Android Studio location)"
			}
		}
	}

	if sdkPath == "" {
		res.Error = "Neither ANDROID_HOME nor ANDROID_SDK_ROOT is set, and default SDK folder not found"
		return res
	}

	res.RedactedPath = security.RedactPath(sdkPath)

	info, err := os.Stat(sdkPath)
	if err != nil || !info.IsDir() {
		res.DirectoryExists = false
		res.Error = "Android SDK directory does not exist or is not a directory"
		return res
	}
	res.DirectoryExists = true

	// Check core subdirectories
	platformTools := filepath.Join(sdkPath, "platform-tools")
	if ptInfo, err := os.Stat(platformTools); err == nil && ptInfo.IsDir() {
		res.HasPlatformTools = true
	}

	buildTools := filepath.Join(sdkPath, "build-tools")
	if btInfo, err := os.Stat(buildTools); err == nil && btInfo.IsDir() {
		res.HasBuildTools = true
	}

	platforms := filepath.Join(sdkPath, "platforms")
	if pInfo, err := os.Stat(platforms); err == nil && pInfo.IsDir() {
		res.HasPlatforms = true
	}

	return res
}
