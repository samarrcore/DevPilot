package infer

import (
	"encoding/json"
	"strings"
)

type appManifestJSON struct {
	Expo struct {
		Name       string `json:"name"`
		SdkVersion string `json:"sdkVersion"`
	} `json:"expo"`
}

// inferReactNative checks package.json and app.json for React Native and Expo markers.
func inferReactNative(dir string, pkg *packageJSON, expected *ExpectedEnv) {
	if pkg == nil {
		return
	}

	// 1. Check dependencies for React Native
	if rnVer, ok := pkg.Dependencies["react-native"]; ok {
		expected.IsReactNative = true
		expected.RNVersion = strings.TrimPrefix(rnVer, "^")
		expected.FrameworkSource = "package.json (dependencies.react-native)"
	} else if rnDev, ok := pkg.DevDependencies["react-native"]; ok {
		expected.IsReactNative = true
		expected.RNVersion = strings.TrimPrefix(rnDev, "^")
		expected.FrameworkSource = "package.json (devDependencies.react-native)"
	}

	// 2. Check dependencies for Expo
	if expoVer, ok := pkg.Dependencies["expo"]; ok {
		expected.IsExpo = true
		expected.ExpoSdkVersion = strings.TrimPrefix(expoVer, "^")
		expected.FrameworkSource = "package.json (dependencies.expo)"
	}

	// 3. Check app.json
	if data, err := readUntrustedManifest(dir, "app.json"); err == nil {
		var app appManifestJSON
		if err := json.Unmarshal(data, &app); err == nil && app.Expo.SdkVersion != "" {
			expected.IsExpo = true
			expected.ExpoSdkVersion = app.Expo.SdkVersion
			expected.FrameworkSource = "app.json (expo.sdkVersion)"
		}
	}

	// 4. Inferred JDK requirement from React Native / Expo ecosystem
	if expected.IsReactNative || expected.IsExpo {
		// React Native >= 0.73 or Expo >= 50 requires JDK 17
		if strings.HasPrefix(expected.RNVersion, "0.7") || strings.HasPrefix(expected.RNVersion, "0.8") || strings.HasPrefix(expected.ExpoSdkVersion, "5") {
			if expected.JavaRange == "" {
				expected.JavaRange = "17"
				expected.JavaSource = "inferred: React Native 0.73+ / Expo SDK 50+ target"
			}
		} else if strings.HasPrefix(expected.RNVersion, "0.6") {
			// Legacy React Native 0.6x requires JDK 11
			if expected.JavaRange == "" {
				expected.JavaRange = "11"
				expected.JavaSource = "inferred: legacy React Native 0.6x target"
			}
		} else if expected.JavaRange == "" {
			// Default modern RN recommendation
			expected.JavaRange = "17"
			expected.JavaSource = "inferred: standard React Native requirement"
		}
	}
}
