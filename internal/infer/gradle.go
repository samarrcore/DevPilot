package infer

import (
	"bufio"
	"bytes"
	"regexp"
	"strings"
)

var (
	gradleDistRegex = regexp.MustCompile(`gradle-([0-9.]+)-(?:all|bin)\.zip`)
	compileSdkRegex = regexp.MustCompile(`(?i)(?:compileSdkVersion|compileSdk)\s*=?\s*["']?(\d+)`)
	minSdkRegex     = regexp.MustCompile(`(?i)(?:minSdkVersion|minSdk)\s*=?\s*["']?(\d+)`)
	targetSdkRegex  = regexp.MustCompile(`(?i)(?:targetSdkVersion|targetSdk)\s*=?\s*["']?(\d+)`)
)

// inferGradle inspects gradle wrapper properties and build.gradle for build specifications.
func inferGradle(dir string, expected *ExpectedEnv) {
	// 1. Check gradle-wrapper.properties in standard locations
	wrapperLocations := []string{
		"android/gradle/wrapper/gradle-wrapper.properties",
		"gradle/wrapper/gradle-wrapper.properties",
	}

	for _, loc := range wrapperLocations {
		if data, err := readUntrustedManifest(dir, loc); err == nil {
			scanner := bufio.NewScanner(bytes.NewReader(data))
			for scanner.Scan() {
				line := strings.TrimSpace(scanner.Text())
				if strings.HasPrefix(line, "distributionUrl") {
					matches := gradleDistRegex.FindStringSubmatch(line)
					if len(matches) >= 2 {
						expected.GradleVersion = matches[1]
						expected.GradleSource = loc
						// Gradle 8.0+ enforces JDK 17
						if strings.HasPrefix(expected.GradleVersion, "8.") && expected.JavaRange == "" {
							expected.JavaRange = "17"
							expected.JavaSource = "inferred: Gradle 8.x prerequisite"
						}
						break
					}
				}
			}
			if expected.GradleVersion != "" {
				break
			}
		}
	}

	// 2. Check build.gradle files for SDK levels
	buildGradleLocations := []string{
		"android/app/build.gradle",
		"android/build.gradle",
		"build.gradle",
	}

	for _, loc := range buildGradleLocations {
		if data, err := readUntrustedManifest(dir, loc); err == nil {
			str := string(data)
			if expected.CompileSDK == "" {
				if m := compileSdkRegex.FindStringSubmatch(str); len(m) >= 2 {
					expected.CompileSDK = m[1]
				}
			}
			if expected.MinSDK == "" {
				if m := minSdkRegex.FindStringSubmatch(str); len(m) >= 2 {
					expected.MinSDK = m[1]
				}
			}
			if expected.TargetSDK == "" {
				if m := targetSdkRegex.FindStringSubmatch(str); len(m) >= 2 {
					expected.TargetSDK = m[1]
				}
			}
		}
	}
}
