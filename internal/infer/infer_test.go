package infer

import (
	"os"
	"path/filepath"
	"testing"
)

func TestInferPackageJSON(t *testing.T) {
	tempDir := t.TempDir()
	content := `{
		"name": "sample-project",
		"engines": {
			"node": ">=20.0.0"
		}
	}`
	if err := os.WriteFile(filepath.Join(tempDir, "package.json"), []byte(content), 0644); err != nil {
		t.Fatal(err)
	}

	env, err := Infer(tempDir)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if env.NodeRange != ">=20.0.0" {
		t.Fatalf("expected node range >=20.0.0, got %s", env.NodeRange)
	}
	if env.NodeSource != "package.json (engines.node)" {
		t.Fatalf("expected source package.json, got %s", env.NodeSource)
	}
}

func TestInferReactNativeAndExpo(t *testing.T) {
	tempDir := t.TempDir()
	pkgContent := `{
		"name": "my-mobile-app",
		"dependencies": {
			"react-native": "^0.74.1",
			"expo": "^51.0.0"
		}
	}`
	if err := os.WriteFile(filepath.Join(tempDir, "package.json"), []byte(pkgContent), 0644); err != nil {
		t.Fatal(err)
	}

	appContent := `{
		"expo": {
			"name": "my-mobile-app",
			"sdkVersion": "51.0.0"
		}
	}`
	if err := os.WriteFile(filepath.Join(tempDir, "app.json"), []byte(appContent), 0644); err != nil {
		t.Fatal(err)
	}

	env, err := Infer(tempDir)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !env.IsReactNative || env.RNVersion != "0.74.1" {
		t.Errorf("expected React Native 0.74.1, got: %+v", env)
	}
	if !env.IsExpo || env.ExpoSdkVersion != "51.0.0" {
		t.Errorf("expected Expo 51.0.0, got: %+v", env)
	}
	if env.JavaRange != "17" {
		t.Errorf("expected inferred Java 17 for RN 0.74, got %s", env.JavaRange)
	}
}

func TestInferGradleWrapperAndBuild(t *testing.T) {
	tempDir := t.TempDir()
	gradleDir := filepath.Join(tempDir, "android", "gradle", "wrapper")
	if err := os.MkdirAll(gradleDir, 0755); err != nil {
		t.Fatal(err)
	}
	propContent := `distributionBase=GRADLE_USER_HOME
distributionPath=wrapper/dists
distributionUrl=https\://services.gradle.org/distributions/gradle-8.6-bin.zip
zipStoreBase=GRADLE_USER_HOME
zipStorePath=wrapper/dists
`
	if err := os.WriteFile(filepath.Join(gradleDir, "gradle-wrapper.properties"), []byte(propContent), 0644); err != nil {
		t.Fatal(err)
	}

	appDir := filepath.Join(tempDir, "android", "app")
	if err := os.MkdirAll(appDir, 0755); err != nil {
		t.Fatal(err)
	}
	buildContent := `android {
    compileSdkVersion 34
    defaultConfig {
        minSdkVersion 23
        targetSdkVersion 34
    }
}`
	if err := os.WriteFile(filepath.Join(appDir, "build.gradle"), []byte(buildContent), 0644); err != nil {
		t.Fatal(err)
	}

	env, err := Infer(tempDir)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if env.GradleVersion != "8.6" {
		t.Errorf("expected Gradle 8.6, got: %s", env.GradleVersion)
	}
	if env.CompileSDK != "34" || env.TargetSDK != "34" || env.MinSDK != "23" {
		t.Errorf("expected SDK 34/34/23, got: compile=%s, target=%s, min=%s", env.CompileSDK, env.TargetSDK, env.MinSDK)
	}
	if env.JavaRange != "17" {
		t.Errorf("expected Java 17 inferred from Gradle 8.6, got: %s", env.JavaRange)
	}
}

func TestInferToolVersionsAndCI(t *testing.T) {
	tempDir := t.TempDir()
	toolVersions := `nodejs 20.11.0
java openjdk-17.0.8
gradle 8.5
`
	if err := os.WriteFile(filepath.Join(tempDir, ".tool-versions"), []byte(toolVersions), 0644); err != nil {
		t.Fatal(err)
	}

	env, err := Infer(tempDir)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if env.NodeRange != "20.11.0" {
		t.Errorf("expected Node 20.11.0 from .tool-versions, got %s", env.NodeRange)
	}
	if env.JavaRange != "17.0.8" {
		t.Errorf("expected Java 17.0.8 from .tool-versions, got %s", env.JavaRange)
	}
	if env.GradleVersion != "8.5" {
		t.Errorf("expected Gradle 8.5 from .tool-versions, got %s", env.GradleVersion)
	}
}

func TestInferNVMRC(t *testing.T) {
	tempDir := t.TempDir()
	if err := os.WriteFile(filepath.Join(tempDir, ".nvmrc"), []byte("20.11.0\n"), 0644); err != nil {
		t.Fatal(err)
	}

	env, err := Infer(tempDir)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if env.NodeRange != "20.11.0" {
		t.Fatalf("expected 20.11.0, got %s", env.NodeRange)
	}
}

func TestReadUntrustedManifest_PathTraversal(t *testing.T) {
	tempDir := t.TempDir()
	_, err := readUntrustedManifest(tempDir, "../../../etc/passwd")
	if err == nil {
		t.Fatalf("expected path traversal error, got nil")
	}
}

func TestReadUntrustedManifest_Oversized(t *testing.T) {
	tempDir := t.TempDir()
	largeFile := filepath.Join(tempDir, "package.json")
	// Create file slightly larger than MaxManifestBytes (1MB + 10 bytes)
	data := make([]byte, MaxManifestBytes+10)
	if err := os.WriteFile(largeFile, data, 0644); err != nil {
		t.Fatal(err)
	}

	_, err := readUntrustedManifest(tempDir, "package.json")
	if err == nil {
		t.Fatalf("expected oversized manifest error, got nil")
	}
}
