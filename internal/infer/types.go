package infer

// ExpectedEnv holds expectations inferred deterministically from repository manifests.
type ExpectedEnv struct {
	// Project identity
	ProjectName string `json:"project_name,omitempty"`

	// Node runtime
	NodeRange  string `json:"node_range,omitempty"`  // e.g. ">=18.0.0", "^20.0.0", "20.11.0"
	NodeSource string `json:"node_source,omitempty"` // e.g. "package.json (engines.node)", ".nvmrc"

	// Framework detection
	IsReactNative  bool   `json:"is_react_native"`
	RNVersion      string `json:"rn_version,omitempty"`
	IsExpo         bool   `json:"is_expo"`
	ExpoSdkVersion string `json:"expo_sdk_version,omitempty"`
	FrameworkSource string `json:"framework_source,omitempty"`

	// Java / JDK requirements
	JavaRange  string `json:"java_range,omitempty"`  // e.g. "17", "11", "21"
	JavaSource string `json:"java_source,omitempty"` // e.g. "React Native 0.74 recommendation", ".tool-versions"

	// Gradle & Android build specs
	GradleVersion string `json:"gradle_version,omitempty"` // e.g. "8.6"
	GradleSource  string `json:"gradle_source,omitempty"`  // e.g. "gradle-wrapper.properties"
	CompileSDK    string `json:"compile_sdk,omitempty"`    // e.g. "34"
	MinSDK        string `json:"min_sdk,omitempty"`        // e.g. "23"
	TargetSDK     string `json:"target_sdk,omitempty"`     // e.g. "34"
}
