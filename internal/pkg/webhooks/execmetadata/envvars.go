/*
Copyright The Kubernetes Authors.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package execmetadata

import (
	"encoding/json"
	"errors"
	"fmt"
	"maps"
	"os"
	"reflect"
	"regexp"
	"slices"
	"strings"

	admissionv1 "k8s.io/api/admission/v1"
	corev1 "k8s.io/api/core/v1"
	"sigs.k8s.io/controller-runtime/pkg/webhook/admission"
)

// envVarName matches the names of the environment variables which the webhook
// may set. The API server rejects an object with an invalid one, so a
// configured name which does not match gets skipped, see envVarsFor.
var envVarName = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]*$`)

// maxAuditAnnotationValue is the longest value of an audit annotation of the
// admission response, the API server rejects a longer one.
const maxAuditAnnotationValue = 256

// errEmptyPath is returned for a path which names no field.
var errEmptyPath = errors.New("the path is empty")

// envVarsFor returns the environment variables which get set for the
// admission request, one per configured name in the order of their names,
// and the warnings for the configured variables which do not get set,
// because their name is invalid or their path resolves to no string.
func (p Handler) envVarsFor(req *admission.Request) (envVars []corev1.EnvVar, warnings []string) {
	names := slices.Sorted(maps.Keys(p.envVars))

	envVars = make([]corev1.EnvVar, 0, len(names))

	for _, name := range names {
		if !envVarName.MatchString(name) {
			warnings = append(warnings, "the security profiles operator did not set "+name+
				": the name is no valid environment variable name")

			continue
		}

		value, err := resolveAdmissionPath(&req.AdmissionRequest, p.envVars[name])
		if err != nil {
			warnings = append(warnings, "the security profiles operator did not set "+name+
				": "+err.Error())

			continue
		}

		envVars = append(envVars, corev1.EnvVar{Name: name, Value: value})
	}

	return envVars, warnings
}

// resolveAdmissionPath returns the value of the string field of the admission
// request at the path, like "uid" or "userInfo.username". The path is the
// dotted sequence of the JSON names of the fields of the request. It fails
// if a name of the path is no field of a struct, or if the field at the path
// is no string or not set.
func resolveAdmissionPath(req *admissionv1.AdmissionRequest, path string) (string, error) {
	if path == "" {
		return "", errEmptyPath
	}

	value := reflect.ValueOf(req).Elem()

	for name := range strings.SplitSeq(path, ".") {
		if value.Kind() != reflect.Struct {
			return "", fmt.Errorf("%q names no field of a struct of the admission request", name)
		}

		field, ok := fieldByJSONName(value.Type(), name)
		if !ok {
			return "", fmt.Errorf("the admission request has no field %q", name)
		}

		value = value.Field(field)

		if value.Kind() == reflect.Pointer {
			if value.IsNil() {
				return "", fmt.Errorf("the field %q of the admission request is not set", name)
			}

			value = value.Elem()
		}
	}

	if value.Kind() != reflect.String {
		return "", fmt.Errorf("%q of the admission request is no string", path)
	}

	return value.String(), nil
}

// fieldByJSONName returns the index of the field of the struct type with the
// JSON name, and false if it has none. Fields without a JSON name cannot be
// named by a path.
func fieldByJSONName(t reflect.Type, name string) (int, bool) {
	for i := range t.NumField() {
		jsonName, _, _ := strings.Cut(t.Field(i).Tag.Get("json"), ",")
		if jsonName != "" && jsonName == name {
			return i, true
		}
	}

	return 0, false
}

// auditAnnotations returns the audit annotations which record the values of
// the environment variables, so that the API server writes them to its audit
// log, if enabled. The value of an annotation is limited in length, so a
// longer one gets no annotation.
func auditAnnotations(envVars []corev1.EnvVar) map[string]string {
	annotations := make(map[string]string, len(envVars))

	for _, envVar := range envVars {
		if len(envVar.Value) <= maxAuditAnnotationValue {
			annotations[envVar.Name] = envVar.Value
		}
	}

	return annotations
}

// EnvVarsFromEnv returns the environment variables which the exec metadata
// webhooks set, from the environment variable with the key, which carries
// them as JSON which maps their names to the paths in the admission request
// which the values come from. A missing or empty variable returns no
// environment variables.
func EnvVarsFromEnv(key string) (map[string]string, error) {
	value := os.Getenv(key)
	if value == "" {
		return map[string]string{}, nil
	}

	envVars := map[string]string{}
	if err := json.Unmarshal([]byte(value), &envVars); err != nil {
		return nil, fmt.Errorf("parse the environment variable %s: %w", key, err)
	}

	return envVars, nil
}
