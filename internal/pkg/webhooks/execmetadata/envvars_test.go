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
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
	admissionv1 "k8s.io/api/admission/v1"
	authenticationv1 "k8s.io/api/authentication/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/webhook/admission"
)

func TestResolveAdmissionPath(t *testing.T) {
	t.Parallel()

	req := &admissionv1.AdmissionRequest{
		UID:         types.UID("req-uid"),
		Name:        "pod",
		Namespace:   "ns",
		SubResource: "exec",
		Operation:   admissionv1.Connect,
		Kind:        metav1.GroupVersionKind{Group: "", Version: "v1", Kind: "PodExecOptions"},
		Resource: metav1.GroupVersionResource{
			Group: "", Version: "v1", Resource: "pods",
		},
		UserInfo: user("alice"),
	}

	for _, tc := range []struct {
		path string
		want string
	}{
		{path: "uid", want: "req-uid"},
		{path: "name", want: "pod"},
		{path: "namespace", want: "ns"},
		{path: "subResource", want: "exec"},
		{path: "operation", want: "CONNECT"},
		{path: "userInfo.username", want: "alice"},
		{path: "userInfo.uid", want: "user-uid"},
		{path: "kind.kind", want: "PodExecOptions"},
		{path: "kind.version", want: "v1"},
		{path: "resource.resource", want: "pods"},
	} {
		t.Run(tc.path, func(t *testing.T) {
			t.Parallel()

			value, err := resolveAdmissionPath(req, tc.path)
			require.NoError(t, err)
			require.Equal(t, tc.want, value)
		})
	}

	for _, tc := range []struct {
		name string
		path string
		want string
	}{
		{name: "empty", path: "", want: "the path is empty"},
		{name: "unknown field", path: "nope", want: `the admission request has no field "nope"`},
		{
			name: "unknown nested field",
			path: "userInfo.nope",
			want: `the admission request has no field "nope"`,
		},
		{
			name: "not a string",
			path: "userInfo.groups",
			want: `"userInfo.groups" of the admission request is no string`,
		},
		{
			name: "not a string at the top",
			path: "object",
			want: `"object" of the admission request is no string`,
		},
		{
			name: "field of a string",
			path: "uid.nope",
			want: `"nope" names no field of a struct of the admission request`,
		},
		{
			name: "unset pointer",
			path: "requestKind.kind",
			want: `the field "requestKind" of the admission request is not set`,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			_, err := resolveAdmissionPath(req, tc.path)
			require.ErrorContains(t, err, tc.want)
		})
	}

	t.Run("set pointer", func(t *testing.T) {
		t.Parallel()

		request := req.DeepCopy()
		request.RequestKind = &metav1.GroupVersionKind{Version: "v1", Kind: "Pod"}

		value, err := resolveAdmissionPath(request, "requestKind.kind")
		require.NoError(t, err)
		require.Equal(t, "Pod", value)
	})
}

func TestEnvVarsFor(t *testing.T) {
	t.Parallel()

	req := &admission.Request{AdmissionRequest: admissionv1.AdmissionRequest{
		UID:      types.UID("req-uid"),
		Name:     "pod",
		UserInfo: user("alice"),
	}}

	for _, tc := range []struct {
		name         string
		envVars      map[string]string
		want         []corev1.EnvVar
		wantWarnings []string
	}{
		{
			name: "nil",
			want: []corev1.EnvVar{},
		},
		{
			name:    "empty",
			envVars: map[string]string{},
			want:    []corev1.EnvVar{},
		},
		{
			name:    "one variable",
			envVars: map[string]string{"A": "uid"},
			want:    []corev1.EnvVar{{Name: "A", Value: "req-uid"}},
		},
		{
			name: "sorted by name",
			envVars: map[string]string{
				"B": "name", "A": "uid", "C": "userInfo.username",
			},
			want: []corev1.EnvVar{
				{Name: "A", Value: "req-uid"},
				{Name: "B", Value: "pod"},
				{Name: "C", Value: "alice"},
			},
		},
		{
			name:    "invalid name",
			envVars: map[string]string{"a-b": "uid"},
			want:    []corev1.EnvVar{},
			wantWarnings: []string{
				"the security profiles operator did not set a-b: " +
					"the name is no valid environment variable name",
			},
		},
		{
			name:    "unknown path",
			envVars: map[string]string{"A": "nope"},
			want:    []corev1.EnvVar{},
			wantWarnings: []string{
				`the security profiles operator did not set A: ` +
					`the admission request has no field "nope"`,
			},
		},
		{
			name: "the valid ones get set",
			envVars: map[string]string{
				"A": "uid", "b-c": "uid", "D": "nope",
			},
			want: []corev1.EnvVar{{Name: "A", Value: "req-uid"}},
			wantWarnings: []string{
				`the security profiles operator did not set D: ` +
					`the admission request has no field "nope"`,
				"the security profiles operator did not set b-c: " +
					"the name is no valid environment variable name",
			},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			handler := Handler{envVars: tc.envVars}
			envVars, warnings := handler.envVarsFor(req)
			require.Equal(t, tc.want, envVars)
			require.Equal(t, tc.wantWarnings, warnings)
		})
	}
}

func TestAuditAnnotations(t *testing.T) {
	t.Parallel()

	envVars := []corev1.EnvVar{
		{Name: "A", Value: "short"},
		{Name: "B", Value: strings.Repeat("x", maxAuditAnnotationValue)},
		{Name: "C", Value: strings.Repeat("x", maxAuditAnnotationValue+1)},
	}

	require.Equal(t, map[string]string{
		"A": "short",
		"B": strings.Repeat("x", maxAuditAnnotationValue),
	}, auditAnnotations(envVars))
}

func TestEnvVarsFromEnv(t *testing.T) {
	const key = "SPO_TEST_EXEC_METADATA_ENV_VARS"

	t.Setenv(key, "")
	envVars, err := EnvVarsFromEnv(key)
	require.NoError(t, err)
	require.Empty(t, envVars)

	t.Setenv(key, `{"A":"uid","B":"userInfo.username"}`)
	envVars, err = EnvVarsFromEnv(key)
	require.NoError(t, err)
	require.Equal(t, map[string]string{"A": "uid", "B": "userInfo.username"}, envVars)

	t.Setenv(key, `{`)
	_, err = EnvVarsFromEnv(key)
	require.ErrorContains(t, err, "parse the environment variable "+key)
}

// user returns the user info of the tests.
func user(name string) authenticationv1.UserInfo {
	return authenticationv1.UserInfo{
		Username: name,
		UID:      "user-uid",
		Groups:   []string{"system:authenticated"},
	}
}
