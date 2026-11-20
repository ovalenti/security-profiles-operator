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
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"path"
	"slices"
	"strconv"
	"strings"

	"github.com/go-logr/logr"
	"gomodules.xyz/jsonpatch/v2"
	corev1 "k8s.io/api/core/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"
	logf "sigs.k8s.io/controller-runtime/pkg/log"
	"sigs.k8s.io/controller-runtime/pkg/webhook"
	"sigs.k8s.io/controller-runtime/pkg/webhook/admission"

	"sigs.k8s.io/security-profiles-operator/internal/pkg/config"
	"sigs.k8s.io/security-profiles-operator/internal/pkg/webhooks/utils"
)

var errUnsupportedSubResource = errors.New("unsupported pod sub resource")

// envCommand is the env binary which the exec sessions run through, so that
// they get the environment variables set.
const envCommand = "env"

type Handler struct {
	log logr.Logger

	// reader looks up the pod of an exec request. Nil skips the lookup.
	reader client.Reader

	// envVars maps the names of the environment variables which get set
	// in exec sessions, ephemeral containers and node debugging pods to
	// the paths in the admission request which the values come from, like
	// "uid" or "userInfo.username". Nil or empty leaves the requests
	// unmodified.
	envVars map[string]string
}

// Ensure ExecMetadataHandler implements admission.Handler at compile time.
var _ admission.Handler = (*Handler)(nil)

// getPodPatch returns the patch for a pod. The API server sends requests for
// the ephemeral containers sub resource with the "pods" resource and the sub
// resource set separately, so the sub resource decides about the patch.
func (p Handler) getPodPatch(
	envVars []corev1.EnvVar, req *admission.Request,
) ([]jsonpatch.JsonPatchOperation, error) {
	switch req.SubResource {
	case "":
		return p.getNodeDebuggingPodPatch(envVars, req)
	case utils.EphemeralContainersSubResource:
		return p.getEphemeralContainerPatch(envVars, req)
	default:
		return nil, fmt.Errorf("%w: %s", errUnsupportedSubResource, req.SubResource)
	}
}

func (p Handler) getNodeDebuggingPodPatch(
	envVars []corev1.EnvVar, req *admission.Request,
) ([]jsonpatch.JsonPatchOperation, error) {
	patches := make([]jsonpatch.JsonPatchOperation, 0, 1)

	podObject := corev1.Pod{}

	if err := json.Unmarshal(req.Object.Raw, &podObject); err != nil {
		return patches, fmt.Errorf("failed to unmarshal pod exec object: %w", err)
	}

	p.log.V(1).Info("podObject before mutate", "podObject", podObject)

	if len(podObject.Spec.Containers) == 0 {
		return patches, errors.New("failed to find a container")
	}

	container := podObject.Spec.Containers[0]
	container.Env = removeExistingEnv(container.Env, envVarNames(envVars))
	container.Env = append(container.Env, envVars...)

	// "add" rather than "replace": Container.Env is omitempty, so the member is
	// absent for a container that declares no environment variables and RFC 6902
	// "replace" on a missing member is an error. "add" upserts in both cases.
	patches = append(patches, jsonpatch.JsonPatchOperation{
		Operation: "add",
		Path:      "/spec/containers/0/env",
		Value:     container.Env,
	})

	p.log.V(1).Info("podObject after mutate", "podObject", podObject)

	return patches, nil
}

func (p Handler) getEphemeralContainerPatch(
	envVars []corev1.EnvVar, req *admission.Request,
) ([]jsonpatch.JsonPatchOperation, error) {
	patches := make([]jsonpatch.JsonPatchOperation, 0)

	podObject := corev1.Pod{}

	if err := json.Unmarshal(req.Object.Raw, &podObject); err != nil {
		return patches, fmt.Errorf("failed to unmarshal pod exec object: %w", err)
	}

	p.log.V(1).Info("podObject before mutate", "execPodObject", podObject)

	// The env of already created ephemeral containers cannot be changed.
	var oldPod *corev1.Pod

	if len(req.OldObject.Raw) > 0 {
		oldPod = &corev1.Pod{}
		if err := json.Unmarshal(req.OldObject.Raw, oldPod); err != nil {
			return patches, fmt.Errorf("failed to unmarshal old pod object: %w", err)
		}
	}

	existing := utils.ExistingEphemeralContainers(&podObject, oldPod)

	for i := range podObject.Spec.EphemeralContainers {
		container := &podObject.Spec.EphemeralContainers[i]
		if existing[container.Name] {
			continue
		}

		container.Env = removeExistingEnv(container.Env, envVarNames(envVars))
		container.Env = append(container.Env, envVars...)

		patches = append(patches, jsonpatch.JsonPatchOperation{
			Operation: "add",
			Path:      "/spec/ephemeralContainers/" + strconv.Itoa(i) + "/env",
			Value:     container.Env,
		})
	}

	p.log.V(1).Info("podObject after mutate", "podObject", podObject)

	return patches, nil
}

// removeExistingEnv removes every environment variable with one of the
// names, so that a duplicated one cannot shadow the variables which get
// appended.
func removeExistingEnv(env []corev1.EnvVar, names []string) []corev1.EnvVar {
	return slices.DeleteFunc(env, func(envVar corev1.EnvVar) bool {
		return slices.Contains(names, envVar.Name)
	})
}

// envVarNames returns the names of the environment variables.
func envVarNames(envVars []corev1.EnvVar) []string {
	names := make([]string, len(envVars))
	for i := range envVars {
		names[i] = envVars[i].Name
	}

	return names
}

func (p Handler) getPodExecPatch(
	envVars []corev1.EnvVar, req *admission.Request,
) ([]jsonpatch.JsonPatchOperation, error) {
	patches := make([]jsonpatch.JsonPatchOperation, 0, 1)

	execObject := corev1.PodExecOptions{}

	if err := json.Unmarshal(req.Object.Raw, &execObject); err != nil {
		return patches, fmt.Errorf("failed to unmarshal pod exec object: %w", err)
	}

	p.log.V(1).Info("execObject before mutate", "execObject", execObject)

	execObject.Command = setExecEnv(execObject.Command, envVars)

	p.log.V(1).Info("execObject after mutate", "execObject", execObject)

	return append(patches, jsonpatch.JsonPatchOperation{
		Operation: "add",
		Path:      "/command",
		Value:     execObject.Command,
	}), nil
}

// setExecEnv makes the command run with the environment variables. The
// leading env commands of the command get parsed, every assignment of one
// of the variables in them gets its value, and the innermost env command
// ends its assignments with the ones it misses, so that neither an
// assignment nor an option like -i or -u of the command can replace or
// remove them. Arguments of the command which runs are never changed. A
// command which is not an env command runs through one, which takes its
// leading arguments with a "=" for assignments as well. An env command
// with an option which is not known, like -S which splits a string into
// more arguments, gets an env command which sets the variables prepended.
// The command can still change the variables, see the documentation of the
// exec metadata.
func setExecEnv(command []string, envVars []corev1.EnvVar) []string {
	assignments := make([]string, len(envVars))
	for i := range envVars {
		assignments[i] = envVars[i].Name + "=" + envVars[i].Value
	}

	withEnv := command

	switch {
	case len(command) > 0 && strings.HasPrefix(command[0], "-"):
		// The command must not become an option of env.
		withEnv = append([]string{envCommand, "--"}, command...)
	case len(command) == 0 || path.Base(command[0]) != envCommand:
		withEnv = append([]string{envCommand}, command...)
	}

	layers, ok := parseEnvLayers(withEnv)
	if !ok {
		return slices.Insert(command, 0, append([]string{envCommand}, assignments...)...)
	}

	command = withEnv

	// set tells for every variable whether the innermost env command
	// assigns it, so that only the missing assignments get appended.
	set := make([]bool, len(envVars))

	for i, layer := range layers {
		for j := layer.assignments; j < layer.end; j++ {
			for k := range envVars {
				if strings.HasPrefix(command[j], envVars[k].Name+"=") {
					command[j] = assignments[k]

					if i == len(layers)-1 {
						set[k] = true
					}
				}
			}
		}
	}

	missing := make([]string, 0, len(assignments))

	for k := range envVars {
		if !set[k] {
			missing = append(missing, assignments[k])
		}
	}

	if len(missing) == 0 {
		return command
	}

	return slices.Insert(command, layers[len(layers)-1].end, missing...)
}

// EnvCommandRequestUID returns the request UID which setExecEnv assigned
// in the arguments of an env command, and false if the arguments are no env
// command or have none. The leading env commands get parsed like setExecEnv
// does: every assignment of the variable in them has the request UID, the
// last one of the innermost env command being the one which env applies
// last. For an env command with an option which is not known, the request
// UID is in the env command which setExecEnv prepended, which is the first
// assignment in the arguments of its process. The process of the env
// command it runs has it in its environment instead, which the caller reads
// then. Options and their arguments, like the directory of -C, are no
// assignments.
func EnvCommandRequestUID(args []string) (string, bool) {
	if len(args) == 0 || path.Base(args[0]) != envCommand {
		return "", false
	}

	prefix := config.ExecRequestUIDEnvKey + "="

	layers, ok := parseEnvLayers(args)
	if !ok {
		if len(args) > 1 {
			if uid, found := strings.CutPrefix(args[1], prefix); found {
				return uid, uid != ""
			}
		}

		return "", false
	}

	for _, layer := range slices.Backward(layers) {
		for j := layer.end - 1; j >= layer.assignments; j-- {
			if uid, found := strings.CutPrefix(args[j], prefix); found {
				return uid, uid != ""
			}
		}
	}

	return "", false
}

// envLayer is an env command within an exec command. Its assignments start at
// the index assignments, after its options, and end before the index end,
// where the command it runs starts.
type envLayer struct {
	assignments, end int
}

// parseEnvLayers returns the env commands the command starts with, an env
// command which runs another env command being one layer each. It returns
// false if an env command has an option which is not known or misses the
// argument of an option. The options are the ones of GNU and busybox env
// which do not change the arguments.
func parseEnvLayers(command []string) ([]envLayer, bool) {
	var layers []envLayer

	for i := 0; i < len(command) && path.Base(command[i]) == envCommand; {
		i++

	options:
		for i < len(command) {
			arg := command[i]

			switch {
			case arg == "--":
				i++

				// A lone "-" after the options is -i, also after "--".
				if i < len(command) && command[i] == "-" {
					i++
				}

				break options
			case arg == "-":
				i++

				break options
			case strings.HasPrefix(arg, "--"), strings.HasPrefix(arg, "-"):
				n, ok := envOption(command, i)
				if !ok {
					return nil, false
				}

				i += n
			default:
				break options
			}
		}

		layer := envLayer{assignments: i}

		// Like env, every argument with a "=" is an assignment.
		for i < len(command) && strings.Contains(command[i], "=") {
			i++
		}

		layer.end = i
		layers = append(layers, layer)
	}

	return layers, true
}

// envOption returns the number of arguments the option of the env command at
// index i takes, or false if it is not known. Short options can be combined,
// like -iu NAME.
func envOption(command []string, i int) (int, bool) {
	arg := command[i]
	hasArg := i+1 < len(command)

	if long, ok := strings.CutPrefix(arg, "--"); ok {
		name, _, inline := strings.Cut(long, "=")

		switch name {
		case "ignore-environment", "null", "debug":
			return 1, !inline
		case "unset", "chdir":
			if inline {
				return 1, true
			}

			return 2, hasArg
		default:
			return 0, false
		}
	}

	for j := 1; j < len(arg); j++ {
		switch arg[j] {
		case 'i', '0', 'v':
		case 'u', 'C':
			// The rest of the argument or the next one is the value.
			if j+1 < len(arg) {
				return 1, true
			}

			return 2, hasArg
		default:
			return 0, false
		}
	}

	return 1, true
}

// isWindowsPodExec returns true if the exec request targets a Windows pod.
// Windows containers have no env command to prefix the exec command with, so
// the command would fail. The request carries only the exec options, so the
// pod gets looked up. If that fails, the request is treated like one for a
// Linux pod, which the vast majority is. The lookup goes to the API server:
// the webhook may only get pods, so it cannot cache them.
func (p Handler) isWindowsPodExec(ctx context.Context, req *admission.Request) bool {
	if p.reader == nil {
		return false
	}

	pod := &corev1.Pod{}
	if err := p.reader.Get(
		ctx,
		client.ObjectKey{Namespace: req.Namespace, Name: req.Name},
		pod,
	); err != nil {
		p.log.Error(err, "Cannot get the pod of the exec request, assuming a Linux pod",
			"namespace", req.Namespace, "pod", req.Name)

		return false
	}

	return utils.IsWindowsPod(pod)
}

//nolint:gocritic // hugeParam: admission.Handler defines the signature
func (p Handler) Handle(ctx context.Context, req admission.Request) admission.Response {
	p.log.V(1).Info("Executing execmetadata webhook")

	patchGenerators := map[string]func(envVars []corev1.EnvVar, req *admission.Request) (
		[]jsonpatch.JsonPatchOperation, error,
	){
		"PodExecOptions": p.getPodExecPatch,
		"Pod":            p.getPodPatch,
	}

	patchFunc, ok := patchGenerators[req.Kind.Kind]
	if !ok {
		p.log.V(1).Info("Unrecognized kind, allowing request", "kind", req.Kind.Kind)

		return admission.Allowed("pod exec request unmodified")
	}

	envVars, warnings := p.envVarsFor(&req)

	if len(envVars) == 0 {
		// No variable to set, either because none is configured or because
		// none of them resolves. The warnings report the ones which do not.
		resp := admission.Allowed("pod exec request unmodified")
		resp.Warnings = append(resp.Warnings, warnings...)

		return resp
	}

	if req.Kind.Kind == "PodExecOptions" && p.isWindowsPodExec(ctx, &req) {
		p.log.V(1).
			Info("Windows pod, allowing request", "namespace", req.Namespace, "pod", req.Name)

		return admission.Allowed("windows pod exec request unmodified")
	}

	jsonPathOps, err := patchFunc(envVars, &req)
	if err != nil {
		p.log.Error(err, "Failed to generate json patch", "kind", req.Kind.Kind)

		// The webhook fails open, but the client learns that the request
		// carries no exec metadata.
		resp := admission.Allowed("pod exec request unmodified").WithWarnings(
			"the security profiles operator did not add the exec metadata: " + err.Error(),
		)
		resp.Warnings = append(resp.Warnings, warnings...)

		return resp
	}

	resp := admission.Patched("environment variables added to execmetadata", jsonPathOps...)

	// The values of the environment variables get recorded as audit
	// annotations, to correlate the log from the container and the API
	// server.
	resp.AuditAnnotations = auditAnnotations(envVars)
	resp.Warnings = append(resp.Warnings, warnings...)

	p.log.V(1).Info("response sent", "resp", resp)

	return resp
}

// Needed to skip the exec requests for Windows pods:
// +kubebuilder:rbac:groups=core,resources=pods,verbs=get

// RegisterWebhook registers the webhook. The reader looks up the pods of exec
// requests, and should read from the API server rather than from a cache,
// because the webhook does not cache pods otherwise. The envVars map the
// names of the environment variables which get set to the paths in the
// admission request which the values come from, see EnvVarsFromEnv.
func RegisterWebhook(server webhook.Server, reader client.Reader, envVars map[string]string) {
	server.Register(
		config.ExecMetadataWebhookPath,
		&webhook.Admission{
			Handler: &Handler{
				log:     logf.Log.WithName("execmetadata"),
				reader:  reader,
				envVars: envVars,
			},
		},
	)
}
