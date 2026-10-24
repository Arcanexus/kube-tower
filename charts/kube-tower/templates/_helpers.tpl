{{- define "kube-tower.name" -}}
{{- default .Chart.Name .Values.nameOverride | trunc 63 | trimSuffix "-" }}
{{- end }}

{{- define "kube-tower.fullname" -}}
{{- if .Values.fullnameOverride }}
{{- .Values.fullnameOverride | trunc 63 | trimSuffix "-" }}
{{- else if contains (include "kube-tower.name" .) .Release.Name }}
{{- .Release.Name | trunc 63 | trimSuffix "-" }}
{{- else }}
{{- printf "%s-%s" .Release.Name (include "kube-tower.name" .) | trunc 63 | trimSuffix "-" }}
{{- end }}
{{- end }}

{{- define "kube-tower.labels" -}}
helm.sh/chart: {{ printf "%s-%s" .Chart.Name .Chart.Version | replace "+" "_" }}
{{ include "kube-tower.selectorLabels" . }}
app.kubernetes.io/version: {{ .Chart.AppVersion | quote }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
{{- end }}

{{- define "kube-tower.selectorLabels" -}}
app.kubernetes.io/name: {{ include "kube-tower.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
{{- end }}

{{- /* Distinct from the kube-tower pods, which select on name and instance only */ -}}
{{- define "kube-tower.trivySelectorLabels" -}}
app.kubernetes.io/name: {{ include "kube-tower.name" . }}-trivy
app.kubernetes.io/instance: {{ .Release.Name }}
{{- end }}

{{- /* Path of the Trivy CLI copied by the init container, empty when kube-tower does not scan with Trivy */ -}}
{{- define "kube-tower.trivyBinary" -}}
{{- $vuln := .Values.config.vulnerabilities | default dict }}
{{- $trivy := $vuln.trivy | default dict }}
{{- if and .Values.trivy.enabled (ne $vuln.enabled false) (ne $trivy.enabled false) }}/opt/trivy/bin/trivy{{- end }}
{{- end }}

{{- define "kube-tower.serviceAccountName" -}}
{{- if .Values.serviceAccount.create }}
{{- default (include "kube-tower.fullname" .) .Values.serviceAccount.name }}
{{- else }}
{{- default "default" .Values.serviceAccount.name }}
{{- end }}
{{- end }}

{{- /* Secret holding the credentials of registries.credentials[index]: the existing one or the chart's */ -}}
{{- define "kube-tower.registrySecretName" -}}
{{- $c := index .root.Values.registries.credentials .index }}
{{- if $c.existingSecret }}
{{- $c.existingSecret }}
{{- else if $c.password }}
{{- printf "%s-registry-%d" (include "kube-tower.fullname" .root) .index }}
{{- else }}
{{- fail (printf "registries.credentials[%d] (%s): set existingSecret or password" .index ($c.registry | default "?")) }}
{{- end }}
{{- end }}

{{- /* kubernetes.io/dockerconfigjson Secret: the existing one or the chart's, empty when none */ -}}
{{- define "kube-tower.dockerConfigSecretName" -}}
{{- if .Values.registries.existingSecret }}
{{- .Values.registries.existingSecret }}
{{- else if .Values.registries.dockerConfigJson }}
{{- printf "%s-dockerconfig" (include "kube-tower.fullname" .) }}
{{- end }}
{{- end }}

{{- /* Secret holding the git token: the existing one or the chart's, empty when none */ -}}
{{- define "kube-tower.gitSecretName" -}}
{{- if .Values.git.existingSecret }}
{{- .Values.git.existingSecret }}
{{- else if .Values.git.token }}
{{- printf "%s-git" (include "kube-tower.fullname" .) }}
{{- end }}
{{- end }}

{{- /* Names of the existing cluster Secrets referenced in the values */ -}}
{{- /* Cluster Secrets of .Values.clusters, read by name: existing ones and the ones the chart creates. */ -}}
{{- define "kube-tower.clusterSecretNames" -}}
{{- $names := list }}
{{- range .Values.clusters }}
{{- if .existingSecret }}
{{- $names = append $names .existingSecret }}
{{- else if .name }}
{{- $names = append $names (printf "%s-cluster-%s" (include "kube-tower.fullname" $) .name) }}
{{- end }}
{{- end }}
{{- toJson $names }}
{{- end }}

{{/* ConfigMap holding the CA certificates of internal registries, empty when none */}}
{{- define "kube-tower.caConfigMapName" -}}
{{- if .Values.registries.ca.existingConfigMap }}
{{- .Values.registries.ca.existingConfigMap }}
{{- else if .Values.registries.ca.pem }}
{{- printf "%s-ca" (include "kube-tower.fullname" .) }}
{{- end }}
{{- end }}
