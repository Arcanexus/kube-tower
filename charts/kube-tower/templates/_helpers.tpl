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

{{- /* The Deployments of kube-tower, as JSON {name: group}. Single mode: one, named "", with every role.
Distributed mode: one per entry of distributed.groups, its roles and its replicas, resources... with the
defaults of the top-level values. The group running trivy has one replica and no autoscaling. */ -}}
{{- define "kube-tower.groups" -}}
{{- $roles := list "ui" "controller" "worker" "trivy" }}
{{- $groups := dict }}
{{- if eq .Values.mode "distributed" }}
{{- $count := dict "ui" 0 "controller" 0 "worker" 0 "trivy" 0 }}
{{- range $name, $g := .Values.distributed.groups }}
{{- if $g }}
{{- $groupRoles := required (printf "distributed.groups.%s.roles is required" $name) $g.roles }}
{{- if has "all" $groupRoles }}
{{- $groupRoles = $roles }}
{{- end }}
{{- range $groupRoles }}
{{- if not (has . $roles) }}
{{- fail (printf "distributed.groups.%s.roles: unknown role %q (expected all, ui, controller, worker or trivy)" $name .) }}
{{- end }}
{{- $_ := set $count . (add1 (get $count .)) }}
{{- end }}
{{- $single := has "trivy" $groupRoles }}
{{- $autoscaling := $g.autoscaling | default dict }}
{{- if or $single (has "controller" $groupRoles) }}
{{- $autoscaling = dict }}
{{- end }}
{{- $_ := set $groups $name (dict
  "roles" $groupRoles
  "replicas" (ternary 1 ($g.replicas | default 1) $single)
  "autoscaling" $autoscaling
  "resources" ($g.resources | default $.Values.resources)
  "nodeSelector" ($g.nodeSelector | default $.Values.nodeSelector)
  "tolerations" ($g.tolerations | default $.Values.tolerations)
  "affinity" ($g.affinity | default $.Values.affinity)) }}
{{- end }}
{{- end }}
{{- range $role, $n := $count }}
{{- if eq (int $n) 0 }}
{{- fail (printf "mode distributed: no group of distributed.groups runs the %s role" $role) }}
{{- end }}
{{- if and (gt (int $n) 1) (has $role (list "controller" "trivy")) }}
{{- fail (printf "mode distributed: the %s role must run in one group of distributed.groups only" $role) }}
{{- end }}
{{- end }}
{{- else if eq .Values.mode "single" }}
{{- $_ := set $groups "" (dict
  "roles" $roles
  "replicas" .Values.replicaCount
  "autoscaling" dict
  "resources" .Values.resources
  "nodeSelector" .Values.nodeSelector
  "tolerations" .Values.tolerations
  "affinity" .Values.affinity) }}
{{- else }}
{{- fail (printf "mode: %q is not single or distributed" .Values.mode) }}
{{- end }}
{{- toJson $groups }}
{{- end }}

{{- define "kube-tower.distributed" -}}
{{- if eq .Values.mode "distributed" }}true{{ end }}
{{- end }}

{{- /* Redis / Valkey URL: where the pods of the distributed mode talk, and the controller keeps the snapshot; empty when none */ -}}
{{- define "kube-tower.redisUrl" -}}
{{- if .Values.redis.valkey.enabled }}
{{- printf "redis://%s-valkey:%v/0" (include "kube-tower.fullname" .) .Values.redis.valkey.port }}
{{- else }}
{{- .Values.redis.url }}
{{- end }}
{{- end }}

{{- define "kube-tower.valkeySelectorLabels" -}}
app.kubernetes.io/name: {{ include "kube-tower.name" . }}-valkey
app.kubernetes.io/instance: {{ .Release.Name }}
{{- end }}

{{- /* Secret holding the Redis / Valkey password: the existing one or the chart's, empty when none */ -}}
{{- define "kube-tower.redisSecretName" -}}
{{- if .Values.redis.existingSecret }}
{{- .Values.redis.existingSecret }}
{{- else if .Values.redis.password }}
{{- printf "%s-redis" (include "kube-tower.fullname" .) }}
{{- end }}
{{- end }}

{{/*
Secret of the login: admin password and session key (auth.enabled).
*/}}
{{/*
Secret of the OIDC client (auth.oidc.existingSecret, or auth.oidc.clientSecret.existingSecret of 1.1.0-rc.1)
and its keys.
*/}}
{{- define "kube-tower.oidcSecretName" -}}
{{- .Values.auth.oidc.existingSecret | default (dig "clientSecret" "existingSecret" "" .Values.auth.oidc) }}
{{- end }}

{{- define "kube-tower.oidcClientSecretKey" -}}
{{- dig "clientSecret" "key" "" .Values.auth.oidc | default .Values.auth.oidc.clientSecretKey | default "clientSecret" }}
{{- end }}

{{- define "kube-tower.authSecretName" -}}
{{- .Values.auth.existingSecret | default (printf "%s-auth" (include "kube-tower.fullname" .)) }}
{{- end }}

{{/*
Dex of the chart (dex.enabled): its selector labels, its address, and its issuer (<auth.url>api/dex).
*/}}
{{- define "kube-tower.dexSelectorLabels" -}}
app.kubernetes.io/name: {{ include "kube-tower.name" . }}-dex
app.kubernetes.io/instance: {{ .Release.Name }}
{{- end }}

{{- define "kube-tower.dexUrl" -}}
{{- printf "http://%s-dex:5556" (include "kube-tower.fullname" .) }}
{{- end }}

{{- define "kube-tower.dexIssuer" -}}
{{- if not .Values.auth.enabled }}
{{- fail "dex.enabled needs auth.enabled=true (and auth.url)" }}
{{- end }}
{{- $url := required "dex.enabled needs auth.url: the URL users open kube-tower with" .Values.auth.url }}
{{- printf "%s/api/dex" (trimSuffix "/" $url) }}
{{- end }}
