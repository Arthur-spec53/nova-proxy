{{/*
Nova Proxy Helm Chart 辅助模板
*/}}

{{/*
展开 chart 名称
*/}}
{{- define "nova-proxy.name" -}}
{{- default .Chart.Name .Values.nameOverride | trunc 63 | trimSuffix "-" }}
{{- end }}

{{/*
创建完整的资源名称
包含 release 名称和 chart 名称
*/}}
{{- define "nova-proxy.fullname" -}}
{{- if .Values.fullnameOverride }}
{{- .Values.fullnameOverride | trunc 63 | trimSuffix "-" }}
{{- else }}
{{- $name := default .Chart.Name .Values.nameOverride }}
{{- if contains $name .Release.Name }}
{{- .Release.Name | trunc 63 | trimSuffix "-" }}
{{- else }}
{{- printf "%s-%s" .Release.Name $name | trunc 63 | trimSuffix "-" }}
{{- end }}
{{- end }}
{{- end }}

{{/*
创建 chart 标签
*/}}
{{- define "nova-proxy.chart" -}}
{{- printf "%s-%s" .Chart.Name .Chart.Version | replace "+" "_" | trunc 63 | trimSuffix "-" }}
{{- end }}

{{/*
通用标签
*/}}
{{- define "nova-proxy.labels" -}}
helm.sh/chart: {{ include "nova-proxy.chart" . }}
{{ include "nova-proxy.selectorLabels" . }}
{{- if .Chart.AppVersion }}
app.kubernetes.io/version: {{ .Chart.AppVersion | quote }}
{{- end }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
app.kubernetes.io/part-of: nova-proxy-system
app.kubernetes.io/component: proxy
{{- end }}

{{/*
选择器标签
*/}}
{{- define "nova-proxy.selectorLabels" -}}
app.kubernetes.io/name: {{ include "nova-proxy.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
{{- end }}

{{/*
创建服务账户名称
*/}}
{{- define "nova-proxy.serviceAccountName" -}}
{{- if .Values.rbac.serviceAccount.create }}
{{- default (include "nova-proxy.fullname" .) .Values.rbac.serviceAccount.name }}
{{- else }}
{{- default "default" .Values.rbac.serviceAccount.name }}
{{- end }}
{{- end }}

{{/*
创建 ConfigMap 名称
*/}}
{{- define "nova-proxy.configMapName" -}}
{{- if .Values.configMap.name }}
{{- .Values.configMap.name }}
{{- else }}
{{- include "nova-proxy.fullname" . }}
{{- end }}
{{- end }}

{{/*
创建 Secret 名称
*/}}
{{- define "nova-proxy.secretName" -}}
{{- if .Values.secret.name }}
{{- .Values.secret.name }}
{{- else }}
{{- include "nova-proxy.fullname" . }}-certs
{{- end }}
{{- end }}

{{/*
创建 PVC 名称
*/}}
{{- define "nova-proxy.pvcName" -}}
{{- if .Values.storage.persistentVolumeClaim.name }}
{{- .Values.storage.persistentVolumeClaim.name }}
{{- else }}
{{- include "nova-proxy.fullname" . }}-data
{{- end }}
{{- end }}

{{/*
创建 Ingress 主机名
*/}}
{{- define "nova-proxy.ingressHost" -}}
{{- if .Values.ingress.hosts }}
{{- (index .Values.ingress.hosts 0).host }}
{{- else }}
{{- printf "%s.%s" (include "nova-proxy.fullname" .) .Values.global.domain | default "example.com" }}
{{- end }}
{{- end }}

{{/*
创建镜像地址
*/}}
{{- define "nova-proxy.image" -}}
{{- $registry := .Values.image.registry | default .Values.global.imageRegistry }}
{{- $repository := .Values.image.repository }}
{{- $tag := .Values.image.tag | default .Chart.AppVersion }}
{{- if $registry }}
{{- printf "%s/%s:%s" $registry $repository $tag }}
{{- else }}
{{- printf "%s:%s" $repository $tag }}
{{- end }}
{{- end }}

{{/*
创建资源限制
*/}}
{{- define "nova-proxy.resources" -}}
{{- if .Values.container.resources }}
resources:
  {{- if .Values.container.resources.requests }}
  requests:
    {{- if .Values.container.resources.requests.memory }}
    memory: {{ .Values.container.resources.requests.memory }}
    {{- end }}
    {{- if .Values.container.resources.requests.cpu }}
    cpu: {{ .Values.container.resources.requests.cpu }}
    {{- end }}
    {{- if .Values.container.resources.requests.ephemeral-storage }}
    ephemeral-storage: {{ index .Values.container.resources.requests "ephemeral-storage" }}
    {{- end }}
  {{- end }}
  {{- if .Values.container.resources.limits }}
  limits:
    {{- if .Values.container.resources.limits.memory }}
    memory: {{ .Values.container.resources.limits.memory }}
    {{- end }}
    {{- if .Values.container.resources.limits.cpu }}
    cpu: {{ .Values.container.resources.limits.cpu }}
    {{- end }}
    {{- if .Values.container.resources.limits.ephemeral-storage }}
    ephemeral-storage: {{ index .Values.container.resources.limits "ephemeral-storage" }}
    {{- end }}
  {{- end }}
{{- end }}
{{- end }}

{{/*
创建安全上下文
*/}}
{{- define "nova-proxy.securityContext" -}}
{{- if .Values.container.securityContext }}
securityContext:
  {{- toYaml .Values.container.securityContext | nindent 2 }}
{{- else if .Values.global.securityContext }}
securityContext:
  {{- toYaml .Values.global.securityContext | nindent 2 }}
{{- end }}
{{- end }}

{{/*
创建 Pod 安全上下文
*/}}
{{- define "nova-proxy.podSecurityContext" -}}
{{- if .Values.deployment.podSecurityContext }}
securityContext:
  {{- toYaml .Values.deployment.podSecurityContext | nindent 2 }}
{{- else if .Values.global.securityContext }}
securityContext:
  {{- toYaml .Values.global.securityContext | nindent 2 }}
{{- end }}
{{- end }}

{{/*
创建亲和性规则
*/}}
{{- define "nova-proxy.affinity" -}}
{{- if .Values.deployment.affinity }}
affinity:
  {{- toYaml .Values.deployment.affinity | nindent 2 }}
{{- else }}
affinity:
  podAntiAffinity:
    preferredDuringSchedulingIgnoredDuringExecution:
    - weight: 100
      podAffinityTerm:
        labelSelector:
          matchExpressions:
          - key: app.kubernetes.io/name
            operator: In
            values:
            - {{ include "nova-proxy.name" . }}
        topologyKey: kubernetes.io/hostname
{{- end }}
{{- end }}

{{/*
创建环境变量
*/}}
{{- define "nova-proxy.env" -}}
{{- range $key, $value := .Values.container.env }}
- name: {{ $key }}
  value: {{ $value | quote }}
{{- end }}
{{- if .Values.redis.enabled }}
- name: NOVA_REDIS_HOST
  value: {{ .Values.redis.host | quote }}
- name: NOVA_REDIS_PORT
  value: {{ .Values.redis.port | quote }}
{{- if .Values.redis.password }}
- name: NOVA_REDIS_PASSWORD
  valueFrom:
    secretKeyRef:
      name: {{ include "nova-proxy.fullname" . }}-redis
      key: password
{{- end }}
{{- end }}
{{- if .Values.tracing.jaeger.enabled }}
- name: NOVA_JAEGER_AGENT_HOST
  value: {{ .Values.tracing.jaeger.agent.host | quote }}
- name: NOVA_JAEGER_AGENT_PORT
  value: {{ .Values.tracing.jaeger.agent.port | quote }}
- name: NOVA_JAEGER_COLLECTOR_ENDPOINT
  value: {{ .Values.tracing.jaeger.collector.endpoint | quote }}
- name: NOVA_JAEGER_SAMPLER_TYPE
  value: {{ .Values.tracing.jaeger.sampler.type | quote }}
- name: NOVA_JAEGER_SAMPLER_PARAM
  value: {{ .Values.tracing.jaeger.sampler.param | quote }}
{{- end }}
{{- with .Values.container.extraEnv }}
{{- toYaml . | nindent 0 }}
{{- end }}
{{- with .Values.extra.env }}
{{- toYaml . | nindent 0 }}
{{- end }}
{{- end }}

{{/*
创建卷挂载
*/}}
{{- define "nova-proxy.volumeMounts" -}}
{{- if .Values.configMap.enabled }}
- name: config
  mountPath: /app/configs
  readOnly: true
{{- end }}
{{- if .Values.secret.enabled }}
- name: certs
  mountPath: /app/certs
  readOnly: true
{{- end }}
{{- if .Values.storage.persistentVolumeClaim.enabled }}
- name: data
  mountPath: /app/data
{{- end }}
{{- if .Values.storage.emptyDir.enabled }}
- name: tmp
  mountPath: /tmp/nova
- name: logs
  mountPath: /app/logs
- name: cache
  mountPath: /app/cache
{{- end }}
{{- with .Values.extra.volumeMounts }}
{{- toYaml . | nindent 0 }}
{{- end }}
{{- end }}

{{/*
创建卷
*/}}
{{- define "nova-proxy.volumes" -}}
{{- if .Values.configMap.enabled }}
- name: config
  configMap:
    name: {{ include "nova-proxy.configMapName" . }}
    defaultMode: 0644
{{- end }}
{{- if .Values.secret.enabled }}
- name: certs
  secret:
    secretName: {{ include "nova-proxy.secretName" . }}
    defaultMode: 0600
{{- end }}
{{- if .Values.storage.persistentVolumeClaim.enabled }}
- name: data
  persistentVolumeClaim:
    claimName: {{ include "nova-proxy.pvcName" . }}
{{- end }}
{{- if .Values.storage.emptyDir.enabled }}
- name: tmp
  emptyDir:
    {{- if .Values.storage.emptyDir.sizeLimit }}
    sizeLimit: {{ .Values.storage.emptyDir.sizeLimit }}
    {{- end }}
    {{- if .Values.storage.emptyDir.medium }}
    medium: {{ .Values.storage.emptyDir.medium }}
    {{- end }}
- name: logs
  emptyDir:
    sizeLimit: 1Gi
- name: cache
  emptyDir:
    sizeLimit: 500Mi
    {{- if eq .Values.storage.emptyDir.medium "Memory" }}
    medium: Memory
    {{- end }}
{{- end }}
{{- with .Values.extra.volumes }}
{{- toYaml . | nindent 0 }}
{{- end }}
{{- end }}

{{/*
验证配置
*/}}
{{- define "nova-proxy.validateConfig" -}}
{{- if not .Values.image.repository }}
{{- fail "image.repository is required" }}
{{- end }}
{{- if not .Values.image.tag }}
{{- if not .Chart.AppVersion }}
{{- fail "image.tag or Chart.AppVersion is required" }}
{{- end }}
{{- end }}
{{- if and .Values.ingress.enabled (not .Values.ingress.hosts) }}
{{- fail "ingress.hosts is required when ingress is enabled" }}
{{- end }}
{{- if and .Values.storage.persistentVolumeClaim.enabled (not .Values.storage.persistentVolumeClaim.size) }}
{{- fail "storage.persistentVolumeClaim.size is required when PVC is enabled" }}
{{- end }}
{{- end }}

{{/*
创建注解
*/}}
{{- define "nova-proxy.annotations" -}}
{{- with .Values.deployment.annotations }}
{{- toYaml . | nindent 0 }}
{{- end }}
{{- with .Values.extra.annotations }}
{{- toYaml . | nindent 0 }}
{{- end }}
{{- end }}

{{/*
创建 Pod 注解
*/}}
{{- define "nova-proxy.podAnnotations" -}}
checksum/config: {{ include (print $.Template.BasePath "/configmap/configmap.yaml") . | sha256sum }}
checksum/secret: {{ include (print $.Template.BasePath "/secret/secret.yaml") . | sha256sum }}
{{- with .Values.deployment.podAnnotations }}
{{- toYaml . | nindent 0 }}
{{- end }}
{{- with .Values.extra.annotations }}
{{- toYaml . | nindent 0 }}
{{- end }}
{{- end }}

{{/*
创建网络策略选择器
*/}}
{{- define "nova-proxy.networkPolicySelector" -}}
matchLabels:
  {{- include "nova-proxy.selectorLabels" . | nindent 2 }}
{{- end }}

{{/*
创建监控标签
*/}}
{{- define "nova-proxy.monitoringLabels" -}}
{{- if .Values.monitoring.prometheus.serviceMonitor.labels }}
{{- toYaml .Values.monitoring.prometheus.serviceMonitor.labels | nindent 0 }}
{{- end }}
app.kubernetes.io/name: {{ include "nova-proxy.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
{{- end }}

{{/*
创建测试标签
*/}}
{{- define "nova-proxy.testLabels" -}}
{{- include "nova-proxy.labels" . }}
app.kubernetes.io/component: test
{{- end }}