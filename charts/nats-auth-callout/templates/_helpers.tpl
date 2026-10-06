{{- define "nats-auth-callout.name" -}}
{{- default .Chart.Name .Values.nameOverride | trunc 63 | trimSuffix "-" }}
{{- end }}

{{- define "nats-auth-callout.fullname" -}}
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

{{- define "nats-auth-callout.selectorLabels" -}}
app.kubernetes.io/name: {{ include "nats-auth-callout.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
{{- end }}

{{- define "nats-auth-callout.labels" -}}
helm.sh/chart: {{ printf "%s-%s" .Chart.Name .Chart.Version | replace "+" "_" | trunc 63 | trimSuffix "-" }}
{{ include "nats-auth-callout.selectorLabels" . }}
app.kubernetes.io/version: {{ .Chart.AppVersion | quote }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
{{- end }}

{{- define "nats-auth-callout.serviceAccountName" -}}
{{- if .Values.serviceAccount.create }}
{{- default (include "nats-auth-callout.fullname" .) .Values.serviceAccount.name }}
{{- else }}
{{- default "default" .Values.serviceAccount.name }}
{{- end }}
{{- end }}

{{- define "nats-auth-callout.image" -}}
{{- printf "%s:%s" .Values.image.repository (default .Chart.AppVersion .Values.image.tag) }}
{{- end }}

{{/* Name of the Secret with issuer seed, xkey seed and password. */}}
{{- define "nats-auth-callout.secretName" -}}
{{- if .Values.secret.create }}
{{- include "nats-auth-callout.fullname" . }}
{{- else }}
{{- required "secret.existingSecret is required unless secret.create=true" .Values.secret.existingSecret }}
{{- end }}
{{- end }}

{{/* Secret keys: fixed when the chart creates the Secret, configurable for an existing one. */}}
{{- define "nats-auth-callout.secretKeys" -}}
{{- if .Values.secret.create }}
issuerSeed: issuer-seed
xkeySeed: xkey-seed
password: password
{{- else }}
{{- toYaml .Values.secret.keys }}
{{- end }}
{{- end }}

{{- define "nats-auth-callout.configMapName" -}}
{{- if .Values.existingConfigMap }}
{{- .Values.existingConfigMap }}
{{- else }}
{{- include "nats-auth-callout.fullname" . }}
{{- end }}
{{- end }}
