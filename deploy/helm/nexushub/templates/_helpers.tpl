{{/*
Expand the name of the chart. Truncated to 63 so it's a valid
Kubernetes label value even when the release name is long.
*/}}
{{- define "nexushub.name" -}}
{{- default .Chart.Name .Values.nameOverride | trunc 63 | trimSuffix "-" }}
{{- end }}

{{/*
Fully qualified app name. Used as the default resource name, service
selector, etc. Release.Name appears first so multiple releases of
the same chart don't collide.
*/}}
{{- define "nexushub.fullname" -}}
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

{{/* Chart label, e.g. nexushub-0.1.0 — goes on every resource. */}}
{{- define "nexushub.chart" -}}
{{- printf "%s-%s" .Chart.Name .Chart.Version | replace "+" "_" | trunc 63 | trimSuffix "-" }}
{{- end }}

{{/* Common labels applied to every resource the chart creates. */}}
{{- define "nexushub.labels" -}}
helm.sh/chart: {{ include "nexushub.chart" . }}
{{ include "nexushub.selectorLabels" . }}
app.kubernetes.io/version: {{ .Chart.AppVersion | quote }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
{{- end }}

{{/* Selector labels — stable across upgrades. Must NOT include
version/chart fields, otherwise a chart upgrade orphans the
existing Deployment's selector. */}}
{{- define "nexushub.selectorLabels" -}}
app.kubernetes.io/name: {{ include "nexushub.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
{{- end }}

{{/* ServiceAccount name to use. */}}
{{- define "nexushub.serviceAccountName" -}}
{{- if .Values.serviceAccount.create }}
{{- default (include "nexushub.fullname" .) .Values.serviceAccount.name }}
{{- else }}
{{- default "default" .Values.serviceAccount.name }}
{{- end }}
{{- end }}

{{/* Name of the Secret carrying DATABASE_URL. When the operator
supplied an existingSecret we return that; otherwise we
generate one from values.yaml. */}}
{{- define "nexushub.postgresSecretName" -}}
{{- if .Values.postgres.existingSecret }}
{{- .Values.postgres.existingSecret }}
{{- else }}
{{- printf "%s-postgres" (include "nexushub.fullname" .) }}
{{- end }}
{{- end }}

{{/* Name of the Secret carrying JWT_SECRET + PEER_KEY_ENCRYPTION_KEY. */}}
{{- define "nexushub.appSecretName" -}}
{{- if .Values.secrets.existingSecret }}
{{- .Values.secrets.existingSecret }}
{{- else }}
{{- printf "%s-app" (include "nexushub.fullname" .) }}
{{- end }}
{{- end }}

{{/* Image reference combining repository + tag (falling back to
appVersion when tag is empty). */}}
{{- define "nexushub.image" -}}
{{- $tag := default .Chart.AppVersion .Values.image.tag -}}
{{- printf "%s:%s" .Values.image.repository $tag -}}
{{- end }}
