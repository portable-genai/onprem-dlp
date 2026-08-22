{{- define "onprem-dlp.name" -}}
{{- default .Chart.Name .Values.nameOverride | trunc 63 | trimSuffix "-" }}
{{- end }}

{{- define "onprem-dlp.fullname" -}}
{{- if .Values.fullnameOverride }}
{{- .Values.fullnameOverride | trunc 63 | trimSuffix "-" }}
{{- else }}
{{- printf "%s-%s" .Release.Name (include "onprem-dlp.name" .) | trunc 63 | trimSuffix "-" }}
{{- end }}
{{- end }}

{{- define "onprem-dlp.labels" -}}
app.kubernetes.io/name: {{ include "onprem-dlp.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
app.kubernetes.io/version: {{ .Chart.AppVersion | quote }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
helm.sh/chart: {{ printf "%s-%s" .Chart.Name .Chart.Version | quote }}
{{- end }}

{{- define "onprem-dlp.selectorLabels" -}}
app.kubernetes.io/name: {{ include "onprem-dlp.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
{{- end }}

{{- define "onprem-dlp.serviceAccountName" -}}
{{- if .Values.serviceAccount.create }}
{{- default (include "onprem-dlp.fullname" .) .Values.serviceAccount.name }}
{{- else }}
{{- required "serviceAccount.name is required when create=false" .Values.serviceAccount.name }}
{{- end }}
{{- end }}

{{- define "onprem-dlp.image" -}}
{{- if .Values.image.digest -}}
{{ printf "%s@%s" .Values.image.repository .Values.image.digest }}
{{- else -}}
{{ printf "%s:%s" .Values.image.repository .Values.image.tag }}
{{- end -}}
{{- end }}
