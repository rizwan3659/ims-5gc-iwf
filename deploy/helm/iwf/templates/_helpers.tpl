{{- define "iwf.fullname" -}}
{{- printf "%s" .Release.Name | trunc 63 | trimSuffix "-" -}}
{{- end -}}
{{- define "iwf.labels" -}}
app: {{ include "iwf.fullname" . }}
app.kubernetes.io/name: iwf
app.kubernetes.io/instance: {{ .Release.Name }}
app.kubernetes.io/version: {{ .Chart.AppVersion }}
{{- end -}}
