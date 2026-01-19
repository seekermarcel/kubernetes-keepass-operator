/*
Copyright 2026.

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

package v1alpha1

import (
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// SourceRefKind defines the kind of source reference for the KeePass database
// +kubebuilder:validation:Enum=ConfigMap;Secret
type SourceRefKind string

const (
	// SourceRefKindConfigMap indicates the source is a ConfigMap
	SourceRefKindConfigMap SourceRefKind = "ConfigMap"
	// SourceRefKindSecret indicates the source is a Secret
	SourceRefKindSecret SourceRefKind = "Secret"
)

// SourceRef defines a reference to the source containing the KeePass database
type SourceRef struct {
	// kind specifies whether the source is a ConfigMap or Secret
	// +kubebuilder:validation:Required
	// +kubebuilder:default=ConfigMap
	Kind SourceRefKind `json:"kind"`

	// name is the name of the ConfigMap or Secret containing the .kdbx file
	// +kubebuilder:validation:Required
	// +kubebuilder:validation:MinLength=1
	// +kubebuilder:validation:MaxLength=253
	Name string `json:"name"`

	// key is the key within the ConfigMap/Secret's binaryData that contains the .kdbx file
	// +kubebuilder:validation:Required
	// +kubebuilder:validation:MinLength=1
	Key string `json:"key"`
}

// PasswordRef defines how to obtain the password for decrypting the KeePass database
type PasswordRef struct {
	// secretName is the name of the Secret containing the password
	// Required when useNamespaceLookup is false
	// +optional
	SecretName string `json:"secretName,omitempty"`

	// secretKey is the key within the Secret that contains the password
	// Defaults to "password" if not specified
	// +kubebuilder:default=password
	// +optional
	SecretKey string `json:"secretKey,omitempty"`

	// useNamespaceLookup enables automatic password lookup from domain-passwords.kdbx
	// When true, the operator looks up the password using the namespace name as the entry title
	// The domain-passwords.kdbx file must be mounted in the operator and decrypted using MASTER_PASSWORD env var
	// +kubebuilder:default=false
	// +optional
	UseNamespaceLookup bool `json:"useNamespaceLookup,omitempty"`
}

// KeePassSecretSpec defines the desired state of KeePassSecret
type KeePassSecretSpec struct {
	// sourceRef references the ConfigMap or Secret containing the .kdbx file
	// +kubebuilder:validation:Required
	SourceRef SourceRef `json:"sourceRef"`

	// passwordRef defines how to obtain the password for decrypting the KeePass database
	// +kubebuilder:validation:Required
	PasswordRef PasswordRef `json:"passwordRef"`

	// targetSecretName overrides the default secret name (derived from the source key name)
	// If not specified, the secret name will be derived from the .kdbx filename without extension
	// +kubebuilder:validation:MaxLength=253
	// +kubebuilder:validation:Pattern=`^[a-z0-9]([-a-z0-9]*[a-z0-9])?(\.[a-z0-9]([-a-z0-9]*[a-z0-9])?)*$`
	// +optional
	TargetSecretName string `json:"targetSecretName,omitempty"`

	// secretLabels defines additional labels to apply to generated secrets
	// +optional
	SecretLabels map[string]string `json:"secretLabels,omitempty"`

	// suspend stops the operator from reconciling this resource when set to true
	// +kubebuilder:default=false
	// +optional
	Suspend bool `json:"suspend,omitempty"`
}

// GeneratedSecretInfo contains information about a generated Kubernetes Secret
type GeneratedSecretInfo struct {
	// name is the name of the generated Secret
	Name string `json:"name"`

	// keys is the number of data keys in the Secret
	Keys int `json:"keys"`

	// lastUpdated is the timestamp when the Secret was last updated
	// +optional
	LastUpdated *metav1.Time `json:"lastUpdated,omitempty"`
}

// KeePassSecretStatus defines the observed state of KeePassSecret
type KeePassSecretStatus struct {
	// conditions represent the current state of the KeePassSecret resource
	// +listType=map
	// +listMapKey=type
	// +optional
	Conditions []metav1.Condition `json:"conditions,omitempty"`

	// generatedSecrets contains information about the Kubernetes Secrets created from this resource
	// +optional
	GeneratedSecrets []GeneratedSecretInfo `json:"generatedSecrets,omitempty"`

	// lastReconcileTime is the timestamp of the last successful reconciliation
	// +optional
	LastReconcileTime *metav1.Time `json:"lastReconcileTime,omitempty"`

	// observedGeneration is the last observed generation of the KeePassSecret resource
	// +optional
	ObservedGeneration int64 `json:"observedGeneration,omitempty"`
}

// Condition types for KeePassSecret
const (
	// ConditionTypeReady indicates whether the KeePassSecret is ready
	ConditionTypeReady = "Ready"

	// ConditionTypeSourceAvailable indicates whether the source ConfigMap/Secret is available
	ConditionTypeSourceAvailable = "SourceAvailable"

	// ConditionTypePasswordResolved indicates whether the password was successfully resolved
	ConditionTypePasswordResolved = "PasswordResolved"

	// ConditionTypeDecrypted indicates whether the KeePass database was successfully decrypted
	ConditionTypeDecrypted = "Decrypted"

	// ConditionTypeSecretsCreated indicates whether the Kubernetes Secrets were created
	ConditionTypeSecretsCreated = "SecretsCreated"
)

// Condition reasons for KeePassSecret
const (
	// ReasonSucceeded indicates the operation succeeded
	ReasonSucceeded = "Succeeded"

	// ReasonFailed indicates the operation failed
	ReasonFailed = "Failed"

	// ReasonSourceNotFound indicates the source ConfigMap/Secret was not found
	ReasonSourceNotFound = "SourceNotFound"

	// ReasonKeyNotFound indicates the specified key was not found in the source
	ReasonKeyNotFound = "KeyNotFound"

	// ReasonPasswordSecretNotFound indicates the password Secret was not found
	ReasonPasswordSecretNotFound = "PasswordSecretNotFound"

	// ReasonNamespacePasswordNotFound indicates no password entry for the namespace in domain-passwords.kdbx
	ReasonNamespacePasswordNotFound = "NamespacePasswordNotFound"

	// ReasonDecryptionFailed indicates the KeePass database could not be decrypted
	ReasonDecryptionFailed = "DecryptionFailed"

	// ReasonInvalidKeePassFile indicates the file is not a valid KeePass database
	ReasonInvalidKeePassFile = "InvalidKeePassFile"

	// ReasonSuspended indicates the resource reconciliation is suspended
	ReasonSuspended = "Suspended"
)

// +kubebuilder:object:root=true
// +kubebuilder:subresource:status
// +kubebuilder:printcolumn:name="Ready",type="string",JSONPath=".status.conditions[?(@.type=='Ready')].status"
// +kubebuilder:printcolumn:name="Secrets",type="integer",JSONPath=".status.generatedSecrets[*].keys"
// +kubebuilder:printcolumn:name="Age",type="date",JSONPath=".metadata.creationTimestamp"

// KeePassSecret is the Schema for the keepasssecrets API
// It creates Kubernetes Secrets from encrypted KeePass database files
type KeePassSecret struct {
	metav1.TypeMeta `json:",inline"`

	// metadata is the standard object metadata
	// +optional
	metav1.ObjectMeta `json:"metadata,omitempty"`

	// spec defines the desired state of KeePassSecret
	// +required
	Spec KeePassSecretSpec `json:"spec"`

	// status defines the observed state of KeePassSecret
	// +optional
	Status KeePassSecretStatus `json:"status,omitempty"`
}

// +kubebuilder:object:root=true

// KeePassSecretList contains a list of KeePassSecret resources
type KeePassSecretList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []KeePassSecret `json:"items"`
}

func init() {
	SchemeBuilder.Register(&KeePassSecret{}, &KeePassSecretList{})
}
