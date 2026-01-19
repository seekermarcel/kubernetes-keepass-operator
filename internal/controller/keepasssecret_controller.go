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

package controller

import (
	"context"
	"fmt"
	"os"
	"strings"
	"time"

	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"
	"sigs.k8s.io/controller-runtime/pkg/handler"
	logf "sigs.k8s.io/controller-runtime/pkg/log"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"

	secretsv1alpha1 "github.com/seekermarcel/kubernetes-keepass-operator/api/v1alpha1"
	"github.com/seekermarcel/kubernetes-keepass-operator/internal/keepass"
)

const (
	// DomainPasswordsPath is the path to the domain-passwords.kdbx file
	DomainPasswordsPath = "/etc/domain-passwords/domain-passwords.kdbx"

	// MasterPasswordEnvVar is the environment variable containing the master password
	MasterPasswordEnvVar = "MASTER_PASSWORD"

	// LabelManagedBy is the label key for identifying the operator
	LabelManagedBy = "app.kubernetes.io/managed-by"
	// LabelManagedByValue is the value for the managed-by label
	LabelManagedByValue = "keepass-operator"

	// LabelSecretName is the label key for the secret name
	LabelSecretName = "app.kubernetes.io/name"

	// LabelSourceKeePassSecret is the label key for the source KeePassSecret
	LabelSourceKeePassSecret = "secrets.keepass.io/source-keepasssecret"

	// FinalizerName is the finalizer used by this controller
	FinalizerName = "secrets.keepass.io/finalizer"
)

// KeePassSecretReconciler reconciles a KeePassSecret object
type KeePassSecretReconciler struct {
	client.Client
	Scheme *runtime.Scheme

	// domainPasswordsDB caches the domain-passwords.kdbx database
	domainPasswordsDB *keepass.Database
}

// +kubebuilder:rbac:groups=secrets.keepass.io,resources=keepasssecrets,verbs=get;list;watch;create;update;patch;delete
// +kubebuilder:rbac:groups=secrets.keepass.io,resources=keepasssecrets/status,verbs=get;update;patch
// +kubebuilder:rbac:groups=secrets.keepass.io,resources=keepasssecrets/finalizers,verbs=update
// +kubebuilder:rbac:groups="",resources=secrets,verbs=get;list;watch;create;update;patch;delete
// +kubebuilder:rbac:groups="",resources=configmaps,verbs=get;list;watch
// +kubebuilder:rbac:groups="",resources=events,verbs=create;patch

// Reconcile is part of the main kubernetes reconciliation loop which aims to
// move the current state of the cluster closer to the desired state.
func (r *KeePassSecretReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	log := logf.FromContext(ctx)
	log.Info("Reconciling KeePassSecret", "namespace", req.Namespace, "name", req.Name)

	// Fetch the KeePassSecret instance
	kps := &secretsv1alpha1.KeePassSecret{}
	if err := r.Get(ctx, req.NamespacedName, kps); err != nil {
		if apierrors.IsNotFound(err) {
			log.Info("KeePassSecret resource not found, ignoring")
			return ctrl.Result{}, nil
		}
		log.Error(err, "Failed to get KeePassSecret")
		return ctrl.Result{}, err
	}

	// Handle deletion
	if !kps.DeletionTimestamp.IsZero() {
		return r.handleDeletion(ctx, kps)
	}

	// Add finalizer if not present
	if !controllerutil.ContainsFinalizer(kps, FinalizerName) {
		controllerutil.AddFinalizer(kps, FinalizerName)
		if err := r.Update(ctx, kps); err != nil {
			return ctrl.Result{}, err
		}
		return ctrl.Result{Requeue: true}, nil
	}

	// Check if suspended
	if kps.Spec.Suspend {
		log.Info("KeePassSecret is suspended, skipping reconciliation")
		r.setCondition(kps, secretsv1alpha1.ConditionTypeReady, metav1.ConditionFalse,
			secretsv1alpha1.ReasonSuspended, "Reconciliation is suspended")
		return r.updateStatus(ctx, kps)
	}

	// Step 1: Resolve password
	password, err := r.resolvePassword(ctx, kps)
	if err != nil {
		log.Error(err, "Failed to resolve password")
		r.setCondition(kps, secretsv1alpha1.ConditionTypePasswordResolved, metav1.ConditionFalse,
			secretsv1alpha1.ReasonFailed, err.Error())
		r.setCondition(kps, secretsv1alpha1.ConditionTypeReady, metav1.ConditionFalse,
			secretsv1alpha1.ReasonFailed, "Failed to resolve password")
		return r.updateStatus(ctx, kps)
	}
	r.setCondition(kps, secretsv1alpha1.ConditionTypePasswordResolved, metav1.ConditionTrue,
		secretsv1alpha1.ReasonSucceeded, "Password resolved successfully")

	// Step 2: Fetch source data (ConfigMap or Secret with .kdbx)
	kdbxData, err := r.fetchSourceData(ctx, kps)
	if err != nil {
		log.Error(err, "Failed to fetch source data")
		r.setCondition(kps, secretsv1alpha1.ConditionTypeSourceAvailable, metav1.ConditionFalse,
			secretsv1alpha1.ReasonFailed, err.Error())
		r.setCondition(kps, secretsv1alpha1.ConditionTypeReady, metav1.ConditionFalse,
			secretsv1alpha1.ReasonFailed, "Failed to fetch source data")
		return r.updateStatus(ctx, kps)
	}
	r.setCondition(kps, secretsv1alpha1.ConditionTypeSourceAvailable, metav1.ConditionTrue,
		secretsv1alpha1.ReasonSucceeded, "Source data available")

	// Step 3: Decrypt KeePass database
	db, err := keepass.OpenDatabase(kdbxData, password)
	if err != nil {
		log.Error(err, "Failed to decrypt KeePass database")
		r.setCondition(kps, secretsv1alpha1.ConditionTypeDecrypted, metav1.ConditionFalse,
			secretsv1alpha1.ReasonDecryptionFailed, err.Error())
		r.setCondition(kps, secretsv1alpha1.ConditionTypeReady, metav1.ConditionFalse,
			secretsv1alpha1.ReasonDecryptionFailed, "Failed to decrypt KeePass database")
		return r.updateStatus(ctx, kps)
	}
	r.setCondition(kps, secretsv1alpha1.ConditionTypeDecrypted, metav1.ConditionTrue,
		secretsv1alpha1.ReasonSucceeded, "KeePass database decrypted successfully")

	// Step 4: Extract secrets
	defaultSecretName := r.getDefaultSecretName(kps)
	groupedSecrets, err := db.ExtractSecrets(defaultSecretName)
	if err != nil {
		log.Error(err, "Failed to extract secrets from KeePass database")
		r.setCondition(kps, secretsv1alpha1.ConditionTypeReady, metav1.ConditionFalse,
			secretsv1alpha1.ReasonFailed, err.Error())
		return r.updateStatus(ctx, kps)
	}

	// Step 5: Create/Update Kubernetes Secrets
	generatedSecrets, err := r.createOrUpdateSecrets(ctx, kps, groupedSecrets)
	if err != nil {
		log.Error(err, "Failed to create/update secrets")
		r.setCondition(kps, secretsv1alpha1.ConditionTypeSecretsCreated, metav1.ConditionFalse,
			secretsv1alpha1.ReasonFailed, err.Error())
		r.setCondition(kps, secretsv1alpha1.ConditionTypeReady, metav1.ConditionFalse,
			secretsv1alpha1.ReasonFailed, "Failed to create/update secrets")
		return r.updateStatus(ctx, kps)
	}

	// Update status with generated secrets info
	kps.Status.GeneratedSecrets = generatedSecrets
	r.setCondition(kps, secretsv1alpha1.ConditionTypeSecretsCreated, metav1.ConditionTrue,
		secretsv1alpha1.ReasonSucceeded, fmt.Sprintf("Created/updated %d secrets", len(generatedSecrets)))
	r.setCondition(kps, secretsv1alpha1.ConditionTypeReady, metav1.ConditionTrue,
		secretsv1alpha1.ReasonSucceeded, "All secrets synchronized successfully")

	now := metav1.Now()
	kps.Status.LastReconcileTime = &now
	kps.Status.ObservedGeneration = kps.Generation

	log.Info("Reconciliation completed successfully",
		"secretsCreated", len(generatedSecrets))

	return r.updateStatus(ctx, kps)
}

// handleDeletion handles the deletion of a KeePassSecret
func (r *KeePassSecretReconciler) handleDeletion(ctx context.Context, kps *secretsv1alpha1.KeePassSecret) (ctrl.Result, error) {
	log := logf.FromContext(ctx)

	if controllerutil.ContainsFinalizer(kps, FinalizerName) {
		log.Info("Handling deletion of KeePassSecret")

		// Secrets are automatically deleted due to owner references
		// Remove finalizer
		controllerutil.RemoveFinalizer(kps, FinalizerName)
		if err := r.Update(ctx, kps); err != nil {
			return ctrl.Result{}, err
		}
	}

	return ctrl.Result{}, nil
}

// resolvePassword resolves the password for decrypting the KeePass database
func (r *KeePassSecretReconciler) resolvePassword(ctx context.Context, kps *secretsv1alpha1.KeePassSecret) (string, error) {
	if kps.Spec.PasswordRef.UseNamespaceLookup {
		return r.resolveNamespacePassword(kps.Namespace)
	}
	return r.resolveSecretPassword(ctx, kps)
}

// resolveSecretPassword resolves the password from a Kubernetes Secret
func (r *KeePassSecretReconciler) resolveSecretPassword(ctx context.Context, kps *secretsv1alpha1.KeePassSecret) (string, error) {
	if kps.Spec.PasswordRef.SecretName == "" {
		return "", fmt.Errorf("passwordRef.secretName is required when useNamespaceLookup is false")
	}

	secret := &corev1.Secret{}
	secretKey := types.NamespacedName{
		Namespace: kps.Namespace,
		Name:      kps.Spec.PasswordRef.SecretName,
	}

	if err := r.Get(ctx, secretKey, secret); err != nil {
		if apierrors.IsNotFound(err) {
			return "", fmt.Errorf("password secret %q not found", kps.Spec.PasswordRef.SecretName)
		}
		return "", fmt.Errorf("failed to get password secret: %w", err)
	}

	key := kps.Spec.PasswordRef.SecretKey
	if key == "" {
		key = "password"
	}

	passwordBytes, ok := secret.Data[key]
	if !ok {
		return "", fmt.Errorf("key %q not found in password secret %q", key, kps.Spec.PasswordRef.SecretName)
	}

	return string(passwordBytes), nil
}

// resolveNamespacePassword resolves the password from domain-passwords.kdbx
func (r *KeePassSecretReconciler) resolveNamespacePassword(namespace string) (string, error) {
	// Load domain-passwords.kdbx if not already loaded
	if r.domainPasswordsDB == nil {
		masterPassword := os.Getenv(MasterPasswordEnvVar)
		if masterPassword == "" {
			return "", fmt.Errorf("environment variable %s is not set", MasterPasswordEnvVar)
		}

		db, err := keepass.OpenDatabaseFromFile(DomainPasswordsPath, masterPassword)
		if err != nil {
			return "", fmt.Errorf("failed to open domain-passwords.kdbx: %w", err)
		}
		r.domainPasswordsDB = db
	}

	// Look up the password for this namespace
	password, found := r.domainPasswordsDB.FindEntryByTitle(namespace)
	if !found {
		return "", fmt.Errorf("no password entry found for namespace %q in domain-passwords.kdbx", namespace)
	}

	return password, nil
}

// fetchSourceData fetches the .kdbx data from the source ConfigMap or Secret
func (r *KeePassSecretReconciler) fetchSourceData(ctx context.Context, kps *secretsv1alpha1.KeePassSecret) ([]byte, error) {
	sourceRef := kps.Spec.SourceRef
	key := types.NamespacedName{
		Namespace: kps.Namespace,
		Name:      sourceRef.Name,
	}

	var data []byte

	switch sourceRef.Kind {
	case secretsv1alpha1.SourceRefKindConfigMap:
		cm := &corev1.ConfigMap{}
		if err := r.Get(ctx, key, cm); err != nil {
			if apierrors.IsNotFound(err) {
				return nil, fmt.Errorf("source ConfigMap %q not found", sourceRef.Name)
			}
			return nil, fmt.Errorf("failed to get source ConfigMap: %w", err)
		}

		var ok bool
		data, ok = cm.BinaryData[sourceRef.Key]
		if !ok {
			// Also check regular data (base64 encoded)
			if strData, exists := cm.Data[sourceRef.Key]; exists {
				data = []byte(strData)
			} else {
				return nil, fmt.Errorf("key %q not found in ConfigMap %q", sourceRef.Key, sourceRef.Name)
			}
		}

	case secretsv1alpha1.SourceRefKindSecret:
		secret := &corev1.Secret{}
		if err := r.Get(ctx, key, secret); err != nil {
			if apierrors.IsNotFound(err) {
				return nil, fmt.Errorf("source Secret %q not found", sourceRef.Name)
			}
			return nil, fmt.Errorf("failed to get source Secret: %w", err)
		}

		var ok bool
		data, ok = secret.Data[sourceRef.Key]
		if !ok {
			return nil, fmt.Errorf("key %q not found in Secret %q", sourceRef.Key, sourceRef.Name)
		}

	default:
		return nil, fmt.Errorf("unsupported source kind: %s", sourceRef.Kind)
	}

	return data, nil
}

// getDefaultSecretName returns the default secret name based on spec or source key
func (r *KeePassSecretReconciler) getDefaultSecretName(kps *secretsv1alpha1.KeePassSecret) string {
	if kps.Spec.TargetSecretName != "" {
		return kps.Spec.TargetSecretName
	}

	// Derive from source key, removing .kdbx extension
	name := kps.Spec.SourceRef.Key
	name = strings.TrimSuffix(name, ".kdbx")
	name = strings.TrimSuffix(name, ".KDBX")

	return name
}

// createOrUpdateSecrets creates or updates Kubernetes Secrets from grouped secrets
func (r *KeePassSecretReconciler) createOrUpdateSecrets(
	ctx context.Context,
	kps *secretsv1alpha1.KeePassSecret,
	groupedSecrets []keepass.GroupedSecrets,
) ([]secretsv1alpha1.GeneratedSecretInfo, error) {
	log := logf.FromContext(ctx)
	generatedInfo := make([]secretsv1alpha1.GeneratedSecretInfo, 0, len(groupedSecrets))

	for _, gs := range groupedSecrets {
		// Skip empty groups
		if len(gs.Data) == 0 {
			continue
		}

		// Build secret data
		secretData := make(map[string][]byte)
		for _, sd := range gs.Data {
			key := keepass.SanitizeSecretKey(sd.Key)
			secretData[key] = sd.Value
		}

		// Build labels
		labels := map[string]string{
			LabelManagedBy:           LabelManagedByValue,
			LabelSecretName:          gs.SecretName,
			LabelSourceKeePassSecret: kps.Name,
		}

		// Merge labels from spec
		for k, v := range kps.Spec.SecretLabels {
			labels[k] = v
		}

		// Merge labels from group config
		for k, v := range gs.Labels {
			labels[k] = v
		}

		// Create or update the secret
		secret := &corev1.Secret{
			ObjectMeta: metav1.ObjectMeta{
				Name:      gs.SecretName,
				Namespace: kps.Namespace,
			},
		}

		result, err := controllerutil.CreateOrUpdate(ctx, r.Client, secret, func() error {
			secret.Labels = labels
			secret.Data = secretData
			secret.Type = corev1.SecretTypeOpaque

			// Set owner reference
			return controllerutil.SetControllerReference(kps, secret, r.Scheme)
		})

		if err != nil {
			return nil, fmt.Errorf("failed to create/update secret %q: %w", gs.SecretName, err)
		}

		log.Info("Secret reconciled", "name", gs.SecretName, "operation", result)

		now := metav1.Now()
		generatedInfo = append(generatedInfo, secretsv1alpha1.GeneratedSecretInfo{
			Name:        gs.SecretName,
			Keys:        len(secretData),
			LastUpdated: &now,
		})
	}

	return generatedInfo, nil
}

// setCondition sets a condition on the KeePassSecret status
func (r *KeePassSecretReconciler) setCondition(kps *secretsv1alpha1.KeePassSecret, conditionType string, status metav1.ConditionStatus, reason, message string) {
	condition := metav1.Condition{
		Type:               conditionType,
		Status:             status,
		ObservedGeneration: kps.Generation,
		LastTransitionTime: metav1.NewTime(time.Now()),
		Reason:             reason,
		Message:            message,
	}
	meta.SetStatusCondition(&kps.Status.Conditions, condition)
}

// updateStatus updates the status of the KeePassSecret
func (r *KeePassSecretReconciler) updateStatus(ctx context.Context, kps *secretsv1alpha1.KeePassSecret) (ctrl.Result, error) {
	if err := r.Status().Update(ctx, kps); err != nil {
		logf.FromContext(ctx).Error(err, "Failed to update KeePassSecret status")
		return ctrl.Result{}, err
	}
	return ctrl.Result{}, nil
}

// findKeePassSecretsForConfigMap finds KeePassSecrets that reference a given ConfigMap
func (r *KeePassSecretReconciler) findKeePassSecretsForConfigMap(ctx context.Context, obj client.Object) []reconcile.Request {
	cm := obj.(*corev1.ConfigMap)
	log := logf.FromContext(ctx)

	kpsList := &secretsv1alpha1.KeePassSecretList{}
	if err := r.List(ctx, kpsList, client.InNamespace(cm.Namespace)); err != nil {
		log.Error(err, "Failed to list KeePassSecrets")
		return nil
	}

	var requests []reconcile.Request
	for _, kps := range kpsList.Items {
		if kps.Spec.SourceRef.Kind == secretsv1alpha1.SourceRefKindConfigMap &&
			kps.Spec.SourceRef.Name == cm.Name {
			requests = append(requests, reconcile.Request{
				NamespacedName: types.NamespacedName{
					Namespace: kps.Namespace,
					Name:      kps.Name,
				},
			})
		}
	}

	return requests
}

// findKeePassSecretsForSecret finds KeePassSecrets that reference a given Secret
func (r *KeePassSecretReconciler) findKeePassSecretsForSecret(ctx context.Context, obj client.Object) []reconcile.Request {
	secret := obj.(*corev1.Secret)
	log := logf.FromContext(ctx)

	kpsList := &secretsv1alpha1.KeePassSecretList{}
	if err := r.List(ctx, kpsList, client.InNamespace(secret.Namespace)); err != nil {
		log.Error(err, "Failed to list KeePassSecrets")
		return nil
	}

	var requests []reconcile.Request
	for _, kps := range kpsList.Items {
		// Check if this secret is referenced as source
		if kps.Spec.SourceRef.Kind == secretsv1alpha1.SourceRefKindSecret &&
			kps.Spec.SourceRef.Name == secret.Name {
			requests = append(requests, reconcile.Request{
				NamespacedName: types.NamespacedName{
					Namespace: kps.Namespace,
					Name:      kps.Name,
				},
			})
			continue
		}

		// Check if this secret is referenced as password source
		if kps.Spec.PasswordRef.SecretName == secret.Name {
			requests = append(requests, reconcile.Request{
				NamespacedName: types.NamespacedName{
					Namespace: kps.Namespace,
					Name:      kps.Name,
				},
			})
		}
	}

	return requests
}

// SetupWithManager sets up the controller with the Manager.
func (r *KeePassSecretReconciler) SetupWithManager(mgr ctrl.Manager) error {
	return ctrl.NewControllerManagedBy(mgr).
		For(&secretsv1alpha1.KeePassSecret{}).
		// Watch for changes in ConfigMaps that are referenced as sources
		Watches(
			&corev1.ConfigMap{},
			handler.EnqueueRequestsFromMapFunc(r.findKeePassSecretsForConfigMap),
		).
		// Watch for changes in Secrets that are referenced as sources or password refs
		Watches(
			&corev1.Secret{},
			handler.EnqueueRequestsFromMapFunc(r.findKeePassSecretsForSecret),
		).
		// Watch owned Secrets
		Owns(&corev1.Secret{}).
		Named("keepasssecret").
		Complete(r)
}
