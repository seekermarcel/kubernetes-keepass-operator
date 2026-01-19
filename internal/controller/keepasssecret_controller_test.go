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
	"time"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"

	secretsv1alpha1 "github.com/seekermarcel/kubernetes-keepass-operator/api/v1alpha1"
)

var _ = Describe("KeePassSecret Controller", func() {
	const (
		timeout  = time.Second * 10
		interval = time.Millisecond * 250
	)

	Context("When reconciling a suspended resource", func() {
		const resourceName = "test-suspended"
		const namespace = "default"

		ctx := context.Background()

		typeNamespacedName := types.NamespacedName{
			Name:      resourceName,
			Namespace: namespace,
		}

		BeforeEach(func() {
			By("creating the suspended KeePassSecret")
			keepassSecret := &secretsv1alpha1.KeePassSecret{
				ObjectMeta: metav1.ObjectMeta{
					Name:      resourceName,
					Namespace: namespace,
				},
				Spec: secretsv1alpha1.KeePassSecretSpec{
					SourceRef: secretsv1alpha1.SourceRef{
						Kind: secretsv1alpha1.SourceRefKindConfigMap,
						Name: "test-source",
						Key:  "test.kdbx",
					},
					PasswordRef: secretsv1alpha1.PasswordRef{
						SecretName: "test-password",
						SecretKey:  "password",
					},
					Suspend: true,
				},
			}
			err := k8sClient.Get(ctx, typeNamespacedName, &secretsv1alpha1.KeePassSecret{})
			if errors.IsNotFound(err) {
				Expect(k8sClient.Create(ctx, keepassSecret)).To(Succeed())
			}
		})

		AfterEach(func() {
			By("cleaning up the KeePassSecret")
			resource := &secretsv1alpha1.KeePassSecret{}
			err := k8sClient.Get(ctx, typeNamespacedName, resource)
			if err == nil {
				// Remove finalizer if present
				resource.Finalizers = nil
				_ = k8sClient.Update(ctx, resource)
				Expect(k8sClient.Delete(ctx, resource)).To(Succeed())
			}
		})

		It("should skip reconciliation when suspended", func() {
			By("reconciling the suspended resource")
			reconciler := &KeePassSecretReconciler{
				Client: k8sClient,
				Scheme: k8sClient.Scheme(),
			}

			// First reconcile adds finalizer
			_, err := reconciler.Reconcile(ctx, reconcile.Request{
				NamespacedName: typeNamespacedName,
			})
			Expect(err).NotTo(HaveOccurred())

			// Second reconcile processes the resource
			_, err = reconciler.Reconcile(ctx, reconcile.Request{
				NamespacedName: typeNamespacedName,
			})
			Expect(err).NotTo(HaveOccurred())

			// Verify status condition indicates suspended
			Eventually(func() bool {
				resource := &secretsv1alpha1.KeePassSecret{}
				err := k8sClient.Get(ctx, typeNamespacedName, resource)
				if err != nil {
					return false
				}
				for _, cond := range resource.Status.Conditions {
					if cond.Type == secretsv1alpha1.ConditionTypeReady &&
						cond.Reason == secretsv1alpha1.ReasonSuspended {
						return true
					}
				}
				return false
			}, timeout, interval).Should(BeTrue())
		})
	})

	Context("When source ConfigMap is not found", func() {
		const resourceName = "test-missing-source"
		const namespace = "default"

		ctx := context.Background()

		typeNamespacedName := types.NamespacedName{
			Name:      resourceName,
			Namespace: namespace,
		}

		BeforeEach(func() {
			By("creating the KeePassSecret with missing source")
			// Create password secret
			passwordSecret := &corev1.Secret{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "test-password-secret",
					Namespace: namespace,
				},
				Data: map[string][]byte{
					"password": []byte("testpassword"),
				},
			}
			err := k8sClient.Get(ctx, types.NamespacedName{Name: "test-password-secret", Namespace: namespace}, &corev1.Secret{})
			if errors.IsNotFound(err) {
				Expect(k8sClient.Create(ctx, passwordSecret)).To(Succeed())
			}

			keepassSecret := &secretsv1alpha1.KeePassSecret{
				ObjectMeta: metav1.ObjectMeta{
					Name:      resourceName,
					Namespace: namespace,
				},
				Spec: secretsv1alpha1.KeePassSecretSpec{
					SourceRef: secretsv1alpha1.SourceRef{
						Kind: secretsv1alpha1.SourceRefKindConfigMap,
						Name: "nonexistent-configmap",
						Key:  "secrets.kdbx",
					},
					PasswordRef: secretsv1alpha1.PasswordRef{
						SecretName: "test-password-secret",
						SecretKey:  "password",
					},
				},
			}
			err = k8sClient.Get(ctx, typeNamespacedName, &secretsv1alpha1.KeePassSecret{})
			if errors.IsNotFound(err) {
				Expect(k8sClient.Create(ctx, keepassSecret)).To(Succeed())
			}
		})

		AfterEach(func() {
			By("cleaning up resources")
			resource := &secretsv1alpha1.KeePassSecret{}
			err := k8sClient.Get(ctx, typeNamespacedName, resource)
			if err == nil {
				resource.Finalizers = nil
				_ = k8sClient.Update(ctx, resource)
				Expect(k8sClient.Delete(ctx, resource)).To(Succeed())
			}

			secret := &corev1.Secret{}
			err = k8sClient.Get(ctx, types.NamespacedName{Name: "test-password-secret", Namespace: namespace}, secret)
			if err == nil {
				Expect(k8sClient.Delete(ctx, secret)).To(Succeed())
			}
		})

		It("should set SourceAvailable condition to false", func() {
			By("reconciling the resource with missing source")
			reconciler := &KeePassSecretReconciler{
				Client: k8sClient,
				Scheme: k8sClient.Scheme(),
			}

			// First reconcile adds finalizer
			_, err := reconciler.Reconcile(ctx, reconcile.Request{
				NamespacedName: typeNamespacedName,
			})
			Expect(err).NotTo(HaveOccurred())

			// Second reconcile processes the resource
			_, err = reconciler.Reconcile(ctx, reconcile.Request{
				NamespacedName: typeNamespacedName,
			})
			Expect(err).NotTo(HaveOccurred())

			// Verify status condition indicates source not available
			Eventually(func() bool {
				resource := &secretsv1alpha1.KeePassSecret{}
				err := k8sClient.Get(ctx, typeNamespacedName, resource)
				if err != nil {
					return false
				}
				for _, cond := range resource.Status.Conditions {
					if cond.Type == secretsv1alpha1.ConditionTypeSourceAvailable &&
						cond.Status == metav1.ConditionFalse {
						return true
					}
				}
				return false
			}, timeout, interval).Should(BeTrue())
		})
	})

	Context("When password secret is not found", func() {
		const resourceName = "test-missing-password"
		const namespace = "default"

		ctx := context.Background()

		typeNamespacedName := types.NamespacedName{
			Name:      resourceName,
			Namespace: namespace,
		}

		BeforeEach(func() {
			By("creating the KeePassSecret with missing password secret")
			keepassSecret := &secretsv1alpha1.KeePassSecret{
				ObjectMeta: metav1.ObjectMeta{
					Name:      resourceName,
					Namespace: namespace,
				},
				Spec: secretsv1alpha1.KeePassSecretSpec{
					SourceRef: secretsv1alpha1.SourceRef{
						Kind: secretsv1alpha1.SourceRefKindConfigMap,
						Name: "test-source",
						Key:  "secrets.kdbx",
					},
					PasswordRef: secretsv1alpha1.PasswordRef{
						SecretName: "nonexistent-password-secret",
						SecretKey:  "password",
					},
				},
			}
			err := k8sClient.Get(ctx, typeNamespacedName, &secretsv1alpha1.KeePassSecret{})
			if errors.IsNotFound(err) {
				Expect(k8sClient.Create(ctx, keepassSecret)).To(Succeed())
			}
		})

		AfterEach(func() {
			By("cleaning up the KeePassSecret")
			resource := &secretsv1alpha1.KeePassSecret{}
			err := k8sClient.Get(ctx, typeNamespacedName, resource)
			if err == nil {
				resource.Finalizers = nil
				_ = k8sClient.Update(ctx, resource)
				Expect(k8sClient.Delete(ctx, resource)).To(Succeed())
			}
		})

		It("should set PasswordResolved condition to false", func() {
			By("reconciling the resource with missing password")
			reconciler := &KeePassSecretReconciler{
				Client: k8sClient,
				Scheme: k8sClient.Scheme(),
			}

			// First reconcile adds finalizer
			_, err := reconciler.Reconcile(ctx, reconcile.Request{
				NamespacedName: typeNamespacedName,
			})
			Expect(err).NotTo(HaveOccurred())

			// Second reconcile processes the resource
			_, err = reconciler.Reconcile(ctx, reconcile.Request{
				NamespacedName: typeNamespacedName,
			})
			Expect(err).NotTo(HaveOccurred())

			// Verify status condition indicates password not resolved
			Eventually(func() bool {
				resource := &secretsv1alpha1.KeePassSecret{}
				err := k8sClient.Get(ctx, typeNamespacedName, resource)
				if err != nil {
					return false
				}
				for _, cond := range resource.Status.Conditions {
					if cond.Type == secretsv1alpha1.ConditionTypePasswordResolved &&
						cond.Status == metav1.ConditionFalse {
						return true
					}
				}
				return false
			}, timeout, interval).Should(BeTrue())
		})
	})
})
