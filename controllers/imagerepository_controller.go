/*
Copyright 2023 Red Hat, Inc.

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

package controllers

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"strings"
	"time"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"
	ctrllog "sigs.k8s.io/controller-runtime/pkg/log"

	"github.com/go-logr/logr"
	imagerepositoryv1beta1 "github.com/redhat-appstudio/image-controller/api/v1beta1"
	l "github.com/redhat-appstudio/image-controller/pkg/logs"
	"github.com/redhat-appstudio/image-controller/pkg/quay"
	remotesecretv1beta1 "github.com/redhat-appstudio/remote-secret/api/v1beta1"
)

const (
	ImageRepositoryFinalizer = "appstudio.openshift.io/image-repository"
)

// ImageRepositoryReconciler reconciles a ImageRepository object
type ImageRepositoryReconciler struct {
	client.Client
	Scheme *runtime.Scheme

	QuayClient       quay.QuayService
	BuildQuayClient  func(logr.Logger) quay.QuayService
	QuayOrganization string
}

// SetupWithManager sets up the controller with the Manager.
func (r *ImageRepositoryReconciler) SetupWithManager(mgr ctrl.Manager) error {
	return ctrl.NewControllerManagedBy(mgr).
		For(&imagerepositoryv1beta1.ImageRepository{}).
		Complete(r)
}

//+kubebuilder:rbac:groups=appstudio.redhat.com,resources=imagerepositories,verbs=get;list;watch;create;update;patch;delete
//+kubebuilder:rbac:groups=appstudio.redhat.com,resources=imagerepositories/status,verbs=get;update;patch
//+kubebuilder:rbac:groups=appstudio.redhat.com,resources=imagerepositories/finalizers,verbs=update
//+kubebuilder:rbac:groups="",resources=secrets,verbs=get;list;watch;create;update;patch
//+kubebuilder:rbac:groups=appstudio.redhat.com,resources=remotesecrets,verbs=get;list;watch;create

func (r *ImageRepositoryReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	log := ctrllog.FromContext(ctx).WithName("ImageRepository")
	ctx = ctrllog.IntoContext(ctx, log)

	// Fetch the image repository instance
	imageRepository := &imagerepositoryv1beta1.ImageRepository{}
	err := r.Client.Get(ctx, req.NamespacedName, imageRepository)
	if err != nil {
		if errors.IsNotFound(err) {
			// The object is deleted, nothing to do
			return ctrl.Result{}, nil
		}
		log.Error(err, "failed to get image repository", l.Action, l.ActionView)
		return ctrl.Result{}, err
	}

	if !imageRepository.DeletionTimestamp.IsZero() {
		// Reread quay token
		r.QuayClient = r.BuildQuayClient(log)

		if controllerutil.ContainsFinalizer(imageRepository, ImageRepositoryFinalizer) {
			// Do not block deletion on failures
			r.CleanupImageRepository(ctx, imageRepository)

			controllerutil.RemoveFinalizer(imageRepository, ImageRepositoryFinalizer)
			if err := r.Client.Update(ctx, imageRepository); err != nil {
				log.Error(err, "failed to remove image repository finalizer", l.Action, l.ActionUpdate)
				return ctrl.Result{}, err
			}
			log.Info("Image repository finalizer removed", l.Action, l.ActionDelete)
		}
		return ctrl.Result{}, nil
	}

	if imageRepository.Status.State == imagerepositoryv1beta1.ImageRepositoryStateFailed {
		return ctrl.Result{}, nil
	}

	// Reread quay token
	r.QuayClient = r.BuildQuayClient(log)

	// Provision image repository if it hasn't been done yet
	if !controllerutil.ContainsFinalizer(imageRepository, ImageRepositoryFinalizer) ||
		imageRepository.Status.State != imagerepositoryv1beta1.ImageRepositoryStateReady {
		return ctrl.Result{}, r.ProvisionImageRepository(ctx, imageRepository)
	}

	if imageRepository.Status.State != imagerepositoryv1beta1.ImageRepositoryStateReady {
		return ctrl.Result{}, nil
	}

	// Make sure, that image repository name is the same as on creation.
	// Do it here to avoid webhook creation.
	imageRepositoryName := r.getImageRepositoryNameFromImageUrl(imageRepository.Status.Image.URL)
	if imageRepository.Spec.Image.Name != imageRepositoryName {
		oldName := imageRepository.Spec.Image.Name
		imageRepository.Spec.Image.Name = imageRepositoryName
		if err := r.Client.Update(ctx, imageRepository); err != nil {
			log.Error(err, "failed to revert image repository name", "OldName", oldName, "ExpectedName", imageRepositoryName, l.Action, l.ActionUpdate)
			return ctrl.Result{}, err
		}
		return ctrl.Result{}, nil
	}

	// Change image visibility if requested
	if imageRepository.Spec.Image.Visibility != imageRepository.Status.Image.Visibility && imageRepository.Spec.Image.Visibility != "" {
		if err := r.ChangeImageRepositoryVisibility(ctx, imageRepository); err != nil {
			return ctrl.Result{}, err
		}
		return ctrl.Result{}, nil
	}

	// Rotate credentials if requested
	regenerateToken := imageRepository.Spec.Credentials.RegenerateToken
	if regenerateToken != nil && *regenerateToken {
		if err := r.RegenerateImageRepositoryCredentials(ctx, imageRepository); err != nil {
			return ctrl.Result{}, err
		}
		return ctrl.Result{}, nil
	}

	return ctrl.Result{}, nil
}

func (r *ImageRepositoryReconciler) getImageRepositoryNameFromImageUrl(imageUrl string) string {
	return strings.TrimPrefix(imageUrl, fmt.Sprintf("quay.io/%s/", r.QuayOrganization))
}

// func (r *ImageRepositoryReconciler) waitImageRepositoryState(ctx context.Context, imageRepository *imagerepositoryv1beta1.ImageRepository) (bool, error) {

// }

// ProvisionImageRepository creates image repository, robot account(s) and secret(s) to acces the image repository.
// If labels with Application and Component name are present, robot account with pull only access
// will be created and pull token will be propagated to all environments via Remote Secret.
func (r *ImageRepositoryReconciler) ProvisionImageRepository(ctx context.Context, imageRepository *imagerepositoryv1beta1.ImageRepository) error {
	log := ctrllog.FromContext(ctx).WithName("ImageRepositoryProvision")
	ctx = ctrllog.IntoContext(ctx, log)

	var err error

	status := imageRepository.Status

	// Create image repository
	var quayImageURL string
	imageRepositoryName := ""
	if imageRepository.Status.Image.URL == "" {
		if imageRepository.Spec.Image.Name == "" {
			imageRepositoryName = imageRepository.Namespace + "-" + imageRepository.Name
		} else if !strings.HasPrefix(imageRepository.Spec.Image.Name, imageRepository.Namespace) {
			imageRepositoryName = imageRepository.Namespace + "-" + imageRepository.Spec.Image.Name
		}

		if imageRepository.Spec.Image.Visibility == "" {
			imageRepository.Spec.Image.Visibility = imagerepositoryv1beta1.ImageVisibilityPublic
		}
		visibility := string(imageRepository.Spec.Image.Visibility)

		repository, err := r.QuayClient.CreateRepository(quay.RepositoryRequest{
			Namespace:   r.QuayOrganization,
			Repository:  imageRepositoryName,
			Visibility:  visibility,
			Description: "AppStudio repository for the user",
		})
		if err != nil {
			log.Error(err, "failed to create image repository", l.Action, l.ActionAdd, l.Audit, "true")
			if err.Error() == "payment required" {
				status.State = imagerepositoryv1beta1.ImageRepositoryStateFailed
				status.Message = "Number of private repositories exceeds current quay plan limit"
				imageRepository.Status = status
				if err := r.Client.Status().Update(ctx, imageRepository); err != nil {
					log.Error(err, "failed to update image repository status")
					return err
				}
				return nil
			}
			// Temporary API error, retry
			return err
		}
		if repository == nil {
			err := fmt.Errorf("unexpected response from Quay: created image repository data object is nil")
			log.Error(err, "nil repository")
			return err
		}

		quayImageURL := fmt.Sprintf("quay.io/%s/%s", r.QuayOrganization, repository.Name)
		status.Image.URL = quayImageURL
		status.Image.Visibility = imageRepository.Spec.Image.Visibility

		// Update Spec and Status
		imageRepository.Spec.Image.Name = imageRepositoryName
		controllerutil.AddFinalizer(imageRepository, ImageRepositoryFinalizer)
		if err := r.Client.Update(ctx, imageRepository); err != nil {
			log.Error(err, "failed to update CR after provision")
			return err
		} else {
			log.Info("added image repository finalizer")
		}

		imageRepository.Status = status
		if err := r.Client.Status().Update(ctx, imageRepository); err != nil {
			log.Error(err, "failed to update CR status")
			return err
		}

		// Wait actual state of the image repository to be read.
		imageRepositoryKey := types.NamespacedName{Namespace: imageRepository.Namespace, Name: imageRepository.Name}
		for i := 0; i < 5; i++ {
			if err = r.Client.Get(ctx, imageRepositoryKey, imageRepository); err == nil {
				if controllerutil.ContainsFinalizer(imageRepository, ImageRepositoryFinalizer) && imageRepository.Status.Image.URL != "" {
					break
				}
				// Outdated version of the image repository object, wait more.
			} else {
				if errors.IsNotFound(err) {
					// The image repository was deleted
					break
				}
			}
			time.Sleep(100 * time.Millisecond)
		}

		return nil
	} else {
		quayImageURL = imageRepository.Status.Image.URL
		imageRepositoryName = r.getImageRepositoryNameFromImageUrl(quayImageURL)
	}

	// Create push robot account
	var robotAccount *quay.RobotAccount
	robotAccountName := ""
	if imageRepository.Status.Credentials.PushRobotAccountName == "" {
		robotAccountName = generateQuayRobotAccountName(imageRepositoryName, false)
		robotAccount, err = r.QuayClient.CreateRobotAccount(r.QuayOrganization, robotAccountName)
		if err != nil {
			log.Error(err, "failed to create robot account", "RobotAccountName", robotAccountName, l.Action, l.ActionAdd, l.Audit, "true")
			return err
		}
		if robotAccount == nil {
			err := fmt.Errorf("unexpected response from Quay: robot account data object is nil")
			log.Error(err, "nil robot account")
			return err
		}

		status.Credentials.PushRobotAccountName = robotAccountName
		imageRepository.Status = status
		if err := r.Client.Status().Update(ctx, imageRepository); err != nil {
			log.Error(err, "failed to update CR status with push robot account name")
			return err
		}
	} else {
		robotAccountName = imageRepository.Status.Credentials.PushRobotAccountName
		robotAccount, err = r.QuayClient.GetRobotAccount(r.QuayOrganization, robotAccountName)
		if err != nil {
			log.Error(err, "failed to get push robot account", l.Action, l.ActionView, l.Audit, "true")
			return err
		}
		if robotAccount == nil {
			err := fmt.Errorf("unexpected response from Quay: robot account data object is nil")
			log.Error(err, "nil robot account")
			return err
		}
	}

	if !imageRepository.Status.Credentials.PushRobotAccountPermissionsGranted {
		err = r.QuayClient.AddPermissionsForRepositoryToRobotAccount(r.QuayOrganization, imageRepositoryName, robotAccountName, true)
		if err != nil {
			log.Error(err, "failed to add permissions to robot account", "RobotAccountName", robotAccountName, l.Action, l.ActionUpdate, l.Audit, "true")
			return err
		}

		status.Credentials.PushRobotAccountPermissionsGranted = true
		imageRepository.Status = status
		if err := r.Client.Status().Update(ctx, imageRepository); err != nil {
			log.Error(err, "failed to update CR status with push robot account permissions flag")
			return err
		}
	}

	secretName := strings.ReplaceAll(robotAccountName, "_", "-")
	if err := r.EnsureDockerSecret(ctx, imageRepository, robotAccount, secretName, quayImageURL); err != nil {
		log.Error(err, "failed to ensure push secret")
		return err
	} else if imageRepository.Status.Credentials.PushSecretName == "" {
		status.Credentials.PushSecretName = secretName
		imageRepository.Status = status
		if err := r.Client.Status().Update(ctx, imageRepository); err != nil {
			log.Error(err, "failed to update CR status with push secret name")
			return err
		}
	}

	if isComponentLinked(imageRepository) {
		// Pull secret provision and propagation
		var pullRobotAccount *quay.RobotAccount
		pullRobotAccountName := ""
		if imageRepository.Status.Credentials.PullRobotAccountName == "" {
			pullRobotAccountName = generateQuayRobotAccountName(imageRepositoryName, true)
			pullRobotAccount, err = r.QuayClient.CreateRobotAccount(r.QuayOrganization, pullRobotAccountName)
			if err != nil {
				log.Error(err, "failed to create pull robot account", "RobotAccountName", pullRobotAccountName, l.Action, l.ActionAdd, l.Audit, "true")
				return err
			}
			if robotAccount == nil {
				err := fmt.Errorf("unexpected response from Quay: pull robot account data object is nil")
				log.Error(err, "nil pull robot account")
				return err
			}

			status.Credentials.PullRobotAccountName = pullRobotAccountName
			imageRepository.Status = status
			if err := r.Client.Status().Update(ctx, imageRepository); err != nil {
				log.Error(err, "failed to update CR status with pull robot account name")
				return err
			}
		} else {
			pullRobotAccountName = imageRepository.Status.Credentials.PullRobotAccountName
			pullRobotAccount, err = r.QuayClient.GetRobotAccount(r.QuayOrganization, pullRobotAccountName)
			if err != nil {
				log.Error(err, "failed to get pull robot account", l.Action, l.ActionView, l.Audit, "true")
				return err
			}
			if pullRobotAccount == nil {
				err := fmt.Errorf("unexpected response from Quay: robot account data object is nil")
				log.Error(err, "nil robot account")
				return err
			}
		}

		if !imageRepository.Status.Credentials.PullRobotAccountPermissionsGranted {
			err = r.QuayClient.AddPermissionsForRepositoryToRobotAccount(r.QuayOrganization, imageRepositoryName, pullRobotAccount.Name, false)
			if err != nil {
				log.Error(err, "failed to add permissions to pull robot account", "RobotAccountName", robotAccountName, l.Action, l.ActionUpdate, l.Audit, "true")
				return err
			}

			status.Credentials.PullRobotAccountPermissionsGranted = true
			imageRepository.Status = status
			if err := r.Client.Status().Update(ctx, imageRepository); err != nil {
				log.Error(err, "failed to update CR status will pull robot account permissions flag")
				return err
			}
		}

		remoteSecretName := getRemoteSecretName(imageRepository)
		if err := r.EnsureRemotePullSecret(ctx, imageRepository, remoteSecretName); err != nil {
			return err
		}
		if err := r.CreateRemotePullSecretUploadSecret(ctx, pullRobotAccount, imageRepository.Namespace, remoteSecretName, quayImageURL); err != nil {
			return err
		}
		if imageRepository.Status.Credentials.PullSecretName == "" {
			status.Credentials.PullSecretName = remoteSecretName
			imageRepository.Status = status
			if err := r.Client.Status().Update(ctx, imageRepository); err != nil {
				log.Error(err, "failed to update CR status with pull secret name")
				return err
			}
		}
	}

	status.State = imagerepositoryv1beta1.ImageRepositoryStateReady
	status.Credentials.GenerationTimestamp = &metav1.Time{Time: time.Now()}
	imageRepository.Status = status
	if err := r.Client.Status().Update(ctx, imageRepository); err != nil {
		log.Error(err, "failed to update CR status to ready state")
		return err
	}
	log.Info("successfully provisioned image repository")

	// Wait actual state of the image repository to be read.
	imageRepositoryKey := types.NamespacedName{Namespace: imageRepository.Namespace, Name: imageRepository.Name}
	for i := 0; i < 5; i++ {
		if err = r.Client.Get(ctx, imageRepositoryKey, imageRepository); err == nil {
			if imageRepository.Status.State != "" {
				break
			}
			// Outdated version of the image repository object, wait more.
		} else {
			if errors.IsNotFound(err) {
				// The image repository was deleted
				break
			}
		}
		time.Sleep(100 * time.Millisecond)
	}

	return nil
}

// RegenerateImageRepositoryCredentials rotates robot account(s) token and updates corresponding secret(s)
func (r *ImageRepositoryReconciler) RegenerateImageRepositoryCredentials(ctx context.Context, imageRepository *imagerepositoryv1beta1.ImageRepository) error {
	log := ctrllog.FromContext(ctx)

	quayImageURL := imageRepository.Status.Image.URL
	robotAccountName := imageRepository.Status.Credentials.PushRobotAccountName

	robotAccount, err := r.QuayClient.RegenerateRobotAccountToken(r.QuayOrganization, robotAccountName)
	if err != nil {
		log.Error(err, "failed to refresh push token")
		return err
	}
	secretName := strings.ReplaceAll(robotAccountName, "_", "-")
	if err := r.EnsureDockerSecret(ctx, imageRepository, robotAccount, secretName, quayImageURL); err != nil {
		return err
	}
	log.Info("Regenerated push token", "RobotAccountName", robotAccountName)

	if isComponentLinked(imageRepository) {
		pullRobotAccountName := imageRepository.Status.Credentials.PullRobotAccountName
		pullRobotAccount, err := r.QuayClient.RegenerateRobotAccountToken(r.QuayOrganization, pullRobotAccountName)
		if err != nil {
			log.Error(err, "failed to refresh pull token")
			return err
		}

		remoteSecretName := getRemoteSecretName(imageRepository)
		if err := r.CreateRemotePullSecretUploadSecret(ctx, pullRobotAccount, imageRepository.Namespace, remoteSecretName, quayImageURL); err != nil {
			return err
		}
		log.Info("Regenerated pull token", "RobotAccountName", pullRobotAccountName)
	}

	imageRepository.Spec.Credentials.RegenerateToken = nil
	if err := r.Client.Update(ctx, imageRepository); err != nil {
		log.Error(err, "failed to update image repository", l.Action, l.ActionUpdate)
		return err
	}

	imageRepository.Status.Credentials.GenerationTimestamp = &metav1.Time{Time: time.Now()}
	if err := r.Client.Status().Update(ctx, imageRepository); err != nil {
		log.Error(err, "failed to update image repository status", l.Action, l.ActionUpdate)
		return err
	}

	return nil
}

// CleanupImageRepository deletes image repository and corresponding robot account(s).
func (r *ImageRepositoryReconciler) CleanupImageRepository(ctx context.Context, imageRepository *imagerepositoryv1beta1.ImageRepository) {
	log := ctrllog.FromContext(ctx).WithName("RepositoryCleanup")

	robotAccountName := imageRepository.Status.Credentials.PushRobotAccountName
	if robotAccountName != "" {
		isRobotAccountDeleted, err := r.QuayClient.DeleteRobotAccount(r.QuayOrganization, robotAccountName)
		if err != nil {
			log.Error(err, "failed to delete push robot account", l.Action, l.ActionDelete, l.Audit, "true")
		}
		if isRobotAccountDeleted {
			log.Info("Deleted push robot account", "RobotAccountName", robotAccountName, l.Action, l.ActionDelete)
		}
	}

	if isComponentLinked(imageRepository) {
		pullRobotAccountName := imageRepository.Status.Credentials.PullRobotAccountName
		if pullRobotAccountName != "" {
			isPullRobotAccountDeleted, err := r.QuayClient.DeleteRobotAccount(r.QuayOrganization, pullRobotAccountName)
			if err != nil {
				log.Error(err, "failed to delete pull robot account", l.Action, l.ActionDelete, l.Audit, "true")
			}
			if isPullRobotAccountDeleted {
				log.Info("Deleted pull robot account", "RobotAccountName", pullRobotAccountName, l.Action, l.ActionDelete)
			}
		}
	}

	imageRepositoryName := imageRepository.Spec.Image.Name
	isImageRepositoryDeleted, err := r.QuayClient.DeleteRepository(r.QuayOrganization, imageRepositoryName)
	if err != nil {
		log.Error(err, "failed to delete image repository", l.Action, l.ActionDelete, l.Audit, "true")
	}
	if isImageRepositoryDeleted {
		log.Info("Deleted image repository", "ImageRepository", imageRepositoryName, l.Action, l.ActionDelete)
	}
}

func (r *ImageRepositoryReconciler) ChangeImageRepositoryVisibility(ctx context.Context, imageRepository *imagerepositoryv1beta1.ImageRepository) error {
	if imageRepository.Status.Image.Visibility == imageRepository.Spec.Image.Visibility {
		return nil
	}

	log := ctrllog.FromContext(ctx)

	imageRepositoryName := imageRepository.Spec.Image.Name
	requestedVisibility := string(imageRepository.Spec.Image.Visibility)
	err := r.QuayClient.ChangeRepositoryVisibility(r.QuayOrganization, imageRepositoryName, requestedVisibility)
	if err == nil {
		imageRepository.Status.Image.Visibility = imageRepository.Spec.Image.Visibility
		imageRepository.Status.Message = ""
		if err := r.Client.Status().Update(ctx, imageRepository); err != nil {
			log.Error(err, "failed to update image repository name", l.Action, l.ActionUpdate)
			return err
		}
		return nil
	}

	if err.Error() == "payment required" {
		log.Info("failed to make image repository private due to quay plan limit", l.Audit, "true")

		imageRepository.Spec.Image.Visibility = imageRepository.Status.Image.Visibility
		if err := r.Client.Update(ctx, imageRepository); err != nil {
			log.Error(err, "failed to update image repository", l.Action, l.ActionUpdate)
			return err
		}

		imageRepository.Status.Message = "Quay organization plan private repositories limit exceeded"
		if err := r.Client.Status().Update(ctx, imageRepository); err != nil {
			log.Error(err, "failed to update image repository", l.Action, l.ActionUpdate)
			return err
		}

		// Do not trigger a new reconcile since the error handled
		return nil
	}

	log.Error(err, "failed to change image repository visibility")
	return err
}

// EnsureDockerSecret makes sure that secret for given robot account exists and contains up to date credentials.
func (r *ImageRepositoryReconciler) EnsureDockerSecret(ctx context.Context, imageRepository *imagerepositoryv1beta1.ImageRepository, robotAccount *quay.RobotAccount, secretName, imageURL string) error {
	log := ctrllog.FromContext(ctx).WithValues("SecretName", secretName)

	secretKey := types.NamespacedName{Namespace: imageRepository.Namespace, Name: secretName}
	secret := &corev1.Secret{}
	if err := r.Client.Get(ctx, secretKey, secret); err != nil {
		if !errors.IsNotFound(err) {
			log.Error(err, "failed to get push secret", l.Action, l.ActionView)
			return err
		}
		// Cretate secret
		secret = &corev1.Secret{
			ObjectMeta: metav1.ObjectMeta{
				Name:      secretName,
				Namespace: imageRepository.Namespace,
			},
			Type:       corev1.SecretTypeDockerConfigJson,
			StringData: generateDockerconfigSecretData(imageURL, robotAccount),
		}
		if err := controllerutil.SetOwnerReference(imageRepository, secret, r.Scheme); err != nil {
			log.Error(err, "failed to set owner for remote secret")
			return err
		}

		if err := r.Client.Create(ctx, secret); err != nil {
			log.Error(err, "failed to create secret", l.Action, l.ActionAdd)
			return err
		}
	} else {
		// Update the secret
		secret.StringData = generateDockerconfigSecretData(imageURL, robotAccount)
		if err := r.Client.Update(ctx, secret); err != nil {
			log.Error(err, "failed to update secret", l.Action, l.ActionUpdate)
			return err
		}
	}

	return nil
}

func (r *ImageRepositoryReconciler) EnsureRemotePullSecret(ctx context.Context, imageRepository *imagerepositoryv1beta1.ImageRepository, remoteSecretName string) error {
	log := ctrllog.FromContext(ctx).WithValues("RemoteSecretName", remoteSecretName)

	remoteSecret := &remotesecretv1beta1.RemoteSecret{}
	remoteSecretKey := types.NamespacedName{Namespace: imageRepository.Namespace, Name: remoteSecretName}
	if err := r.Client.Get(ctx, remoteSecretKey, remoteSecret); err != nil {
		if !errors.IsNotFound(err) {
			log.Error(err, "failed to get remote secret", l.Action, l.ActionView)
			return err
		}

		remoteSecret := &remotesecretv1beta1.RemoteSecret{
			ObjectMeta: metav1.ObjectMeta{
				Name:      remoteSecretName,
				Namespace: imageRepository.Namespace,
				Labels: map[string]string{
					ApplicationNameLabelName: imageRepository.Labels[ApplicationNameLabelName],
					ComponentNameLabelName:   imageRepository.Labels[ComponentNameLabelName],
				},
			},
			Spec: remotesecretv1beta1.RemoteSecretSpec{
				Secret: remotesecretv1beta1.LinkableSecretSpec{
					Name: remoteSecretName,
					Type: corev1.SecretTypeDockerConfigJson,
					LinkedTo: []remotesecretv1beta1.SecretLink{
						{
							ServiceAccount: remotesecretv1beta1.ServiceAccountLink{
								Reference: corev1.LocalObjectReference{
									Name: defaultServiceAccountName,
								},
							},
						},
					},
				},
			},
		}
		if err := controllerutil.SetOwnerReference(imageRepository, remoteSecret, r.Scheme); err != nil {
			log.Error(err, "failed to set owner for remote secret")
			return err
		}

		if err := r.Client.Create(ctx, remoteSecret); err != nil {
			log.Error(err, "failed to create remote secret", l.Action, l.ActionAdd, l.Audit, "true")
			return err
		}
	}

	return nil
}

// CreateRemotePullSecretUploadSecret propagates credentials from given robot account to corresponding remote secret.
func (r *ImageRepositoryReconciler) CreateRemotePullSecretUploadSecret(ctx context.Context, robotAccount *quay.RobotAccount, namespace, remoteSecretName, imageURL string) error {
	uploadSecretName := "upload-secret-" + remoteSecretName
	log := ctrllog.FromContext(ctx).WithValues("RemoteSecretName", remoteSecretName).WithValues("UploadSecretName", uploadSecretName)

	uploadSecret := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:      uploadSecretName,
			Namespace: namespace,
			Labels: map[string]string{
				remotesecretv1beta1.UploadSecretLabel: "remotesecret",
			},
			Annotations: map[string]string{
				remotesecretv1beta1.RemoteSecretNameAnnotation: remoteSecretName,
			},
		},
		StringData: generateDockerconfigSecretData(imageURL, robotAccount),
	}
	if err := r.Client.Create(ctx, uploadSecret); err != nil {
		log.Error(err, "failed to create upload secret", l.Action, l.ActionAdd, l.Audit, "true")
		return err
	}

	return nil
}

// generateQuayRobotAccountName generates valid robot account name for given image repository name.
func generateQuayRobotAccountName(imageRepositoryName string, isPullOnly bool) string {
	// Robot account name must match ^[a-z][a-z0-9_]{1,254}$

	imageNamePrefix := imageRepositoryName
	if len(imageNamePrefix) > 220 {
		imageNamePrefix = imageNamePrefix[:220]
	}
	imageNamePrefix = strings.ReplaceAll(imageNamePrefix, "/", "_")
	imageNamePrefix = strings.ReplaceAll(imageNamePrefix, ".", "_")
	imageNamePrefix = strings.ReplaceAll(imageNamePrefix, "-", "_")

	randomSuffix := getRandomString(10)

	robotAccountName := fmt.Sprintf("%s_%s", imageNamePrefix, randomSuffix)
	if isPullOnly {
		robotAccountName += "_pull"
	}
	return robotAccountName
}

func getRemoteSecretName(imageRepository *imagerepositoryv1beta1.ImageRepository) string {
	componentName := imageRepository.Labels[ComponentNameLabelName]
	if len(componentName) > 220 {
		componentName = componentName[:220]
	}
	return componentName + "-image-pull"
}

func isComponentLinked(imageRepository *imagerepositoryv1beta1.ImageRepository) bool {
	return imageRepository.Labels[ApplicationNameLabelName] != "" && imageRepository.Labels[ComponentNameLabelName] != ""
}

func getRandomString(length int) string {
	bytes := make([]byte, length/2+1)
	if _, err := rand.Read(bytes); err != nil {
		panic("Failed to read from random generator")
	}
	return hex.EncodeToString(bytes)[0:length]
}
