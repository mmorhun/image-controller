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
	"encoding/base64"
	"encoding/json"
	"fmt"
	"regexp"
	"strconv"
	"strings"
	"time"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	"github.com/redhat-appstudio/image-controller/pkg/quay"
	remotesecretv1beta1 "github.com/redhat-appstudio/remote-secret/api/v1beta1"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/types"

	imagerepositoryv1beta1 "github.com/redhat-appstudio/image-controller/api/v1beta1"
)

var _ = Describe("Image repository controller", func() {

	var (
		authRegexp = regexp.MustCompile(`.*{"auth":"([A-Za-z0-9+/=]*)"}.*`)

		resourceKey = types.NamespacedName{Name: defaultImageRepositoryName, Namespace: defaultNamespace}

		pushToken                  string
		pullToken                  string
		expectedRobotAccountPrefix string
		expectedRemoteSecretName   string
		expectedImageName          string
		expectedImage              string
	)

	Context("Image repository provision", func() {

		It("should prepare environment", func() {
			createNamespace(defaultNamespace)

			pushToken = "push-token1234"
			expectedImageName = fmt.Sprintf("%s-%s", defaultNamespace, defaultImageRepositoryName)
			expectedImage = fmt.Sprintf("quay.io/%s/%s", testQuayOrg, expectedImageName)
			expectedRobotAccountPrefix = strings.ReplaceAll(expectedImageName, "-", "_")
		})

		It("should provision image repository", func() {
			ResetTestQuayClientToFails()

			isCreateRepositoryInvoked := false
			CreateRepositoryFunc = func(repository quay.RepositoryRequest) (*quay.Repository, error) {
				defer GinkgoRecover()
				isCreateRepositoryInvoked = true
				Expect(repository.Repository).To(Equal(expectedImageName))
				Expect(repository.Namespace).To(Equal(testQuayOrg))
				Expect(repository.Visibility).To(Equal("public"))
				Expect(repository.Description).ToNot(BeEmpty())
				return &quay.Repository{Name: expectedImageName}, nil
			}
			isCreateRobotAccountInvoked := false
			CreateRobotAccountFunc = func(organization, robotName string) (*quay.RobotAccount, error) {
				defer GinkgoRecover()
				isCreateRobotAccountInvoked = true
				Expect(organization).To(Equal(testQuayOrg))
				Expect(robotName).To(HavePrefix(expectedRobotAccountPrefix))
				return &quay.RobotAccount{Name: robotName, Token: pushToken}, nil
			}
			isAddPushPermissionsToRobotAccountInvoked := false
			AddPermissionsForRepositoryToRobotAccountFunc = func(organization, imageRepository, robotAccountName string, isWrite bool) error {
				defer GinkgoRecover()
				isAddPushPermissionsToRobotAccountInvoked = true
				Expect(organization).To(Equal(testQuayOrg))
				Expect(imageRepository).To(Equal(expectedImageName))
				Expect(isWrite).To(BeTrue())
				Expect(robotAccountName).To(HavePrefix(expectedRobotAccountPrefix))
				return nil
			}

			createImageRepository(imageRepositoryConfig{})

			Eventually(func() bool { return isCreateRepositoryInvoked }, timeout, interval).Should(BeTrue())
			Eventually(func() bool { return isCreateRobotAccountInvoked }, timeout, interval).Should(BeTrue())
			Eventually(func() bool { return isAddPushPermissionsToRobotAccountInvoked }, timeout, interval).Should(BeTrue())

			waitImageRepositoryFinalizerOnImageRepository(resourceKey)
			waitImageRepositoryStatus(resourceKey)

			imageRepository := getImageRepository(resourceKey)

			Expect(imageRepository.Spec.Image.Name).To(Equal(expectedImageName))
			Expect(imageRepository.Spec.Image.Visibility).To(Equal(imagerepositoryv1beta1.ImageVisibilityPublic))
			Expect(imageRepository.Status.State).To(Equal(imagerepositoryv1beta1.ImageRepositoryStateReady))
			Expect(imageRepository.Status.Message).To(BeEmpty())
			Expect(imageRepository.Status.Image.URL).To(Equal(expectedImage))
			Expect(imageRepository.Status.Image.Visibility).To(Equal(imagerepositoryv1beta1.ImageVisibilityPublic))
			Expect(imageRepository.Status.Credentials.PushRobotAccountName).To(HavePrefix(expectedRobotAccountPrefix))
			Expect(imageRepository.Status.Credentials.PushSecretName).To(HavePrefix(expectedImageName))
			Expect(imageRepository.Status.Credentials.GenerationTimestamp).ToNot(BeNil())

			secret := &corev1.Secret{}
			secretName := imageRepository.Status.Credentials.PushSecretName
			secretKey := types.NamespacedName{Name: secretName, Namespace: defaultNamespace}
			waitSecretExist(secretKey)
			Expect(k8sClient.Get(ctx, secretKey, secret)).To(Succeed())
			dockerconfigJson := string(secret.Data[corev1.DockerConfigJsonKey])
			var authDataJson interface{}
			Expect(json.Unmarshal([]byte(dockerconfigJson), &authDataJson)).To(Succeed())
			Expect(dockerconfigJson).To(ContainSubstring(expectedImage))
			authString, err := base64.StdEncoding.DecodeString(authRegexp.FindStringSubmatch(dockerconfigJson)[1])
			Expect(err).To(Succeed())
			pushRobotAccountName := imageRepository.Status.Credentials.PushRobotAccountName
			Expect(string(authString)).To(Equal(fmt.Sprintf("%s:%s", pushRobotAccountName, pushToken)))

		})

		It("should regenerate token", func() {
			newToken := "push-token5678"

			ResetTestQuayClientToFails()
			// Wait just for case it takes less than a second to regenerate credentials
			time.Sleep(time.Second)

			isRegenerateRobotAccountTokenInvoked := false
			RegenerateRobotAccountTokenFunc = func(organization, robotName string) (*quay.RobotAccount, error) {
				defer GinkgoRecover()
				isRegenerateRobotAccountTokenInvoked = true
				Expect(organization).To(Equal(testQuayOrg))
				Expect(robotName).To(HavePrefix(expectedRobotAccountPrefix))
				return &quay.RobotAccount{Name: robotName, Token: newToken}, nil
			}

			imageRepository := getImageRepository(resourceKey)
			oldTokenGenerationTimestamp := *imageRepository.Status.Credentials.GenerationTimestamp
			regenerateToken := true
			imageRepository.Spec.Credentials.RegenerateToken = &regenerateToken
			Expect(k8sClient.Update(ctx, imageRepository)).To(Succeed())

			Eventually(func() bool { return isRegenerateRobotAccountTokenInvoked }, timeout, interval).Should(BeTrue())
			Eventually(func() bool {
				imageRepository := getImageRepository(resourceKey)
				return imageRepository.Spec.Credentials.RegenerateToken == nil &&
					imageRepository.Status.Credentials.GenerationTimestamp != nil &&
					*imageRepository.Status.Credentials.GenerationTimestamp != oldTokenGenerationTimestamp
			}, timeout, interval).Should(BeTrue())

			secret := &corev1.Secret{}
			secretName := imageRepository.Status.Credentials.PushSecretName
			secretKey := types.NamespacedName{Name: secretName, Namespace: defaultNamespace}
			Expect(k8sClient.Get(ctx, secretKey, secret)).To(Succeed())
			dockerconfigJson := string(secret.Data[corev1.DockerConfigJsonKey])
			var authDataJson interface{}
			Expect(json.Unmarshal([]byte(dockerconfigJson), &authDataJson)).To(Succeed())
			Expect(dockerconfigJson).To(ContainSubstring(expectedImage))
			authString, err := base64.StdEncoding.DecodeString(authRegexp.FindStringSubmatch(dockerconfigJson)[1])
			Expect(err).To(Succeed())
			Expect(string(authString)).To(HavePrefix(expectedRobotAccountPrefix))
			Expect(string(authString)).To(HaveSuffix(newToken))
		})

		It("should update image visibility", func() {
			ResetTestQuayClientToFails()

			isChangeRepositoryVisibilityInvoked := false
			ChangeRepositoryVisibilityFunc = func(organization, imageRepository, visibility string) error {
				defer GinkgoRecover()
				isChangeRepositoryVisibilityInvoked = true
				Expect(organization).To(Equal(testQuayOrg))
				Expect(imageRepository).To(Equal(expectedImageName))
				Expect(visibility).To(Equal(string(imagerepositoryv1beta1.ImageVisibilityPrivate)))
				return nil
			}

			imageRepository := getImageRepository(resourceKey)
			imageRepository.Spec.Image.Visibility = imagerepositoryv1beta1.ImageVisibilityPrivate
			Expect(k8sClient.Update(ctx, imageRepository)).To(Succeed())

			Eventually(func() bool { return isChangeRepositoryVisibilityInvoked }, timeout, interval).Should(BeTrue())
			Eventually(func() bool {
				imageRepository := getImageRepository(resourceKey)
				return imageRepository.Spec.Image.Visibility == imagerepositoryv1beta1.ImageVisibilityPrivate &&
					imageRepository.Status.Image.Visibility == imagerepositoryv1beta1.ImageVisibilityPrivate &&
					imageRepository.Status.Message == ""
			}, timeout, interval).Should(BeTrue())
		})

		It("should revert image name if edited", func() {
			ResetTestQuayClientToFails()

			imageRepository := getImageRepository(resourceKey)
			imageRepository.Spec.Image.Name = "renamed"
			Expect(k8sClient.Update(ctx, imageRepository)).To(Succeed())

			Eventually(func() bool {
				imageRepository := getImageRepository(resourceKey)
				return imageRepository.Spec.Image.Name == expectedImageName
			}, timeout, interval).Should(BeTrue())
		})

		It("should cleanup repository", func() {
			ResetTestQuayClientToFails()

			isDeleteRobotAccountInvoked := false
			DeleteRobotAccountFunc = func(organization, robotAccountName string) (bool, error) {
				defer GinkgoRecover()
				isDeleteRobotAccountInvoked = true
				Expect(organization).To(Equal(testQuayOrg))
				Expect(robotAccountName).To(HavePrefix(expectedRobotAccountPrefix))
				return true, nil
			}
			isDeleteRepositoryInvoked := false
			DeleteRepositoryFunc = func(organization, imageRepository string) (bool, error) {
				defer GinkgoRecover()
				isDeleteRepositoryInvoked = true
				Expect(organization).To(Equal(testQuayOrg))
				Expect(imageRepository).To(Equal(expectedImageName))
				return true, nil
			}

			deleteImageRepository(resourceKey)

			Eventually(func() bool { return isDeleteRobotAccountInvoked }, timeout, interval).Should(BeTrue())
			Eventually(func() bool { return isDeleteRepositoryInvoked }, timeout, interval).Should(BeTrue())
		})
	})

	Context("Image repository for component provision", func() {

		It("should prepare environment", func() {
			pushToken = "push-token1234"
			pullToken = "pull-token1234"
			expectedImageName = fmt.Sprintf("%s-%s/%s", defaultNamespace, defaultComponentApplication, defaultComponentName)
			expectedImage = fmt.Sprintf("quay.io/%s/%s", testQuayOrg, expectedImageName)
			expectedRobotAccountPrefix = strings.ReplaceAll(strings.ReplaceAll(expectedImageName, "-", "_"), "/", "_")
			expectedRemoteSecretName = defaultComponentName + "-image-pull"
		})

		It("should provision image repository for component", func() {
			ResetTestQuayClientToFails()

			isCreateRepositoryInvoked := false
			CreateRepositoryFunc = func(repository quay.RepositoryRequest) (*quay.Repository, error) {
				defer GinkgoRecover()
				isCreateRepositoryInvoked = true
				Expect(repository.Repository).To(Equal(expectedImageName))
				Expect(repository.Namespace).To(Equal(testQuayOrg))
				Expect(repository.Visibility).To(Equal("public"))
				Expect(repository.Description).ToNot(BeEmpty())
				return &quay.Repository{Name: expectedImageName}, nil
			}
			isCreatePushRobotAccountInvoked := false
			isCreatePullRobotAccountInvoked := false
			CreateRobotAccountFunc = func(organization, robotName string) (*quay.RobotAccount, error) {
				defer GinkgoRecover()
				Expect(organization).To(Equal(testQuayOrg))
				Expect(robotName).To(HavePrefix(expectedRobotAccountPrefix))
				if strings.HasSuffix(robotName, "_pull") {
					isCreatePullRobotAccountInvoked = true
					return &quay.RobotAccount{Name: robotName, Token: pullToken}, nil
				}
				isCreatePushRobotAccountInvoked = true
				return &quay.RobotAccount{Name: robotName, Token: pushToken}, nil
			}
			isAddPushPermissionsToRobotAccountInvoked := false
			isAddPullPermissionsToRobotAccountInvoked := false
			AddPermissionsForRepositoryToRobotAccountFunc = func(organization, imageRepository, robotAccountName string, isWrite bool) error {
				defer GinkgoRecover()
				Expect(organization).To(Equal(testQuayOrg))
				Expect(imageRepository).To(Equal(expectedImageName))
				Expect(robotAccountName).To(HavePrefix(expectedRobotAccountPrefix))
				if strings.HasSuffix(robotAccountName, "_pull") {
					Expect(isWrite).To(BeFalse())
					isAddPullPermissionsToRobotAccountInvoked = true
				} else {
					Expect(isWrite).To(BeTrue())
					isAddPushPermissionsToRobotAccountInvoked = true
				}
				return nil
			}

			createImageRepository(imageRepositoryConfig{
				ResourceKey: &resourceKey,
				ImageName:   fmt.Sprintf("%s/%s", defaultComponentApplication, defaultComponentName),
				Labels: map[string]string{
					ApplicationNameLabelName: defaultComponentApplication,
					ComponentNameLabelName:   defaultComponentName,
				},
			})

			Eventually(func() bool { return isCreateRepositoryInvoked }, timeout, interval).Should(BeTrue())
			Eventually(func() bool { return isCreatePushRobotAccountInvoked }, timeout, interval).Should(BeTrue())
			Eventually(func() bool { return isCreatePullRobotAccountInvoked }, timeout, interval).Should(BeTrue())
			Eventually(func() bool { return isAddPushPermissionsToRobotAccountInvoked }, timeout, interval).Should(BeTrue())
			Eventually(func() bool { return isAddPullPermissionsToRobotAccountInvoked }, timeout, interval).Should(BeTrue())

			waitImageRepositoryFinalizerOnImageRepository(resourceKey)
			waitImageRepositoryStatus(resourceKey)

			imageRepository := getImageRepository(resourceKey)
			Expect(imageRepository.Spec.Image.Name).To(Equal(expectedImageName))
			Expect(imageRepository.Spec.Image.Visibility).To(Equal(imagerepositoryv1beta1.ImageVisibilityPublic))
			Expect(imageRepository.Status.State).To(Equal(imagerepositoryv1beta1.ImageRepositoryStateReady))
			Expect(imageRepository.Status.Message).To(BeEmpty())
			Expect(imageRepository.Status.Image.URL).To(Equal(expectedImage))
			Expect(imageRepository.Status.Image.Visibility).To(Equal(imagerepositoryv1beta1.ImageVisibilityPublic))
			Expect(imageRepository.Status.Credentials.PushRobotAccountName).To(HavePrefix(expectedRobotAccountPrefix))
			Expect(imageRepository.Status.Credentials.PushSecretName).To(HavePrefix(strings.ReplaceAll(expectedImageName, "/", "-")))
			Expect(imageRepository.Status.Credentials.PullRobotAccountName).To(HavePrefix(expectedRobotAccountPrefix))
			Expect(imageRepository.Status.Credentials.PullRobotAccountName).To(HaveSuffix("_pull"))
			Expect(imageRepository.Status.Credentials.PullSecretName).To(Equal(expectedRemoteSecretName))
			Expect(imageRepository.Status.Credentials.GenerationTimestamp).ToNot(BeNil())

			var authDataJson interface{}
			secret := &corev1.Secret{}
			secretName := imageRepository.Status.Credentials.PushSecretName
			secretKey := types.NamespacedName{Name: secretName, Namespace: defaultNamespace}
			waitSecretExist(secretKey)
			Expect(k8sClient.Get(ctx, secretKey, secret)).To(Succeed())
			dockerconfigJson := string(secret.Data[corev1.DockerConfigJsonKey])
			Expect(json.Unmarshal([]byte(dockerconfigJson), &authDataJson)).To(Succeed())
			Expect(dockerconfigJson).To(ContainSubstring(expectedImage))
			authString, err := base64.StdEncoding.DecodeString(authRegexp.FindStringSubmatch(dockerconfigJson)[1])
			Expect(err).To(Succeed())
			pushRobotAccountName := imageRepository.Status.Credentials.PushRobotAccountName
			Expect(string(authString)).To(Equal(fmt.Sprintf("%s:%s", pushRobotAccountName, pushToken)))

			remoteSecretKey := types.NamespacedName{Name: expectedRemoteSecretName, Namespace: defaultNamespace}
			remoteSecret := waitRemoteSecretExist(remoteSecretKey)
			Expect(remoteSecret.Labels[ApplicationNameLabelName]).To(Equal(defaultComponentApplication))
			Expect(remoteSecret.Labels[ComponentNameLabelName]).To(Equal(defaultComponentName))
			Expect(remoteSecret.OwnerReferences).To(HaveLen(1))
			Expect(remoteSecret.OwnerReferences[0].Name).To(Equal(imageRepository.Name))
			Expect(remoteSecret.OwnerReferences[0].Kind).To(Equal("ImageRepository"))
			Expect(remoteSecret.Spec.Secret.Name).To(Equal(remoteSecretKey.Name))
			Expect(remoteSecret.Spec.Secret.Type).To(Equal(corev1.SecretTypeDockerConfigJson))
			Expect(remoteSecret.Spec.Secret.LinkedTo).To(HaveLen(1))
			Expect(remoteSecret.Spec.Secret.LinkedTo[0].ServiceAccount.Reference.Name).To(Equal(defaultServiceAccountName))

			uploadSecretKey := types.NamespacedName{Name: "upload-secret-" + expectedRemoteSecretName, Namespace: defaultNamespace}
			uploadSecret := waitSecretExist(uploadSecretKey)
			defer deleteSecret(uploadSecretKey)
			Expect(uploadSecret.Labels[remotesecretv1beta1.UploadSecretLabel]).To(Equal("remotesecret"))
			Expect(uploadSecret.Annotations[remotesecretv1beta1.RemoteSecretNameAnnotation]).To(Equal(expectedRemoteSecretName))
			uploadSecretDockerconfigJson := string(uploadSecret.Data[corev1.DockerConfigJsonKey])
			Expect(json.Unmarshal([]byte(uploadSecretDockerconfigJson), &authDataJson)).To(Succeed())
			Expect(uploadSecretDockerconfigJson).To(ContainSubstring(expectedImage))
			uploadSecretAuthString, err := base64.StdEncoding.DecodeString(authRegexp.FindStringSubmatch(uploadSecretDockerconfigJson)[1])
			Expect(err).To(Succeed())
			pullRobotAccountName := imageRepository.Status.Credentials.PullRobotAccountName
			Expect(string(uploadSecretAuthString)).To(Equal(fmt.Sprintf("%s:%s", pullRobotAccountName, pullToken)))
		})

		It("should regenerate tokens and update remote secret", func() {
			newPushToken := "push-token5678"
			newPullToken := "pull-token5678"

			ResetTestQuayClientToFails()
			// Wait just for case it takes less than a second to regenerate credentials
			time.Sleep(time.Second)

			isRegenerateRobotAccountTokenForPushInvoked := false
			isRegenerateRobotAccountTokenForPullInvoked := false
			RegenerateRobotAccountTokenFunc = func(organization, robotName string) (*quay.RobotAccount, error) {
				defer GinkgoRecover()
				Expect(organization).To(Equal(testQuayOrg))
				Expect(robotName).To(HavePrefix(expectedRobotAccountPrefix))
				if strings.HasSuffix(robotName, "_pull") {
					isRegenerateRobotAccountTokenForPullInvoked = true
					return &quay.RobotAccount{Name: robotName, Token: newPullToken}, nil
				}
				isRegenerateRobotAccountTokenForPushInvoked = true
				return &quay.RobotAccount{Name: robotName, Token: newPushToken}, nil
			}

			imageRepository := getImageRepository(resourceKey)
			oldTokenGenerationTimestamp := *imageRepository.Status.Credentials.GenerationTimestamp
			regenerateToken := true
			imageRepository.Spec.Credentials.RegenerateToken = &regenerateToken
			Expect(k8sClient.Update(ctx, imageRepository)).To(Succeed())

			Eventually(func() bool { return isRegenerateRobotAccountTokenForPushInvoked }, timeout, interval).Should(BeTrue())
			Eventually(func() bool { return isRegenerateRobotAccountTokenForPullInvoked }, timeout, interval).Should(BeTrue())
			Eventually(func() bool {
				imageRepository := getImageRepository(resourceKey)
				return imageRepository.Spec.Credentials.RegenerateToken == nil &&
					imageRepository.Status.Credentials.GenerationTimestamp != nil &&
					*imageRepository.Status.Credentials.GenerationTimestamp != oldTokenGenerationTimestamp
			}, timeout, interval).Should(BeTrue())

			secret := &corev1.Secret{}
			secretName := imageRepository.Status.Credentials.PushSecretName
			secretKey := types.NamespacedName{Name: secretName, Namespace: defaultNamespace}
			Expect(k8sClient.Get(ctx, secretKey, secret)).To(Succeed())
			dockerconfigJson := string(secret.Data[corev1.DockerConfigJsonKey])
			var authDataJson interface{}
			Expect(json.Unmarshal([]byte(dockerconfigJson), &authDataJson)).To(Succeed())
			Expect(dockerconfigJson).To(ContainSubstring(expectedImage))
			authString, err := base64.StdEncoding.DecodeString(authRegexp.FindStringSubmatch(dockerconfigJson)[1])
			Expect(err).To(Succeed())
			pushRobotAccountName := imageRepository.Status.Credentials.PushRobotAccountName
			Expect(string(authString)).To(Equal(fmt.Sprintf("%s:%s", pushRobotAccountName, newPushToken)))

			uploadSecretKey := types.NamespacedName{Name: "upload-secret-" + expectedRemoteSecretName, Namespace: defaultNamespace}
			uploadSecret := waitSecretExist(uploadSecretKey)
			Expect(uploadSecret.Labels[remotesecretv1beta1.UploadSecretLabel]).To(Equal("remotesecret"))
			Expect(uploadSecret.Annotations[remotesecretv1beta1.RemoteSecretNameAnnotation]).To(Equal(expectedRemoteSecretName))
			uploadSecretDockerconfigJson := string(uploadSecret.Data[corev1.DockerConfigJsonKey])
			Expect(json.Unmarshal([]byte(uploadSecretDockerconfigJson), &authDataJson)).To(Succeed())
			Expect(uploadSecretDockerconfigJson).To(ContainSubstring(expectedImage))
			uploadSecretAuthString, err := base64.StdEncoding.DecodeString(authRegexp.FindStringSubmatch(uploadSecretDockerconfigJson)[1])
			Expect(err).To(Succeed())
			pullRobotAccountName := imageRepository.Status.Credentials.PullRobotAccountName
			Expect(string(uploadSecretAuthString)).To(Equal(fmt.Sprintf("%s:%s", pullRobotAccountName, newPullToken)))

			deleteSecret(uploadSecretKey)
		})

		It("should cleanup component repository", func() {
			ResetTestQuayClientToFails()

			isDeleteRobotAccountForPushInvoked := false
			isDeleteRobotAccountForPullInvoked := false
			DeleteRobotAccountFunc = func(organization, robotAccountName string) (bool, error) {
				defer GinkgoRecover()
				Expect(organization).To(Equal(testQuayOrg))
				Expect(robotAccountName).To(HavePrefix(expectedRobotAccountPrefix))
				if strings.HasSuffix(robotAccountName, "_pull") {
					isDeleteRobotAccountForPushInvoked = true
				} else {
					isDeleteRobotAccountForPullInvoked = true
				}
				return true, nil
			}
			isDeleteRepositoryInvoked := false
			DeleteRepositoryFunc = func(organization, imageRepository string) (bool, error) {
				defer GinkgoRecover()
				isDeleteRepositoryInvoked = true
				Expect(organization).To(Equal(testQuayOrg))
				Expect(imageRepository).To(Equal(expectedImageName))
				return true, nil
			}

			deleteImageRepository(resourceKey)

			Eventually(func() bool { return isDeleteRobotAccountForPushInvoked }, timeout, interval).Should(BeTrue())
			Eventually(func() bool { return isDeleteRobotAccountForPullInvoked }, timeout, interval).Should(BeTrue())
			Eventually(func() bool { return isDeleteRepositoryInvoked }, timeout, interval).Should(BeTrue())
		})
	})

	Context("Simultaneous image repository provision with often quay API errors", func() {

		It("should prepare environment", func() {
			pushToken = "push-token1234"
			pullToken = "pull-token1234"
			expectedImageName = fmt.Sprintf("%s-%s/%s", defaultNamespace, defaultComponentApplication, defaultComponentName)
			expectedImage = fmt.Sprintf("quay.io/%s/%s", testQuayOrg, expectedImageName)
			expectedRobotAccountPrefix = strings.ReplaceAll(strings.ReplaceAll(expectedImageName, "-", "_"), "/", "_")
		})

		It("should provision image repositories for components when quay is unstable", func() {
			nImageRepositories := 1
			nQuayErrors := 5

			createRepositoryFuncInvocations := make(map[int]int)
			createPushRobotAccountInvocations := make(map[int]int)
			createPullRobotAccountInvocations := make(map[int]int)
			addPushPermissionsToRobotAccountInvocations := make(map[int]int)
			addPullPermissionsToRobotAccountInvocations := make(map[int]int)
			getPushRobotAccountInvocations := make(map[int]int)
			getPullRobotAccountInvocations := make(map[int]int)

			ResetTestQuayClientToFails()

			CreateRepositoryFunc = func(repository quay.RepositoryRequest) (*quay.Repository, error) {
				defer GinkgoRecover()
				Expect(repository.Namespace).To(Equal(testQuayOrg))
				Expect(repository.Visibility).To(Equal("public"))
				Expect(repository.Description).ToNot(BeEmpty())
				Expect(repository.Repository).To(HavePrefix(expectedImageName))
				imageIndex, err := strconv.Atoi(repository.Repository[len(repository.Repository)-1:])
				Expect(err).ToNot(HaveOccurred())
				Expect(imageIndex > 0 && imageIndex <= nImageRepositories).To(BeTrue())

				if counter, exists := createRepositoryFuncInvocations[imageIndex]; !exists {
					createRepositoryFuncInvocations[imageIndex] = 0
				} else {
					if counter > nQuayErrors {
						Fail(fmt.Sprintf("Invoked create repository %s after success", repository.Repository))
					}
					if counter == nQuayErrors {
						return &quay.Repository{Name: repository.Repository}, nil
					}
				}
				createRepositoryFuncInvocations[imageIndex]++
				return nil, fmt.Errorf("quay error on %s repository creation", repository.Repository)
			}

			CreateRobotAccountFunc = func(organization, robotName string) (*quay.RobotAccount, error) {
				defer GinkgoRecover()
				Expect(organization).To(Equal(testQuayOrg))
				Expect(robotName).To(HavePrefix(expectedRobotAccountPrefix))
				imageIndex, err := strconv.Atoi(strings.TrimPrefix(robotName, expectedRobotAccountPrefix)[0:1])
				Expect(err).ToNot(HaveOccurred())

				Expect(createRepositoryFuncInvocations[imageIndex]).To(Equal(nQuayErrors))

				if strings.HasSuffix(robotName, "_pull") {
					if counter, exists := createPullRobotAccountInvocations[imageIndex]; !exists {
						createPullRobotAccountInvocations[imageIndex] = 0
					} else {
						if counter > nQuayErrors {
							Fail(fmt.Sprintf("Invoked create pull robot account %s after success", robotName))
						}
						if counter == nQuayErrors {
							return &quay.RobotAccount{Name: robotName, Token: pullToken}, nil
						}
					}
					createPullRobotAccountInvocations[imageIndex]++
					return nil, fmt.Errorf("quay error on %s pull robot account creation", robotName)
				} else {
					if counter, exists := createPushRobotAccountInvocations[imageIndex]; !exists {
						createPushRobotAccountInvocations[imageIndex] = 0
					} else {
						if counter > nQuayErrors {
							Fail(fmt.Sprintf("Invoked create push robot account %s after success", robotName))
						}
						if counter == nQuayErrors {
							return &quay.RobotAccount{Name: robotName, Token: pushToken}, nil
						}
					}
					createPushRobotAccountInvocations[imageIndex]++
					return nil, fmt.Errorf("quay error on %s push robot account creation", robotName)
				}
			}

			AddPermissionsForRepositoryToRobotAccountFunc = func(organization, imageRepository, robotAccountName string, isWrite bool) error {
				defer GinkgoRecover()
				Expect(organization).To(Equal(testQuayOrg))
				Expect(imageRepository).To(HavePrefix(expectedImageName))
				Expect(robotAccountName).To(HavePrefix(expectedRobotAccountPrefix))
				imageIndex, err := strconv.Atoi(strings.TrimPrefix(robotAccountName, expectedRobotAccountPrefix)[0:1])
				Expect(err).ToNot(HaveOccurred())

				if strings.HasSuffix(robotAccountName, "_pull") {
					Expect(createPullRobotAccountInvocations[imageIndex]).To(Equal(nQuayErrors))
					Expect(isWrite).To(BeFalse())
					if counter, exists := addPullPermissionsToRobotAccountInvocations[imageIndex]; !exists {
						addPullPermissionsToRobotAccountInvocations[imageIndex] = 0
					} else {
						if counter > nQuayErrors {
							Fail(fmt.Sprintf("Invoked add permissions for pull robot account %s after success", robotAccountName))
						}
						if counter == nQuayErrors {
							return nil
						}
					}
					addPullPermissionsToRobotAccountInvocations[imageIndex]++
					return fmt.Errorf("quay error on %s add permissions for pull robot account", robotAccountName)
				} else {
					Expect(createPushRobotAccountInvocations[imageIndex]).To(Equal(nQuayErrors))
					Expect(isWrite).To(BeTrue())
					if counter, exists := addPushPermissionsToRobotAccountInvocations[imageIndex]; !exists {
						addPushPermissionsToRobotAccountInvocations[imageIndex] = 0
					} else {
						if counter > nQuayErrors {
							Fail(fmt.Sprintf("Invoked add permissions for push robot account %s after success", robotAccountName))
						}
						if counter == nQuayErrors {
							return nil
						}
					}
					addPushPermissionsToRobotAccountInvocations[imageIndex]++
					return fmt.Errorf("quay error on %s add permissions for push robot account", robotAccountName)
				}
			}

			GetRobotAccountFunc = func(organization, robotAccountName string) (*quay.RobotAccount, error) {
				defer GinkgoRecover()
				Expect(organization).To(Equal(testQuayOrg))
				Expect(robotAccountName).To(HavePrefix(expectedRobotAccountPrefix))
				imageIndex, err := strconv.Atoi(strings.TrimPrefix(robotAccountName, expectedRobotAccountPrefix)[0:1])
				Expect(err).ToNot(HaveOccurred())

				if strings.HasSuffix(robotAccountName, "_pull") {
					if counter, exists := getPullRobotAccountInvocations[imageIndex]; !exists {
						getPullRobotAccountInvocations[imageIndex] = 0
					} else {
						if counter >= nQuayErrors {
							return &quay.RobotAccount{Name: robotAccountName, Token: pullToken}, nil
						}
					}
					getPullRobotAccountInvocations[imageIndex]++
					return nil, fmt.Errorf("quay error on get %s robot account", robotAccountName)
				} else {
					if counter, exists := getPushRobotAccountInvocations[imageIndex]; !exists {
						getPushRobotAccountInvocations[imageIndex] = 0
					} else {
						if counter >= nQuayErrors {
							return &quay.RobotAccount{Name: robotAccountName, Token: pushToken}, nil
						}
					}
					getPushRobotAccountInvocations[imageIndex]++
					return nil, fmt.Errorf("quay error on get %s robot account", robotAccountName)
				}
			}

			DeleteRobotAccountFunc = func(organization, robotAccountName string) (bool, error) {
				return true, nil
			}
			DeleteRepositoryFunc = func(organization, imageRepository string) (bool, error) {
				return true, nil
			}

			imageRepositoryKeys := make(map[int]types.NamespacedName)
			for i := 1; i <= nImageRepositories; i++ {
				key := resourceKey
				key.Name = key.Name + fmt.Sprint(i)
				imageRepositoryKeys[i] = key

				createImageRepository(imageRepositoryConfig{
					ResourceKey: &key,
					ImageName:   fmt.Sprintf("%s/%s%d", defaultComponentApplication, defaultComponentName, i),
					Labels: map[string]string{
						ApplicationNameLabelName: defaultComponentApplication,
						ComponentNameLabelName:   fmt.Sprintf("%s%d", defaultComponentName, i),
					},
				})
			}
			defer func() {
				for i := 1; i <= nImageRepositories; i++ {
					deleteImageRepository(imageRepositoryKeys[i])
				}
			}()

			isAllInvocationsDone := func(invocations map[int]int) bool {
				if len(invocations) != nImageRepositories {
					return false
				}
				for _, val := range invocations {
					if val != nQuayErrors {
						return false
					}
				}
				return true
			}
			Eventually(func() bool {
				log.Info(fmt.Sprintf("PushPermissions: %v", addPushPermissionsToRobotAccountInvocations))
				log.Info(fmt.Sprintf("PullPermissions: %v", addPullPermissionsToRobotAccountInvocations))
				log.Info(fmt.Sprintf("Push get: %v", getPushRobotAccountInvocations))
				log.Info(fmt.Sprintf("Pull get: %v", getPullRobotAccountInvocations))
				return isAllInvocationsDone(addPushPermissionsToRobotAccountInvocations)
			}, timeout, interval).Should(BeTrue())
			Eventually(func() bool {
				log.Info(fmt.Sprintf("PushPermissions: %v", addPushPermissionsToRobotAccountInvocations))
				log.Info(fmt.Sprintf("PullPermissions: %v", addPullPermissionsToRobotAccountInvocations))
				log.Info(fmt.Sprintf("Push get: %v", getPushRobotAccountInvocations))
				log.Info(fmt.Sprintf("Pull get: %v", getPullRobotAccountInvocations))
				return isAllInvocationsDone(addPullPermissionsToRobotAccountInvocations)
			}, timeout, interval).Should(BeTrue())
			Eventually(func() bool {
				return isAllInvocationsDone(getPushRobotAccountInvocations)
			}, timeout, interval).Should(BeTrue())
			Eventually(func() bool {
				return isAllInvocationsDone(getPullRobotAccountInvocations)
			}, timeout, interval).Should(BeTrue())

			for i := 1; i <= nImageRepositories; i++ {
				key := imageRepositoryKeys[i]
				waitImageRepositoryFinalizerOnImageRepository(key)
				waitImageRepositoryStatus(key)

				expectedRemoteSecretName = defaultComponentName + fmt.Sprint(i) + "-image-pull"

				imageRepository := getImageRepository(key)
				log.Info(fmt.Sprintf(">>>>>>>>>>>> STATUS: %#v", imageRepository.Status))
				Expect(imageRepository.Spec.Image.Name).ToNot(BeEmpty())
				Expect(imageRepository.Spec.Image.Visibility).To(Equal(imagerepositoryv1beta1.ImageVisibilityPublic))
				Expect(imageRepository.Status.State).To(Equal(imagerepositoryv1beta1.ImageRepositoryStateReady))
				Expect(imageRepository.Status.Message).To(BeEmpty())
				Expect(imageRepository.Status.Image.URL).ToNot(BeEmpty())
				Expect(imageRepository.Status.Image.Visibility).To(Equal(imagerepositoryv1beta1.ImageVisibilityPublic))
				Expect(imageRepository.Status.Credentials.PushRobotAccountName).To(HavePrefix(expectedRobotAccountPrefix))
				Expect(imageRepository.Status.Credentials.PushSecretName).To(HavePrefix(strings.ReplaceAll(expectedImageName, "/", "-")))
				Expect(imageRepository.Status.Credentials.PullRobotAccountName).To(HavePrefix(expectedRobotAccountPrefix))
				Expect(imageRepository.Status.Credentials.PullRobotAccountName).To(HaveSuffix("_pull"))
				Expect(imageRepository.Status.Credentials.PullSecretName).To(Equal(expectedRemoteSecretName))
				Expect(imageRepository.Status.Credentials.GenerationTimestamp).ToNot(BeNil())

				secret := &corev1.Secret{}
				secretName := imageRepository.Status.Credentials.PushSecretName
				secretKey := types.NamespacedName{Name: secretName, Namespace: defaultNamespace}
				waitSecretExist(secretKey)
				Expect(k8sClient.Get(ctx, secretKey, secret)).To(Succeed())
				dockerconfigJson := string(secret.Data[corev1.DockerConfigJsonKey])
				Expect(dockerconfigJson).ToNot(BeNil())
				var authDataJson interface{}
				Expect(json.Unmarshal([]byte(dockerconfigJson), &authDataJson)).To(Succeed())

				remoteSecretKey := types.NamespacedName{Name: expectedRemoteSecretName, Namespace: defaultNamespace}
				remoteSecret := waitRemoteSecretExist(remoteSecretKey)
				Expect(remoteSecret.Labels[ApplicationNameLabelName]).To(Equal(defaultComponentApplication))
				Expect(remoteSecret.Labels[ComponentNameLabelName]).To(Equal(defaultComponentName + fmt.Sprint(i)))
				Expect(remoteSecret.OwnerReferences).To(HaveLen(1))
				Expect(remoteSecret.OwnerReferences[0].Name).To(Equal(imageRepository.Name))
				Expect(remoteSecret.OwnerReferences[0].Kind).To(Equal("ImageRepository"))
				Expect(remoteSecret.Spec.Secret.Name).To(Equal(remoteSecretKey.Name))
				Expect(remoteSecret.Spec.Secret.Type).To(Equal(corev1.SecretTypeDockerConfigJson))
				Expect(remoteSecret.Spec.Secret.LinkedTo).To(HaveLen(1))
				Expect(remoteSecret.Spec.Secret.LinkedTo[0].ServiceAccount.Reference.Name).To(Equal(defaultServiceAccountName))

				uploadSecretKey := types.NamespacedName{Name: "upload-secret-" + expectedRemoteSecretName, Namespace: defaultNamespace}
				uploadSecret := waitSecretExist(uploadSecretKey)
				defer deleteSecret(uploadSecretKey)
				Expect(uploadSecret.Labels[remotesecretv1beta1.UploadSecretLabel]).To(Equal("remotesecret"))
				Expect(uploadSecret.Annotations[remotesecretv1beta1.RemoteSecretNameAnnotation]).To(Equal(expectedRemoteSecretName))
				uploadSecretDockerconfigJson := string(uploadSecret.Data[corev1.DockerConfigJsonKey])
				Expect(uploadSecretDockerconfigJson).ToNot(BeEmpty())
			}
		})
	})

	Context("Image repository error scenarios", func() {

		It("should prepare environment", func() {
			deleteImageRepository(resourceKey)

			pushToken = "push-token1234"
			expectedImageName = fmt.Sprintf("%s-%s", defaultNamespace, defaultImageRepositoryName)
			expectedImage = fmt.Sprintf("quay.io/%s/%s", testQuayOrg, expectedImageName)
			expectedRobotAccountPrefix = strings.ReplaceAll(expectedImageName, "-", "_")
		})

		It("should permanently fail if private image repository requested on creation but quota exceeded", func() {
			ResetTestQuayClient()

			isCreateRepositoryInvoked := false
			CreateRepositoryFunc = func(repository quay.RepositoryRequest) (*quay.Repository, error) {
				defer GinkgoRecover()
				isCreateRepositoryInvoked = true
				Expect(repository.Repository).To(Equal(expectedImageName))
				Expect(repository.Namespace).To(Equal(testQuayOrg))
				Expect(repository.Visibility).To(Equal("private"))
				Expect(repository.Description).ToNot(BeEmpty())
				return nil, fmt.Errorf("payment required")
			}

			createImageRepository(imageRepositoryConfig{IsPrivate: true})

			Eventually(func() bool { return isCreateRepositoryInvoked }, timeout, interval).Should(BeTrue())

			imageRepository := &imagerepositoryv1beta1.ImageRepository{}
			Eventually(func() bool {
				imageRepository = getImageRepository(resourceKey)
				return string(imageRepository.Status.State) != ""
			}, timeout, interval).Should(BeTrue())
			Expect(imageRepository.Status.State).To(Equal(imagerepositoryv1beta1.ImageRepositoryStateFailed))
			Expect(imageRepository.Status.Message).ToNot(BeEmpty())
			Expect(imageRepository.Status.Message).To(ContainSubstring("exceeds current quay plan limit"))

			deleteImageRepository(resourceKey)
		})

		It("should add error message and revert visibility in spec if private visibility requested after provision but quota exceeded", func() {
			deleteImageRepository(resourceKey)
			ResetTestQuayClient()

			CreateRepositoryFunc = func(repository quay.RepositoryRequest) (*quay.Repository, error) {
				return &quay.Repository{Name: expectedImageName}, nil
			}
			CreateRobotAccountFunc = func(organization, robotName string) (*quay.RobotAccount, error) {
				return &quay.RobotAccount{Name: robotName, Token: pushToken}, nil
			}
			createImageRepository(imageRepositoryConfig{})
			waitImageRepositoryFinalizerOnImageRepository(resourceKey)

			ResetTestQuayClientToFails()

			isChangeRepositoryVisibilityInvoked := false
			ChangeRepositoryVisibilityFunc = func(organization, imageRepository, visibility string) error {
				defer GinkgoRecover()
				isChangeRepositoryVisibilityInvoked = true
				Expect(organization).To(Equal(testQuayOrg))
				Expect(imageRepository).To(Equal(expectedImageName))
				Expect(visibility).To(Equal(string(imagerepositoryv1beta1.ImageVisibilityPrivate)))
				return fmt.Errorf("payment required")
			}

			imageRepository := getImageRepository(resourceKey)
			imageRepository.Spec.Image.Visibility = imagerepositoryv1beta1.ImageVisibilityPrivate
			Expect(k8sClient.Update(ctx, imageRepository)).To(Succeed())

			Eventually(func() bool { return isChangeRepositoryVisibilityInvoked }, timeout, interval).Should(BeTrue())
			Eventually(func() bool {
				imageRepository := getImageRepository(resourceKey)
				return imageRepository.Spec.Image.Visibility == imagerepositoryv1beta1.ImageVisibilityPublic &&
					imageRepository.Status.Image.Visibility == imagerepositoryv1beta1.ImageVisibilityPublic &&
					imageRepository.Status.Message != ""
			}, timeout, interval).Should(BeTrue())

			ResetTestQuayClient()
			deleteImageRepository(resourceKey)
		})

		It("should fail if invalid image repository name given", func() {
			deleteImageRepository(resourceKey)
			ResetTestQuayClient()

			imageRepository := getImageRepositoryConfig(imageRepositoryConfig{
				ImageName: "wrong&name",
			})
			Expect(k8sClient.Create(ctx, imageRepository)).ToNot(Succeed())
		})
	})

})
