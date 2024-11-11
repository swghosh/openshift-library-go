package controllers

import (
	"fmt"
	"hash/fnv"
	"sort"
	"strings"
	"time"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	apiserverv1 "k8s.io/apiserver/pkg/apis/apiserver/v1"
)

const (
	KMSPluginEndpoint = "unix:///var/kms-plugin/socket.sock"
	KMSPluginTimeout  = 5 * time.Second
)

func shortHash(s string) string {
	hash := fnv.New32a()
	hash.Write([]byte(s))
	intHash := hash.Sum32()
	result := fmt.Sprintf("%08x", intHash)
	return result
}

func resourceHash(resConfig apiserverv1.ResourceConfiguration) string {
	res := resConfig.Resources
	sort.Strings(res)
	return shortHash(strings.Join(res, "+"))
}

func patchEncryptionConfigForKMS(existingConfig *apiserverv1.EncryptionConfiguration) *apiserverv1.EncryptionConfiguration {
	newConfig := existingConfig.DeepCopy()
	for i, resource := range newConfig.Resources {
		kmsProvider := apiserverv1.ProviderConfiguration{
			KMS: &apiserverv1.KMSConfiguration{
				APIVersion: "v2",
				Name:       fmt.Sprintf("kms-%s", resourceHash(resource)),
				Endpoint:   KMSPluginEndpoint,
				Timeout: &metav1.Duration{
					Duration: KMSPluginTimeout,
				},
			},
		}

		newProviders := []apiserverv1.ProviderConfiguration{kmsProvider}
		newConfig.Resources[i].Providers = append(newProviders, newConfig.Resources[i].Providers...)
	}
	return newConfig
}

func patchEncryptionConfigForDecryptingKMS(existingConfig *apiserverv1.EncryptionConfiguration) *apiserverv1.EncryptionConfiguration {
	newConfig := existingConfig.DeepCopy()
	for i, resource := range newConfig.Resources {
		kmsProvider := apiserverv1.ProviderConfiguration{
			KMS: &apiserverv1.KMSConfiguration{
				APIVersion: "v2",
				Name:       fmt.Sprintf("kms-%s", resourceHash(resource)),
				Endpoint:   KMSPluginEndpoint,
				Timeout: &metav1.Duration{
					Duration: KMSPluginTimeout,
				},
			},
		}

		newProviders := []apiserverv1.ProviderConfiguration{}
		remainingProviders := []apiserverv1.ProviderConfiguration{}
		for _, provider := range newConfig.Resources[i].Providers {
			if provider.Identity != nil {
				newProviders = append(newProviders, provider)
			} else {
				remainingProviders = append(remainingProviders, provider)
			}
		}
		newProviders = append(newProviders, kmsProvider)
		newConfig.Resources[i].Providers = append(newProviders, remainingProviders...)
	}
	return newConfig
}
