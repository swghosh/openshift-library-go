package encryptionconfig

import (
	"fmt"
	"hash/fnv"
	"sort"
	"strings"
	"time"

	"k8s.io/apimachinery/pkg/runtime/schema"
)

const (
	KMSPluginEndpoint = "unix:///var/kms-plugin/socket.sock"
	KMSPluginTimeout  = 5 * time.Second
)

// shortHash returns the 32-bit FNV-1a hash
func shortHash(s string) string {
	hash := fnv.New32a()
	hash.Write([]byte(s))
	intHash := hash.Sum32()
	result := fmt.Sprintf("%08x", intHash)
	return result
}

// resourceHash hashes GR names into a short hash.
// This function can input multiple resource names at based on upstream apiserverconfigv1.ResourceConfiguration
// but in our controllers we only support one GR per provider.
func resourceHash(grs ...schema.GroupResource) string {
	res := make([]string, len(grs))
	for i, gr := range grs {
		res[i] = gr.String()
	}
	sort.Strings(res)
	return shortHash(strings.Join(res, "+"))
}

// generateKMSKeyName generates key name for current kms provider
func generateKMSKeyName(prefix string, gr schema.GroupResource) string {
	return fmt.Sprintf("%s-%s", prefix, resourceHash(gr))
}
