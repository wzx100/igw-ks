/*
Copyright 2022.

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

import metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

const (
	ResourceKindOpTenant     = "OpTenant"
	ResourceSingularOpTenant = "optenant"
	ResourcePluralOpTenant   = "optenants"
	OpTenantLabel            = "kubesphere.io/optenant"
)

// EDIT THIS FILE!  THIS IS SCAFFOLDING FOR YOU TO OWN!
// NOTE: json tags are required.  Any new fields you add must have json tags for the fields to be serialized.

// OpTenantSpec defines the desired state of OpTenant
type OpTenantSpec struct {
	// INSERT ADDITIONAL SPEC FIELDS - desired state of cluster
	// Important: Run "make" to regenerate code after modifying this file

	// TenantName is an example field of OpTenant. Edit optenant_types.go to remove/update
	TenantName string `json:"tenantname,omitempty"`

	RelatedWorkSpaces string `json:"relatedworkspaces,omitempty"`

	// TenantAdmin is an example field of OpTenant. Edit optenant_types.go to remove/update
	TenantAdmin string `json:"tenantadmin,omitempty"`
}

// OpTenantStatus defines the observed state of OpTenant
type OpTenantStatus struct {
	// INSERT ADDITIONAL STATUS FIELD - define observed state of cluster
	// Important: Run "make" to regenerate code after modifying this file
}

//+kubebuilder:object:root=true
//+kubebuilder:subresource:status
//+kubebuilder:printcolumn:name="TenantName",type="string",JSONPath=".spec.tenantname"
//+kubebuilder:printcolumn:name="TenantAdmin",type="string",JSONPath=".spec.tenantadmin"
//+kubebuilder:resource:scope=Cluster

// OpTenant is the Schema for the optenants API
type OpTenant struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	Spec   OpTenantSpec   `json:"spec,omitempty"`
	Status OpTenantStatus `json:"status,omitempty"`
}

//+kubebuilder:object:root=true

// OpTenantList contains a list of OpTenant
type OpTenantList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []OpTenant `json:"items"`
}

func init() {
	SchemeBuilder.Register(&OpTenant{}, &OpTenantList{})
}
