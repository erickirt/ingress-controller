package ingress_test

import (
	"context"
	"errors"
	"fmt"
	"path/filepath"
	"reflect"
	"sync"
	"testing"
	"time"

	"github.com/go-logr/zapr"
	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/stretchr/testify/suite"
	"go.uber.org/zap/zaptest"
	"google.golang.org/protobuf/proto"
	corev1 "k8s.io/api/core/v1"
	networkingv1 "k8s.io/api/networking/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/apimachinery/pkg/util/intstr"
	clientgoscheme "k8s.io/client-go/kubernetes/scheme"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/config"
	"sigs.k8s.io/controller-runtime/pkg/envtest"
	logf "sigs.k8s.io/controller-runtime/pkg/log"
	"sigs.k8s.io/controller-runtime/pkg/manager"

	icsv1 "github.com/pomerium/ingress-controller/apis/ingress/v1"
	ingress_controller "github.com/pomerium/ingress-controller/controllers/ingress"
	"github.com/pomerium/ingress-controller/controllers/reporter"
	"github.com/pomerium/ingress-controller/model"
)

var (
	_ suite.SetupAllSuite     = &ControllerTestSuite{}
	_ suite.TearDownAllSuite  = &ControllerTestSuite{}
	_ suite.SetupTestSuite    = &ControllerTestSuite{}
	_ suite.TearDownTestSuite = &ControllerTestSuite{}

	cmpOpts = []cmp.Option{
		cmpopts.IgnoreTypes(metav1.TypeMeta{}),
		cmpopts.IgnoreFields(metav1.ObjectMeta{}, "SelfLink"),
	}
)

type ControllerTestSuite struct {
	suite.Suite
	client.Client
	*envtest.Environment

	// created per test
	mgrCtxCancel context.CancelFunc
	mgrDone      chan error
	*mockPomeriumReconciler

	controllerName string
}

type mockPomeriumReconciler struct {
	sync.RWMutex
	lastUpsert *model.IngressConfig
	lastDelete *types.NamespacedName
}

func (m *mockPomeriumReconciler) Upsert(_ context.Context, ic *model.IngressConfig) (bool, error) {
	m.Lock()
	defer m.Unlock()

	m.lastUpsert = ic.Clone()
	m.lastDelete = nil
	return true, nil
}

func (m *mockPomeriumReconciler) Delete(_ context.Context, name types.NamespacedName) (bool, error) {
	m.Lock()
	defer m.Unlock()

	m.lastDelete = &name
	m.lastUpsert = nil
	return true, nil
}

func (m *mockPomeriumReconciler) Set(_ context.Context, ics []*model.IngressConfig) (bool, error) {
	if len(ics) != 0 {
		return false, errors.New("unexpected ingresses")
	}
	return false, nil
}

func (s *ControllerTestSuite) EventuallyDeleted(name types.NamespacedName) {
	s.T().Helper()
	require.Eventually(s.T(), func() bool {
		s.mockPomeriumReconciler.Lock()
		defer s.mockPomeriumReconciler.Unlock()

		if s.mockPomeriumReconciler.lastDelete == nil {
			return false
		}
		val := *s.mockPomeriumReconciler.lastDelete == name
		s.mockPomeriumReconciler.lastDelete = nil
		return val
	}, time.Second, time.Millisecond*50, "lastDeleted != %s", name)
}

func (s *ControllerTestSuite) diffFn(diffFn func(current *model.IngressConfig) string, diff *string) func() bool {
	return func() bool {
		s.mockPomeriumReconciler.RLock()
		defer s.mockPomeriumReconciler.RUnlock()

		if s.lastUpsert == nil {
			*diff = "lastUpsert == nil"
			return false
		}
		if s.lastDelete != nil {
			*diff = fmt.Sprintf("lastDelete = %s", *s.lastDelete)
		}
		*diff = diffFn(s.lastUpsert)
		return *diff == ""
	}
}

func (s *ControllerTestSuite) EventuallyUpsert(diffFn func(current *model.IngressConfig) string, msg string) {
	s.T().Helper()
	var diff string

	if !assert.Eventually(s.T(), s.diffFn(diffFn, &diff), time.Second*30, time.Millisecond*50) {
		s.T().Fatalf("condition %q never satisfied: %s", msg, diff)
	}
}

func (s *ControllerTestSuite) NeverEqual(diffFn func(current *model.IngressConfig) string) {
	s.T().Helper()
	var diff string
	require.Never(s.T(), s.diffFn(diffFn, &diff), time.Second, time.Millisecond*50)
}

func (s *ControllerTestSuite) NoError(err error, msgAndArgs ...interface{}) {
	s.T().Helper()
	require.NoError(s.T(), err, msgAndArgs...)
}

func (s *ControllerTestSuite) SetupSuite() {
	s.controllerName = ingress_controller.DefaultClassControllerName

	scheme := runtime.NewScheme()
	s.NoError(clientgoscheme.AddToScheme(scheme))
	s.NoError(icsv1.AddToScheme(scheme))

	useExistingCluster := false
	s.Environment = &envtest.Environment{
		CRDDirectoryPaths:     []string{filepath.Join("..", "..", "config", "crd", "bases")},
		ErrorIfCRDPathMissing: true,
		Scheme:                scheme,
		UseExistingCluster:    &useExistingCluster,
	}
	cfg, err := s.Environment.Start()
	s.NoError(err)
	require.NotNil(s.T(), cfg)
	s.T().Logf("API Host: %s", cfg.Host)

	k8sClient, err := client.New(cfg, client.Options{Scheme: scheme})
	s.NoError(err)
	require.NotNil(s.T(), k8sClient)
	s.Client = k8sClient
}

func (s *ControllerTestSuite) SetupTest() {
	logf.SetLogger(zapr.NewLogger(zaptest.NewLogger(s.T())))
}

func (s *ControllerTestSuite) deleteAll() {
	// s.Client.DeleteAll is not implemented for the test environment thus we need manually loop over objects
	ctx := context.Background()

	icl := new(networkingv1.IngressClassList)
	s.NoError(s.Client.List(ctx, icl))
	for i := range icl.Items {
		s.NoError(s.Client.Delete(ctx, &icl.Items[i]))
	}

	il := new(networkingv1.IngressList)
	s.NoError(s.Client.List(ctx, il))
	for i := range il.Items {
		s.NoError(s.Client.Delete(ctx, &il.Items[i]))
	}

	svcs := new(corev1.ServiceList)
	s.NoError(s.Client.List(ctx, svcs))
	for i := range svcs.Items {
		s.NoError(s.Client.Delete(ctx, &svcs.Items[i]))
	}

	secrets := new(corev1.SecretList)
	s.NoError(s.Client.List(ctx, secrets))
	for i := range secrets.Items {
		s.NoError(s.Client.Delete(ctx, &secrets.Items[i]))
	}

	settings := new(icsv1.PomeriumList)
	s.NoError(s.Client.List(ctx, settings))
	for i := range settings.Items {
		s.NoError(s.Client.Delete(ctx, &settings.Items[i]))
	}
}

func (s *ControllerTestSuite) TearDownTest() {
	s.T().Log("TearDownTest")
	if s.mgrCtxCancel == nil {
		s.deleteAll()
		return
	}
	s.mgrCtxCancel()
	<-s.mgrDone
	s.deleteAll()
	s.mgrCtxCancel = nil
	close(s.mgrDone)
}

func (s *ControllerTestSuite) TearDownSuite() {
	s.NoError(s.Environment.Stop())
}

func (s *ControllerTestSuite) createTestController(ctx context.Context, opts ...ingress_controller.Option) {
	s.mockPomeriumReconciler = &mockPomeriumReconciler{}

	skipNameValidation := true
	mgr, err := ctrl.NewManager(s.Environment.Config, manager.Options{
		Controller: config.Controller{
			SkipNameValidation: &skipNameValidation,
		},
		Scheme: s.Environment.Scheme,
	})
	s.NoError(err)
	s.NoError(ingress_controller.NewIngressController(mgr, s.mockPomeriumReconciler, opts...))

	ctx, cancel := context.WithCancel(context.Background())
	s.mgrCtxCancel = cancel
	s.mgrDone = make(chan error)

	go func() {
		s.mgrDone <- mgr.Start(ctx)
	}()
}

type testObjs struct {
	*networkingv1.IngressClass
	*networkingv1.Ingress
	*corev1.Endpoints
	*corev1.Service
	*corev1.Secret
}

func (s *ControllerTestSuite) initialTestObjects(namespace string) *testObjs {
	typePrefix := networkingv1.PathTypePrefix
	icsName := "pomerium"
	return &testObjs{
		&networkingv1.IngressClass{
			ObjectMeta: metav1.ObjectMeta{Name: icsName, Namespace: namespace},
			Spec: networkingv1.IngressClassSpec{
				Controller: s.controllerName,
			},
		},
		&networkingv1.Ingress{
			ObjectMeta: metav1.ObjectMeta{Name: "ingress", Namespace: namespace},
			Spec: networkingv1.IngressSpec{
				IngressClassName: &icsName,
				TLS: []networkingv1.IngressTLS{{
					Hosts:      []string{"service.localhost.pomerium.io"},
					SecretName: "secret",
				}},
				Rules: []networkingv1.IngressRule{{
					Host: "service.localhost.pomerium.io",
					IngressRuleValue: networkingv1.IngressRuleValue{
						HTTP: &networkingv1.HTTPIngressRuleValue{
							Paths: []networkingv1.HTTPIngressPath{{
								Path:     "/",
								PathType: &typePrefix,
								Backend: networkingv1.IngressBackend{
									Service: &networkingv1.IngressServiceBackend{
										Name: "service",
										Port: networkingv1.ServiceBackendPort{
											Name: "http",
										},
									},
								},
							}},
						},
					},
				}},
			},
		},
		&corev1.Endpoints{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "service",
				Namespace: namespace,
			},
			Subsets: []corev1.EndpointSubset{{
				Addresses: []corev1.EndpointAddress{{IP: "1.2.3.4"}},
			}},
		},
		&corev1.Service{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "service",
				Namespace: namespace,
			},
			Spec: corev1.ServiceSpec{
				Ports: []corev1.ServicePort{{
					Name:       "http",
					Protocol:   "TCP",
					Port:       80,
					TargetPort: intstr.IntOrString{IntVal: 80},
				}},
			},
			Status: corev1.ServiceStatus{},
		},
		&corev1.Secret{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "secret",
				Namespace: namespace,
			},
			Data: map[string][]byte{
				corev1.TLSPrivateKeyKey: []byte("A"),
				corev1.TLSCertKey:       []byte("A"),
			},
			Type: corev1.SecretTypeTLS,
		},
	}
}

func (s *ControllerTestSuite) TestIngressClass() {
	ctx := context.Background()
	s.createTestController(ctx)

	to := s.initialTestObjects("default")
	ingressClass, ingress, endpoints, service := to.IngressClass, to.Ingress, to.Endpoints, to.Service

	s.Run("no ingress class", func() {
		ingress.Spec.IngressClassName = nil
		// ingress should not be picked up for reconciliation as there's no ingress class record
		s.NoError(s.Client.Create(ctx, to.Secret))
		s.NoError(s.Client.Create(ctx, ingress))
		s.NoError(s.Client.Create(ctx, endpoints))
		s.NoError(s.Client.Create(ctx, service))
		s.NeverEqual(func(ic *model.IngressConfig) string {
			return cmp.Diff(ingress, ic.Ingress, cmpOpts...)
		})
	})
	s.Run("ingress class that is not default", func() {
		// create ingress class spec that is not default
		s.NoError(s.Client.Create(ctx, ingressClass))
		s.NeverEqual(func(ic *model.IngressConfig) string {
			return cmp.Diff(ingress, ic.Ingress, cmpOpts...)
		})
	})
	s.Run("ingress class that is not ours", func() {
		// create ingress class that is not ours
		anotherIngressClass := &networkingv1.IngressClass{
			ObjectMeta: metav1.ObjectMeta{Name: "another", Namespace: "default"},
			Spec: networkingv1.IngressClassSpec{
				Controller: "example.com/ingress-controller",
			},
		}
		s.NoError(s.Client.Create(ctx, anotherIngressClass))
		ingress.Spec.IngressClassName = &anotherIngressClass.Name
		s.NoError(s.Client.Update(ctx, ingress))
		s.NeverEqual(func(ic *model.IngressConfig) string {
			return cmp.Diff(ingress, ic.Ingress, cmpOpts...)
		})
	})
	s.Run("ingress class that is ours", func() {
		// mark ingress with ingress class name that is ours
		ingress.Spec.IngressClassName = &ingressClass.Name
		s.NoError(s.Client.Update(ctx, ingress))
		s.EventuallyUpsert(func(ic *model.IngressConfig) string {
			return cmp.Diff(ingress, ic.Ingress, cmpOpts...)
		}, "set ingressClass to ingress spec")
	})
	s.Run("no ingress class set", func() {
		// remove ingress class annotation, it should be deleted
		ingress.Spec.IngressClassName = nil
		s.NoError(s.Client.Update(ctx, ingress))
		s.EventuallyDeleted(types.NamespacedName{Name: ingress.Name, Namespace: ingress.Namespace})
	})
	s.Run("default ingress class", func() {
		// make ingressClass default, ingress should be recreated
		ingressClass.Annotations = map[string]string{ingress_controller.IngressClassDefaultAnnotationKey: "true"}
		s.NoError(s.Client.Update(ctx, ingressClass))
		s.EventuallyUpsert(func(ic *model.IngressConfig) string {
			return cmp.Diff(ingress, ic.Ingress, cmpOpts...)
		}, "default ingress class")
	})
}

// TestDependencies verifies that when objects the Ingress depends on change,
// a configuration reconciliation would happen
func (s *ControllerTestSuite) TestDependencies() {
	ctx := context.Background()
	s.createTestController(ctx)

	to := s.initialTestObjects("default")
	ingressClass, ingress, endpoints, service, secret := to.IngressClass, to.Ingress, to.Endpoints, to.Service, to.Secret
	svcName := types.NamespacedName{Name: "service", Namespace: "default"}
	secretName := types.NamespacedName{Name: "secret", Namespace: "default"}

	for _, obj := range []client.Object{ingress, endpoints, service, secret} {
		s.NoError(s.Client.Create(ctx, obj))
	}
	s.NeverEqual(func(ic *model.IngressConfig) string {
		return cmp.Diff(ingress, ic.Ingress)
	})
	s.NoError(s.Client.Create(ctx, ingressClass))
	s.EventuallyUpsert(func(ic *model.IngressConfig) string {
		return cmp.Diff(service, ic.Services[svcName], cmpOpts...) +
			cmp.Diff(secret, ic.Secrets[secretName], cmpOpts...) +
			cmp.Diff(ingress, ic.Ingress, cmpOpts...)
	}, "secret, service, ingress up to date")

	service.Spec.Ports[0].Port = 8080
	s.NoError(s.Client.Update(ctx, service))
	s.EventuallyUpsert(func(ic *model.IngressConfig) string {
		return cmp.Diff(service, ic.Services[svcName], cmpOpts...)
	}, "updated port")

	// update secret
	secret.Data = map[string][]byte{
		corev1.TLSPrivateKeyKey: []byte("B"),
		corev1.TLSCertKey:       []byte("B"),
	}
	s.NoError(s.Client.Update(ctx, secret))
	s.EventuallyUpsert(func(ic *model.IngressConfig) string {
		return cmp.Diff(secret, ic.Secrets[secretName], cmpOpts...)
	}, "updated secret")
}

func (s *ControllerTestSuite) TestAnnotationDependencies() {
	ctx := context.Background()
	s.createTestController(ctx)

	to := s.initialTestObjects("default")
	ingressClass, ingress, endpoints, service, secret := to.IngressClass, to.Ingress, to.Endpoints, to.Service, to.Secret
	ingress.Annotations = map[string]string{
		fmt.Sprintf("%s/%s", ingress_controller.DefaultAnnotationPrefix, model.TLSCustomCASecret):           "custom-ca",
		fmt.Sprintf("%s/%s", ingress_controller.DefaultAnnotationPrefix, model.TLSClientSecret):             "client",
		fmt.Sprintf("%s/%s", ingress_controller.DefaultAnnotationPrefix, model.TLSDownstreamClientCASecret): "downstream-ca",
	}
	svcName := types.NamespacedName{Name: "service", Namespace: "default"}
	secretName := types.NamespacedName{Name: "secret", Namespace: "default"}

	for _, obj := range []client.Object{ingress, endpoints, service, secret, ingressClass} {
		s.NoError(s.Client.Create(ctx, obj))
	}
	s.NeverEqual(func(ic *model.IngressConfig) string {
		return cmp.Diff(ingress, ic.Ingress, cmpOpts...)
	})

	for _, obj := range []*corev1.Secret{{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "client",
			Namespace: "default",
		},
		StringData: map[string]string{
			corev1.TLSPrivateKeyKey: "k1",
			corev1.TLSCertKey:       "c1",
		},
		Type: corev1.SecretTypeTLS,
	}, {
		ObjectMeta: metav1.ObjectMeta{
			Name:      "custom-ca",
			Namespace: "default",
		},
		StringData: map[string]string{
			corev1.TLSCertKey: "c2",
		},
	}, {
		ObjectMeta: metav1.ObjectMeta{
			Name:      "downstream-ca",
			Namespace: "default",
		},
		StringData: map[string]string{
			corev1.TLSCertKey: "c3",
		},
	}} {
		s.NoError(s.Client.Create(ctx, obj))
	}
	s.EventuallyUpsert(func(ic *model.IngressConfig) string {
		return cmp.Diff(service, ic.Services[svcName], cmpOpts...) +
			cmp.Diff(secret, ic.Secrets[secretName], cmpOpts...) +
			cmp.Diff(ingress, ic.Ingress, cmpOpts...)
	}, "secret, service, ingress up to date")
}

// TestNamespaces checks that controller would only
func (s *ControllerTestSuite) TestNamespaces() {
	namespaces := map[string]bool{"a": true, "b": false, "c": true, "d": false}

	ctx := context.Background()
	s.createTestController(ctx, ingress_controller.WithNamespaces([]string{"a", "c"}))
	del := func(obj client.Object) { s.Client.Delete(ctx, obj) }

	ingressClass := s.initialTestObjects("").IngressClass
	s.NoError(s.Client.Create(ctx, ingressClass))

	for ns, shouldCreate := range namespaces {
		to := s.initialTestObjects(ns)
		ingress, endpoints, service, secret := to.Ingress, to.Endpoints, to.Service, to.Secret
		for _, obj := range []client.Object{
			&corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: ns}},
			ingress, endpoints, service, secret,
		} {
			s.NoError(s.Client.Create(ctx, obj), "%s/%s %s", obj.GetNamespace(), obj.GetName(), reflect.TypeOf(obj))
			defer del(obj)
		}

		diffFn := func(ic *model.IngressConfig) string {
			return cmp.Diff(ingress, ic.Ingress, cmpOpts...)
		}

		if shouldCreate {
			s.EventuallyUpsert(diffFn, ns)
		} else {
			s.NeverEqual(diffFn)
		}
	}
}

func (s *ControllerTestSuite) TestIngressStatus() {
	ctx := context.Background()

	proxySvcName := types.NamespacedName{Name: "pomerium-proxy", Namespace: "pomerium"}
	s.createTestController(ctx,
		ingress_controller.WithNamespaces([]string{"default"}),
		ingress_controller.WithUpdateIngressStatusFromService(proxySvcName),
	)

	ns := &corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: "pomerium"}}
	proxySvc := &corev1.Service{
		TypeMeta: metav1.TypeMeta{},
		ObjectMeta: metav1.ObjectMeta{
			Name:      proxySvcName.Name,
			Namespace: proxySvcName.Namespace,
		},
		Spec: corev1.ServiceSpec{
			Type: corev1.ServiceTypeLoadBalancer,
			Ports: []corev1.ServicePort{{
				Name:       "https",
				Protocol:   "TCP",
				Port:       443,
				TargetPort: intstr.FromInt(5443),
			}},
		},
	}
	to := s.initialTestObjects("default")
	class, ingress, endpoints, service, secret := to.IngressClass, to.Ingress, to.Endpoints, to.Service, to.Secret
	del := func(obj client.Object) { s.Client.Delete(ctx, obj) }
	for _, obj := range []client.Object{
		ns, proxySvc,
		class, endpoints, service, secret, ingress,
	} {
		s.NoError(s.Client.Create(ctx, obj))
		defer del(obj)
	}

	s.EventuallyUpsert(func(ic *model.IngressConfig) string {
		return cmp.Diff(ingress, ic.Ingress, cmpOpts...)
	}, "ingress created")

	vipMode := corev1.LoadBalancerIPModeVIP
	lbIngress := []corev1.LoadBalancerIngress{{
		IP:     "10.10.10.10",
		IPMode: &vipMode, // as of v1.30, this field is populated automatically with the default mode
	}}
	proxySvc.Status.LoadBalancer.Ingress = lbIngress
	s.NoError(s.Client.Status().Update(ctx, proxySvc), proxySvc.Spec)
	s.Equal(lbIngress, proxySvc.Status.LoadBalancer.Ingress)
	require.Eventually(s.T(), func() bool {
		s.NoError(s.Client.Get(ctx, types.NamespacedName{Name: ingress.Name, Namespace: ingress.Namespace}, ingress))
		if len(ingress.Status.LoadBalancer.Ingress) != len(lbIngress) {
			return false
		}
		for i := range ingress.Status.LoadBalancer.Ingress {
			if ingress.Status.LoadBalancer.Ingress[i].IP != lbIngress[i].IP {
				return false
			}
			if ingress.Status.LoadBalancer.Ingress[i].Hostname != lbIngress[i].Hostname {
				return false
			}
			for j := range ingress.Status.LoadBalancer.Ingress[i].Ports {
				if ingress.Status.LoadBalancer.Ingress[i].Ports[j].Protocol != lbIngress[i].Ports[j].Protocol {
					return false
				}
				if ingress.Status.LoadBalancer.Ingress[i].Ports[j].Port != lbIngress[i].Ports[j].Port {
					return false
				}
			}
		}
		return true
	}, time.Minute, time.Second)
}

func (s *ControllerTestSuite) TestIngressAddressWithNodeport() {
	ctx := context.Background()

	proxySvcName := types.NamespacedName{Name: "pomerium-proxy", Namespace: "pomerium-nodeport"}
	s.createTestController(ctx,
		ingress_controller.WithNamespaces([]string{"default"}),
		ingress_controller.WithUpdateIngressStatusFromService(proxySvcName),
	)

	ns := &corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: "pomerium-nodeport"}}
	proxySvc := &corev1.Service{
		TypeMeta: metav1.TypeMeta{},
		ObjectMeta: metav1.ObjectMeta{
			Name:      proxySvcName.Name,
			Namespace: proxySvcName.Namespace,
		},
		Spec: corev1.ServiceSpec{
			Type: corev1.ServiceTypeNodePort,
			Ports: []corev1.ServicePort{{
				Name:       "https",
				Protocol:   "TCP",
				Port:       443,
				TargetPort: intstr.FromInt(5443),
			}},
		},
	}
	to := s.initialTestObjects("default")
	class, ingress, endpoints, service, secret := to.IngressClass, to.Ingress, to.Endpoints, to.Service, to.Secret
	del := func(obj client.Object) { s.Client.Delete(ctx, obj) }
	for _, obj := range []client.Object{
		ns, proxySvc,
		class, endpoints, service, secret, ingress,
	} {
		s.NoError(s.Client.Create(ctx, obj))
		defer del(obj)
	}

	// s.EventuallyUpsert(func(ic *model.IngressConfig) string {
	// 	return cmp.Diff(ingress, ic.Ingress, cmpOpts...)
	// }, "ingress created")

	proxySvc.Spec.ClusterIP = "10.0.0.1"
	s.NoError(s.Client.Status().Update(ctx, proxySvc), proxySvc.Spec)
	require.Eventually(s.T(), func() bool {
		s.NoError(s.Client.Get(ctx, types.NamespacedName{Name: ingress.Name, Namespace: ingress.Namespace}, ingress))
		if len(ingress.Status.LoadBalancer.Ingress) != 1 {
			return false
		}
		if ingress.Status.LoadBalancer.Ingress[0].IP != proxySvc.Spec.ClusterIP {
			return false
		}
		return true
	}, time.Minute, time.Second)
}

func (s *ControllerTestSuite) TestHttp01Solver() {
	ctx := context.Background()
	s.createTestController(ctx)

	typePrefix := networkingv1.PathTypeImplementationSpecific
	ingressClass := &networkingv1.IngressClass{
		ObjectMeta: metav1.ObjectMeta{Name: "pomerium"},
		Spec: networkingv1.IngressClassSpec{
			Controller: s.controllerName,
		},
	}

	ingress := &networkingv1.Ingress{
		ObjectMeta: metav1.ObjectMeta{
			Name: "ingress", Namespace: "default",
			Annotations: map[string]string{
				"kubernetes.io/ingress.class": ingressClass.Name,
			},
			Labels: map[string]string{
				"acme.cert-manager.io/http01-solver": "true",
			},
		},
		Spec: networkingv1.IngressSpec{
			Rules: []networkingv1.IngressRule{{
				Host: "service.localhost.pomerium.io",
				IngressRuleValue: networkingv1.IngressRuleValue{
					HTTP: &networkingv1.HTTPIngressRuleValue{
						Paths: []networkingv1.HTTPIngressPath{{
							Path:     "/.well-known/acme-challenge/xZ2esGlx49lBuluhAjE92fHXxgHLBlxgy8hxqamt00g",
							PathType: &typePrefix,
							Backend: networkingv1.IngressBackend{
								Service: &networkingv1.IngressServiceBackend{
									Name: "service",
									Port: networkingv1.ServiceBackendPort{
										Number: 8089,
									},
								},
							},
						}},
					},
				},
			}},
		},
	}

	endpoints := &corev1.Endpoints{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "service",
			Namespace: "default",
		},
		Subsets: []corev1.EndpointSubset{{
			Addresses: []corev1.EndpointAddress{{IP: "1.2.3.4"}},
		}},
	}
	service := &corev1.Service{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "service",
			Namespace: "default",
		},
		Spec: corev1.ServiceSpec{
			Ports: []corev1.ServicePort{{
				Name:       "http",
				Protocol:   "TCP",
				Port:       8089,
				TargetPort: intstr.IntOrString{IntVal: 8089},
			}},
		},
	}

	// ingress should not be picked up unless there's a certificate
	s.NoError(s.Client.Create(ctx, ingressClass))
	s.NoError(s.Client.Create(ctx, ingress))
	s.NoError(s.Client.Create(ctx, endpoints))
	s.NoError(s.Client.Create(ctx, service))

	s.EventuallyUpsert(func(ic *model.IngressConfig) string {
		return cmp.Diff(ingress, ic.Ingress, cmpOpts...)
	}, "http01 solver ingress")
}

func (s *ControllerTestSuite) TestCustomSecrets() {
	ctx := context.Background()
	s.createTestController(ctx)
	to := s.initialTestObjects("default")
	ingressClass, ingress, endpoints, service, secret := to.IngressClass, to.Ingress, to.Endpoints, to.Service, to.Secret
	ingress.Annotations = map[string]string{
		fmt.Sprintf("%s/%s", ingress_controller.DefaultAnnotationPrefix, model.SetRequestHeadersSecret):  "request-headers",
		fmt.Sprintf("%s/%s", ingress_controller.DefaultAnnotationPrefix, model.SetResponseHeadersSecret): "response-headers",
	}

	for _, obj := range []client.Object{
		endpoints, service, secret, ingressClass,
		&corev1.Secret{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "k8s-token",
				Namespace: "default",
			},
			StringData: map[string]string{
				"token": "token-value",
			},
			Type: corev1.SecretTypeOpaque,
		}, &corev1.Secret{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "request-headers",
				Namespace: "default",
			},
			StringData: map[string]string{
				"header1": "value 1",
				"header2": "value 2",
			},
			Type: corev1.SecretTypeOpaque,
		}, &corev1.Secret{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "response-headers",
				Namespace: "default",
			},
			StringData: map[string]string{
				"header3": "value 3",
				"header4": "value 4",
			},
		},
		ingress,
	} {
		s.NoError(s.Client.Create(ctx, obj))
	}

	s.EventuallyUpsert(func(ic *model.IngressConfig) string {
		return cmp.Diff(ingress, ic.Ingress, cmpOpts...)
	}, "ingress")
}

func (s *ControllerTestSuite) TestSettingsStatusUpdate() {
	ctx := context.Background()

	name := types.NamespacedName{Namespace: "default", Name: "config"}
	reporter := reporter.IngressSettingsReporter{
		SettingsReporter: reporter.SettingsReporter{
			NamespacedName: name,
			Client:         s.Client,
		},
	}

	to := s.initialTestObjects("default")
	ingressName := types.NamespacedName{Namespace: to.Ingress.Namespace, Name: to.Ingress.Name}
	other := *to.Ingress
	other.Name = "some-other"
	otherName := types.NamespacedName{Namespace: other.Namespace, Name: other.Name}
	s.NoError(s.Client.Create(ctx, to.Ingress))
	s.NoError(s.Client.Create(ctx, &other))

	gs := icsv1.Pomerium{
		ObjectMeta: metav1.ObjectMeta{Name: name.Name, Namespace: name.Namespace},
		Spec: icsv1.PomeriumSpec{
			IdentityProvider: &icsv1.IdentityProvider{
				Provider: "oidc",
				Secret:   "secret",
			},
			Authenticate: &icsv1.Authenticate{
				URL: "https://provider.local",
			},
			Secrets: "default/default-secrets",
		},
	}
	s.NoError(s.Client.Create(ctx, &gs))

	s.NoError(reporter.IngressReconciled(ctx, &other))

	s.NoError(reporter.IngressNotReconciled(ctx, to.Ingress, errors.New("some error")))
	s.NoError(s.Client.Get(ctx, name, &gs))
	cOpts := cmpopts.IgnoreFields(icsv1.ResourceStatus{}, "ObservedAt")
	assert.Empty(s.T(), cmp.Diff(
		gs.Status.Routes,
		map[string]icsv1.ResourceStatus{
			ingressName.String(): {
				ObservedGeneration: to.Ingress.Generation,
				Reconciled:         false,
				Error:              proto.String("some error"),
			},
			otherName.String(): {
				ObservedGeneration: other.Generation,
				Reconciled:         true,
			},
		},
		cOpts))

	s.NoError(reporter.IngressReconciled(ctx, to.Ingress))
	s.NoError(s.Client.Get(ctx, name, &gs))
	assert.Empty(s.T(), cmp.Diff(
		gs.Status.Routes,
		map[string]icsv1.ResourceStatus{
			ingressName.String(): {
				ObservedGeneration: to.Ingress.Generation,
				Reconciled:         true,
			},
			otherName.String(): {
				ObservedGeneration: other.Generation,
				Reconciled:         true,
			},
		},
		cOpts))

	s.NoError(reporter.IngressDeleted(ctx, ingressName, "test"))
	s.NoError(s.Client.Get(ctx, name, &gs))
	assert.Empty(s.T(), cmp.Diff(
		gs.Status.Routes,
		map[string]icsv1.ResourceStatus{
			otherName.String(): {
				ObservedGeneration: other.Generation,
				Reconciled:         true,
			},
		},
		cOpts))
}

func TestIngressController(t *testing.T) {
	suite.Run(t, &ControllerTestSuite{})
}
