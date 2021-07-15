# istio-sdewan
This is for the integration of istio and sdewan

<!-- omit in toc -->
SDEWAN uses Istio and other open source solutions to leverage Istio Authorization and Authentication frameworks. Authentication for the SDEWAN users are done at the Isito Gateway, where all the traffic enters the cluster. Istio along with Authservice (Istio ecosystem project) enables request-level authentication with JSON Web Token (JWT) validation. This can be achieved using a custom authentication provider or any OpenID Connect providers like Keycloak, Auth0 etc.

Authservice (https://github.com/istio-ecosystem/authservice) is an istio-ecosystem project that works alongside with Envoy proxy. It is used to along with Istio to work with external IAM systems (OAUTH2). Many Enterprises have their own OAUTH2 server for authenticating users and providing roles to users. EMCO along with Istio-ingress and Authservice can use single or multiple OAUTH2 servers, one belonging to each project (Enterprise).

## Steps for setting up SDEWAN with Istio

These steps need to be followed in the Kubernetes Cluster where SDEWAN-CNF, SDNWAN-CRD-CONTROLLER and SDEWAN-OVERLAY-CONTROLLER is installed.

### Pre-Installation

#### Istio

- Install istioctl and init

  ```shell
  # Download the latest istio release
  curl -L https://istio.io/downloadIstio | sh -
  
  # Download the specified istio release for target_arch
  # In the guide, we need istio version >= 1.7.4
  # curl -L https://istio.io/downloadIstio | ISTIO_VERSION=1.7.4 TARGET_ARCH=x86_64 sh -
  
  # Add the `istioctl` client binary to your path
  export PATH=$PWD/bin:$PATH
  
  # Deploy istio operator
  istioctl operator init
  ```

- Install the `istio` demo profile using operator

  ```shell
  # Create istio namespace
  kubectl create ns istio-system
  
  # Aplly the istio demo profile
  kubectl apply -f - <<EOF
  apiVersion: install.istio.io/v1alpha1
  kind: IstioOperator
  metadata:
    namespace: istio-system
    name: example-istiocontrolplane
  spec:
    profile: demo
  EOF
  ```

### Keycloak

- Create the certificate file for keycloak

  ```shell
  # Use the key and cert in istio-sdewan/keycloak or using the commands to create
  openssl genrsa 2048 > keycloak.key
  openssl req -new -x509 -nodes -sha256 -days 365 -key keycloak.key -out keycloak.crt
  ```

- Configure and setup keycloak in k8s cluster

  ```shell
  # Create keycloak namespace
  kubectl create ns keycloak
  
  # Create secret for keycloak
  kubectl create -n keycloak secret tls ca-keycloak-certs --key keycloak/keycloak.key --cert keycloak/keycloak.crt
  
  # Deploy keycloak
  kubectl apply -f keycloak/keycloak.yaml -n keycloak
  ```

- Configure in Keycloak using its web interface

  ```
  - Create a new Realm - ex: enterprise1
  - Add Users (as per customer requirement)
  - Create a new Client under realm name - ex: sdewan
  - Under Setting for client
        > Change assess type for client to confidential
        > Under Authentication Flow Overrides - Change Direct grant flow to direct grant
        > Update Valid Redirect URIs. # "https://istio-ingress-url/*".
  - In Roles tab:
        > Add roles (ex. Admin and User)
        > Under Users assign roles from emco client to users ( Admin and User). Verify under EMCO Client roles for user are in the role.
  - Add Mappers # Under EMCO Client under mapper tab create a mapper
        > Mapper type - User Client role
        > Client-ID: emco
        > Token claim name: role
        > Claim JSON Type: string
  ```

  

#### Configure Istio Sidecar Injection for EMCO namespace

```Shell
$ kubectl label namespace emco istio-injection=enabled
```
#### Install EMCO in the emco namespace
Use the EMCO Helm chart to install EMCO in the emco namespace. EMCO services will come up with Istio sidecars.

### Enable mTLS
Enable mTLS in the emco namespace

```shell
apiVersion: "security.istio.io/v1beta1"
kind: "PeerAuthentication"
metadata:
  name: "default"
  namespace: emco
spec:
  mtls:
    mode: STRICT
```

#### Configure Istio Ingress Gateway

Create certificate for Ingress Gateway and create secret for Istio Ingress Gateway
```
$ kubectl create -n istio-system secret tls emco-credential --key=v2.key --cert=v2.crt
```

Example Gateway yaml

```shell
apiVersion: networking.istio.io/v1alpha3
kind: Gateway
metadata:
  name: emco-gateway
  namespace: emco
spec:
  selector:
    istio: ingressgateway # use Istio default gateway implementation
  servers:
  - port:
      number: 80
      name: http
      protocol: HTTP
    hosts:
    - "*"
  - port:
      number: 443
      name: https
      protocol: HTTPS
    tls:
      mode: SIMPLE
      credentialName: emco-credential
    hosts:
    - "*"
```

#### Create Istio VirtualServices Resources for EMCO
An Istio VirtualService Resource is required to be created for each of the EMCO microservices. For EMCO [VirtualService Resources](../../kud/samples/istio/emco-virtualservices.yaml) need to be applied in the cluster.

Make sure the EMCO service is accessible through Istio Ingress Gateway at this point.  "https://istio-ingress-url/v2/projects"


```shell
$ curl http://<istio-ingress-url>/v2/projects
200: ...

OR

$ emcoctl get projects
```

#### Enable Istio Authentication and Authorization Policy
Install an Authentication Policy for the Keycloak server being used. Check this document on how to configure Keycloak. After these 2 policies are applied access to EMCO can happen only with an access token retrieved from Keycloak.

```shell
apiVersion: security.istio.io/v1beta1
kind: RequestAuthentication
metadata:
  name: request-keycloak-auth
  namespace: istio-system
spec:
  jwtRules:
    - issuer: "http://<keycloak-url>/auth/realms/enterprise1"
      jwksUri: "http://<keycloak-url>/auth/realms/enterprise1/protocol/openid-connect/certs"
```

#### Authorization Policies with Istio

A deny policy is added to ensure that only authenticated users (with right token) are allowed access.

```shell
apiVersion: "security.istio.io/v1beta1"
kind: "AuthorizationPolicy"
metadata:
  name: "deny-auth-policy"
  namespace: istio-system
spec:
  selector:
    matchLabels:
      istio: ingressgateway
  action: DENY
  rules:
  - from:
    - source:
        notRequestPrincipals: ["*"]
```

Curl to the EMCO url will give an error "403 : RBAC: access denied"

Retrieve access token from Keycloak and use it to access EMCO resources.

```
$ export TOKEN=`curl --location --request POST 'http://<keycloack url>/auth/realms/enterprise1/protocol/openid-connect/token' --header 'Content-Type: application/x-www-form-urlencoded' --data-urlencode 'grant_type=password' --data-urlencode 'client_id=emco' --data-urlencode 'username=user1' --data-urlencode 'password=test' --data-urlencode 'client_secret=<secret>' | jq .access_token`

$ curl --header "Authorization: Bearer $TOKEN"  http://<istio-ingress-url>/v2/projects

OR

$ emcoctl get projects -t $TOKEN

```
#### Authorization Policies with Istio

As specified in Keycloak section Role Mappers are created using Keycloak. Check Keycloak section on how to create Roles using Keycloak. These can be used apply authorizations based on Role of the user.

For example to allow Role "Admin" to perform any operations and Role "User" to only create/delete resources under a specified project following policies can be used.

```shell

apiVersion: "security.istio.io/v1beta1"
kind: AuthorizationPolicy
metadata:
  name: allow-admin
  namespace: istio-system
spec:
  selector:
    matchLabels:
      app: istio-ingressgateway
  action: ALLOW
  rules:
  - when:
    - key: request.auth.claims[role]
      values: ["Admin"]

---
apiVersion: security.istio.io/v1beta1
kind: AuthorizationPolicy
metadata:
  name: allow-user
  namespace: istio-system
spec:
  selector:
    matchLabels:
      app: istio-ingressgateway
  action: ALLOW
  rules:
  - to:
    - operation:
        paths: ["/v2/projects/restrictedproj/*"]
    - operation:
        methods: ["GET"]
        paths: ["/v2/projects/restrictedproj"]
    when:
      - key: request.auth.claims[role]
        values: ["User"]

```

## Keycloak setup

Keycloak is an open source software product to allow single sign-on with Identity Management and Access Management. Keycloak is being used here as an example of IAM service to be used with EMCO. Keycloak need to be running and configured to work with Istio and Authservice.

Keycloak deployment file for Kubernetes is available: https://raw.githubusercontent.com/keycloak/keycloak-quickstarts/latest/kubernetes-examples/keycloak.yaml

In a Kubernetes cluster where Keycloak is going to be installed follow these steps to create Keycloak deployment:

```shell
$ kubectl create ns keycloak
$ kubectl create -n keycloak secret tls ca-keycloak-certs --key keycloak.key --cert keycloak.crt
$ kubectl apply -f keycloak.yaml -n keycloak
```

Example Yaml file that can be used to install Keycloak

```shell
apiVersion: v1
kind: Service
metadata:
  name: keycloak
  labels:
    app: keycloak
spec:
  ports:
  - name: http
    port: 8080
    targetPort: 8080
  - name: https
    port: 8443
    targetPort: 8443
  selector:
    app: keycloak
  type: LoadBalancer
---

apiVersion: apps/v1
kind: Deployment
metadata:
  name: keycloak
  labels:
    app: keycloak
spec:
  replicas: 1
  selector:
    matchLabels:
      app: keycloak
  template:
    metadata:
      labels:
        app: keycloak
    spec:
      containers:
      - name: keycloak
        image: quay.io/keycloak/keycloak:9.0.2
        volumeMounts:
        - name: keycloak-certs
          mountPath: /etc/x509/https
          readOnly: false
        env:
        - name: KEYCLOAK_USER
          value: "admin"
        - name: KEYCLOAK_PASSWORD
          value: "admin"
        - name: PROXY_ADDRESS_FORWARDING
          value: "true"
        ports:
        - name: http
          containerPort: 8080
        - name: https
          containerPort: 8443
        readinessProbe:
          httpGet:
            path: /auth/realms/master
            port: 8080
      volumes:
      - name: keycloak-certs
        secret:
          secretName: keycloak-certs
          defaultMode: 420
          optional: true
```

#### Example Keycloak Configuration for working with Istio and EMCO
Create a realm, add users and roles to Keycloak as required to work with Istio and Authservice.

Steps to configure in Keycloak using its web interface:
- Create a new Realm - ex: enterprise1
- Add Users (as per customer requirement)
- Create a new Client under realm  name - ex: emco
- Under Setting for client
  - Change assess type for client to confidential
  - Under Authentication Flow Overrides - Change Direct grant flow to direct grant
  -  Update Valid Redirect URIs. This needs to be of the format "https://istio-ingress-url/*". Here "istio-ingress-url" is URL for Istio Ingress Gateway.
- In Roles tab:
   - Add roles (ex. Admin and User)
   - Under Users assign roles from emco client to users ( Admin and User). Verify under EMCO Client roles for user are in the role.
- Add Mappers
  - Under EMCO Client under mapper tab create a mapper
  ```
    Mapper type - User Client role
    Client-ID: emco
    Token claim name: role
    Claim JSON Type: string
  ```
For complete documentation of Keycloak refer to these links:

https://www.keycloak.org/getting-started/getting-started-kube

https://developers.redhat.com/blog/2020/01/29/api-login-and-jwt-token-generation-using-keycloak/

## Steps for setting up EMCO with Istio + Authservice (Using authservice-configurator)

To make configuration of authservice easier to work with EMCO, a project called autheservice-configurator(https://github.com/intel/authservice-configurator) is used. This manages configuration for authservice and makes it easier to add and delete chains from authservice. 

1. Follow instructions on this repository to deploy authservice configurator: https://github.com/intel/authservice-configurator#install-configurator-for-authservice

2. Deploy Authservice: With TLS https://github.com/intel/authservice-configurator#authservice-over-tls-connection or without TLS https://github.com/intel/authservice-configurator#deploy-authservice 

3. Deploy Chain CR
    Example of chain CR: (https://github.com/intel/authservice-configurator/blob/main/config/samples/authcontroller_v1_chain.yaml)
    Make sure to change the Chain values to correspond to your own OIDC installation. Install the Chains to the namespace where you have your AuthService instance running. After this the ConfigMap which the AuthService needs is dynamically created and AuthService deployment in the same namespace is restarted. 

  Example chain with EMCO:

  ```
  apiVersion: authcontroller.intel.com/v1
  kind: Chain
  metadata:
    name: chain-sample-1
    namespace: istio-system
  spec:
    authorizationUri: "https://<keycloack-url>/auth/realms/enterprise1/protocol/openid-connect/auth"
    tokenUri: "https://<keycloack-url>/auth/realms/enterprise1/protocol/openid-connect/token"
    callbackUri: "https://<istio-ingress-url>/mesh/auth_callback"
    clientId: "emco"
    clientSecret: "1f07edc2-8ca3-4529-b91d-8c9ab01f1295"
    cookieNamePrefix: "service-name"
    trustedCertificateAuthority: "-----BEGIN CERTIFICATE-----\MZnfqxDBn8jPQ==.............................\n-----END CERTIFICATE-----\n"
    jwks: '{"keys":[{"kid": .........................}]}'
    match:
      header: ":path"
      prefix: "/v2/projects/enterprise1"

  ```
Use multiple chains for different OAUTH Servers. The match section of the Chain CR is used to decide which chain will be used for what url.

```
match:
  header: ":path"
  prefix: "/v2/projects/enterprise1"

```

4. Deploy EnvoyFilter: With TLS https://github.com/intel/authservice-configurator#authservice-over-tls-connection or without TLS https://github.com/intel/authservice-configurator#deploy-authservice 

5. Open a browser and use url https://istio-ingress-url/v2/projects" and you'll be redirected to external OAuth Server for authentication.

## Other security considerations

In addition to the use of Istio for authorization and authentication, the security of the EMCO system depends on setup and configuration of the underlying cluster node operating systems and of the Kubernetes cluster installation.

This section provides some references to find further information for guidance on setting up a secure infrastructure for EMCO.

[Kubernetes Security Concepts] (https://kubernetes.io/docs/concepts/security/)

[Kubernetes Tutorials] (https://kubernetes.io/docs/tutorials/clusters/)

[Istio / Security] (https://istio.io/latest/docs/reference/config/security/)


## APPENDIX

## Steps for setting up EMCO with Istio + Authservice (Not recommended, without authservice-configurator)

Before in this document it was explained how authservice can be used with EMCO using authservice-configurator. This section
goes over how EMCO can be used without authservice-configurator.

Authentication Policy need to be applied as above:

```shell
apiVersion: security.istio.io/v1beta1
kind: RequestAuthentication
metadata:
  name: request-keycloak-auth
  namespace: istio-system
spec:
  jwtRules:
    - issuer: "https://<keycloak-url>/auth/realms/enterprise1"
      jwksUri: "http://<keycloak-url>/auth/realms/enterprise1/protocol/openid-connect/certs"
```
And deny AuthorizationPolicy as in the last section are in effect.

#### Authservice Setup in Istio Ingress-gateway

Authservice requires a configMap to be created and to be populated with following fields  authorizationUri, tokenUri, callbackUri, clientId, clientSecret, trustedCertificateAuthority and jwks based on the Keycloak installation:

Example ConfigMap for Authservice using example realm enterprise1 and client as emco:

```shell
kind: ConfigMap
apiVersion: v1
metadata:
  name: emco-authservice-configmap
  namespace: istio-system
data:
  config.json: |
    {
      "listen_address": "127.0.0.1",
      "listen_port": "10003",
      "log_level": "trace",
      "threads": 8,
      "chains": [
        {
          "name": "idp_filter_chain",
          "filters": [
          {
            "oidc":
              {
                "authorization_uri": "https://<Keycloak-url>/auth/realms/enterprise1/protocol/openid-connect/auth",
                "token_uri": "https://<Keycloak-url>/auth/realms/enterprise1/protocol/openid-connect/token",
                "callback_uri": "https://<Istio Ingress url>/mesh/auth_callback",
                "jwks": "{Escaped Json output of the command --> curl http://<Keycloak-url>/auth/realms/enterprise1/protocol/openid-connect/certs}",
                "client_id": "emco",
                "client_secret": "Copy secret from keycloak",
                "trusted_certificate_authority": "-----BEGIN CERTIFICATE-----CA Certificate for the keycloak server in escaped format----END CERTIFICATE-----",
                "scopes": [],
                "id_token": {
                  "preamble": "Bearer",
                  "header": "Authorization"
                },
                "access_token": {
                  "preamble": "Bearer",
                  "header": "Authorization"
                }
              }
            }
          ]
        }
      ]
    }
```
#### Install Authservice with the Isito-Ingress gateway
In this setup Authservice is getting setup at the Isito-Ingress gateway level. Refer this link for details:

https://github.com/istio-ecosystem/authservice/tree/master/bookinfo-example#istio-ingress-gateway-integration

Currently, there is not yet a native way to install Authservice into the Istio Ingress-gateway. We are manually modifying the Deployment of "istio-ingressgateway" to add the Authservice container. Add the container below. Note: Change the container section in ingress-gateway deployment to make it possible to add multiple containers.

```shell
$ kubectl edit deployments istio-ingressgateway -n istio-system
Under containers section add:
- name: authservice
        image: adrianlzt/authservice:0.3.1-d3cd2d498169
        imagePullPolicy: Always
        ports:
          - containerPort: 10003
        volumeMounts:
          - name: emco-authservice-configmap-volume
            mountPath: /etc/authservice

In the volumes section add:
     - name: emco-authservice-configmap-volume
        configMap:
          name: emco-authservice-configmap
```

#### EnvoyFilter Resource for Authservice
As a last step to enable Authservice create an EnvoyFilter resource for Authservice. At this time the Authservice is enabled and the traffic will flow to Authservice for interaction with the OAUTH2 server.

```shell
apiVersion: networking.istio.io/v1alpha3
kind: EnvoyFilter
metadata:
  name: sidecar-token-service-filter-for-ingress
  namespace: istio-system
spec:
  workloadSelector:
    labels:
      istio: ingressgateway
      app: istio-ingressgateway
  configPatches:
  - applyTo: HTTP_FILTER
    match:
      context: GATEWAY
      listener:
        filterChain:
          filter:
            name: "envoy.http_connection_manager"
            subFilter:
              name: "envoy.filters.http.jwt_authn"
    patch:
      operation: INSERT_BEFORE
      value:
        name: envoy.ext_authz
        typed_config:
          "@type": type.googleapis.com/envoy.extensions.filters.http.ext_authz.v3.ExtAuthz
          #   stat_prefix: ext_authz
          grpc_service:
            envoy_grpc:
              cluster_name: ext_authz
            timeout: 10s # Timeout for the entire request (including authcode for token exchange with the IDP)
  - applyTo: CLUSTER
    match:
      context: ANY
      cluster: {} # this line is required starting in istio 1.4.0
    patch:
      operation: ADD
      value:
        name: ext_authz
        connect_timeout: 5s # This timeout controls the initial TCP handshake timeout - not the timeout for the entire request
        type: LOGICAL_DNS
        lb_policy: ROUND_ROBIN
        http2_protocol_options: {}
        load_assignment:
          cluster_name: ext_authz
          endpoints:
          - lb_endpoints:
            - endpoint:
                address:
                  socket_address:
                    address: 127.0.0.1
                    port_value: 10003
```


### Support Multiple OAUTH Servers

To setup EMCO to work with multiple OAUTH Servers, two resources need to be updated
- RequestAuthentication
- AuthService ConfigMap

```shell
apiVersion: security.istio.io/v1beta1
kind: RequestAuthentication
metadata:
  name: request-keycloak-auth
  namespace: istio-system
spec:
  jwtRules:
    - issuer: "https://<keycloak-url>/auth/realms/enterprise1"
      jwksUri: "http://<keycloak-url>/auth/realms/enterprise1/protocol/openid-connect/certs"
    - issuer: "https://<keycloak-url>/auth/realms/enterprise2"
      jwksUri: "http://<keycloak-url>/auth/realms/enterprise2/protocol/openid-connect/certs"
```

In the Authservice configMap multiple chains need to be added and the match field decides which chain is to be used

```shell
---
kind: ConfigMap
apiVersion: v1
metadata:
name: emco-authservice-configmap
namespace: istio-system
data:
config.json: |
  {
    "listen_address": "127.0.0.1",
    "listen_port": "10003",
    "log_level": "trace",
    "threads": 8,
    "chains": [
      {
        "name": "idp_filter_chain_1",
        "match": {
          "header": ":path",
          "prefix": "/v2/projects/enterprise1"
        },
        "filters": [
        {
          "oidc":
            {
                "authorization_uri": "https://<Keycloak-url>/auth/realms/enterprise1/protocol/openid-connect/auth",
                "token_uri": "https://<Keycloak-url>/auth/realms/enterprise1/protocol/openid-connect/token",
                "callback_uri": "https://<Istio Ingress url>/mesh/auth_callback",
                "jwks": "{Escaped Json output of the command --> curl http://<Keycloak-url>/auth/realms/enterprise1/protocol/openid-connect/certs}",
                "client_id": "emco",
                "client_secret": "Copy secret from keycloak",
                "trusted_certificate_authority": "-----BEGIN CERTIFICATE-----CA Certificate for the keycloak server in escaped format----END CERTIFICATE-----",
                "scopes": [],
                "id_token": {
                  "preamble": "Bearer",
                  "header": "Authorization"
                },
                "access_token": {
                  "preamble": "Bearer",
                  "header": "Authorization"
                }
              }
          }
        ]
      },
      {
        "name": "idp_filter_chain_2",
        "match": {
          "header": ":path",
          "prefix": "/v2/projects/enterprise2"
        },
        "filters": [
        {
          "oidc":
            {
                "authorization_uri": "https://<Keycloak-url>/auth/realms/enterprise2/protocol/openid-connect/auth",
                "token_uri": "https://<Keycloak-url>/auth/realms/enterprise2/protocol/openid-connect/token",
                "callback_uri": "https://<Istio Ingress url>/mesh/auth_callback",
                "jwks": "{Escaped Json output of the command --> curl http://<Keycloak-url>/auth/realms/enterprise2/protocol/openid-connect/certs}",
                "client_id": "emco",
                "client_secret": "Copy secret from keycloak",
                "trusted_certificate_authority": "-----BEGIN CERTIFICATE-----CA Certificate for the keycloak server in escaped format----END CERTIFICATE-----",
                "scopes": [],
                "id_token": {
                  "preamble": "Bearer",
                  "header": "Authorization"
                },
                "access_token": {
                  "preamble": "Bearer",
                  "header": "Authorization"
                }
            }
          }
        ]
      }
    ]
  }
```
