export const DEFAULT_CERTIFICATE = `-----BEGIN CERTIFICATE-----
MIIC3zCCAcegAwIBAgIDAeJAMA0GCSqGSIb3DQEBCwUAMCkxDjAMBgNVBAoTBWFk
bWluMRcwFQYDVQQDEw5Vbml2ZXJzYWwgQ0VSVDAeFw0yNTA4MDUxNjE2MThaFw00
NTA4MDUxNjE2MThaMCkxDjAMBgNVBAoTBWFkbWluMRcwFQYDVQQDEw5Vbml2ZXJz
YWwgQ0VSVDCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBANGmVldavKrB
TIcgRiqzWb4KbTQOeiPxqRIFrOsDAQfnjzSh3wST8Y5PoSgKoqvueemGdadW3N2k
0J1fiFqXLTNygvfDXVWU/7UJNTYgm6B1OvwkSXTY9omsjyECJKPmKEcxZ8QB5JrB
jbXOoY67X39R5xt5sXsj/hPk/UH0V3Jx1kmd4FMuvXeUjqn1983xhIDHFSFFnD7a
lU57SIGi1NTK7AHulwfcytbXN3auhERX5mXhCthqFRD8gmD1vg+c/RjyicFVYmMM
+j+Qno1WjLKCcGK4bTFlPnydIh/x2V3eHXd7H7aXtooZtizigbtn2YZCrIsuJ3t2
keh7jTomjdUCAwEAAaMQMA4wDAYDVR0TAQH/BAIwADANBgkqhkiG9w0BAQsFAAOC
AQEAhgC0zuruPauB6ppkFl4e9fWCzrmz0zuwWW8yRJxdkw1kc3akMob0GeIeaI69
RlvX/p7tbF6yg7rRYcZvb4rtLUSpOqOtQfS0x+NQt9mWrTYaIxyNYEaJ9ptKBN9e
F0wPGXEuhwPjkseCvKINAQRCqauz8rrY/C1Hb9Y9zPSffr6EgGObStt78ULGF45C
VWoPVVT97XZNQujQXGtaYRK1/eLzju0UtS0rdtvQ10B/LmVJqzTbb7L9MfRCTEuq
Hwqp5OJmXeVsB4HuZa2nZ2AB3TUJUyMpJqJ4KeQ6eDEQqV1LfQlDd9Ni+RhLFAQC
+8phzl7NPpFKzSPxLDM6Nq97yg==
-----END CERTIFICATE-----`

export type TenantPreset = {
  id: string
  displayName: string
  endpoint: string
  clientId: string
  orgName: string
  appName: string
  certificate: string
  allowedOrigins: string[]
  deviceName: string
}

export const BUILT_IN_TENANTS: TenantPreset[] = [
  {
    id: 'huangfa-technology-group',
    displayName: '黄发科技集团',
    endpoint: 'https://sso.devhjz.com',
    clientId: 'b39a5ad6d95848ffde82',
    orgName: 'Cloud',
    appName: 'Cloud',
    certificate: DEFAULT_CERTIFICATE,
    allowedOrigins: [],
    deviceName: '',
  },
  {
    id: 'public-authentication-service',
    displayName: '公共认证服务',
    endpoint: 'https://sso.devhjz.com',
    clientId: '6f6a7b4337ffb3d3ee3f',
    orgName: 'Public-IAM',
    appName: 'Public-APP',
    certificate: DEFAULT_CERTIFICATE,
    allowedOrigins: [],
    deviceName: '',
  },
]
