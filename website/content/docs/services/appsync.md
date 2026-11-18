+++
title = "AWS AppSync"
description = "AWS AppSync (appsync) on fakecloud: the complete 74-operation surface (100% conformance) — GraphQL APIs, data sources, resolvers, functions, schema types, API caches, domain names, Event APIs, and source-API associations. restJson1."
weight = 75
+++

fakecloud implements **AWS AppSync** as a restJson1 service. All **74 operations**
ship with **100% conformance** against AWS's own Smithy model, backed by
account-partitioned state that persists across restarts in persistent mode.
AppSync signs SigV4 with the `appsync` scope; every operation is a RESTful
`<METHOD> /v1|/v2/...` route with path labels (e.g. `POST /v1/apis`,
`GET /v1/apis/{apiId}`, `POST /v1/apis/{apiId}/types/{typeName}/resolvers`),
routed by its HTTP method and `@http` URI template.

This is a faithful **control plane + schema state**, not a set of stubs: every
resource is created, stored, and read back with the exact wire shapes AWS
returns, and every sub-resource operation validates its parent API.

## GraphQL APIs

- **`CreateGraphqlApi`** mints an `apiId`, an
  `arn:aws:appsync:<region>:<account>:apis/<apiId>` ARN, the GRAPHQL + REALTIME
  endpoint `uris` (and matching `dns`), and echoes the auth configuration for
  any of the five authentication types — `API_KEY`, `AWS_IAM`,
  `AMAZON_COGNITO_USER_POOLS`, `OPENID_CONNECT`, `AWS_LAMBDA` — including
  `additionalAuthenticationProviders`, `userPoolConfig`, `openIDConnectConfig`,
  `lambdaAuthorizerConfig`, `logConfig`, and the introspection / query-depth /
  resolver-count limits.
- **`GetGraphqlApi`** / **`ListGraphqlApis`** / **`UpdateGraphqlApi`** /
  **`DeleteGraphqlApi`** round-trip the stored API. `UpdateGraphqlApi` merges
  only the members it can change onto the stored API, so the create-only
  `apiType` / `visibility` and the tags survive (likewise `UpdateApi` and
  `UpdateChannelNamespace` keep `created`). Deleting an API cascades to its
  keys, data sources, resolvers, functions, types, cache, schema, and
  environment variables.
- **Tags**: ARN-keyed `TagResource` / `UntagResource` /
  `ListTagsForResource`. Tags passed when creating a GraphQL API, Event API,
  channel namespace, or domain name land in the same store, the `tags` member
  of every Get / List / Update response renders from it, and deleting the
  resource drops its tags.

## Sub-resources

- **API keys** (`CreateApiKey` / `ListApiKeys` / `UpdateApiKey` /
  `DeleteApiKey`) with `expires` / `deletes` epoch bounds.
- **Data sources** (`CreateDataSource` / `Get` / `List` / `Update` / `Delete`)
  for every `DataSourceType` — `AWS_LAMBDA`, `AMAZON_DYNAMODB`,
  `AMAZON_OPENSEARCH_SERVICE`, `AMAZON_ELASTICSEARCH`, `HTTP`,
  `RELATIONAL_DATABASE`, `AMAZON_EVENTBRIDGE`, `AMAZON_BEDROCK_RUNTIME`,
  `NONE` — with the type-specific config (`dynamodbConfig`, `lambdaConfig`,
  `httpConfig`, ...) echoed verbatim.
- **Resolvers** (`CreateResolver` / `Get` / `List` / `ListResolversByFunction` /
  `Update` / `Delete`) attached to a `type.field`, `UNIT` or `PIPELINE` kind,
  with VTL request/response mapping templates or `APPSYNC_JS` `code` +
  `runtime`.
- **Functions** (`CreateFunction` / `Get` / `List` / `Update` / `Delete`).
- **Schema types** (`CreateType` / `Get` / `List` / `Update` / `Delete`), SDL or
  JSON `format`.
- **API caches** (`CreateApiCache` / `Get` / `Update` / `Delete` /
  `FlushApiCache`) and **environment variables**
  (`PutGraphqlApiEnvironmentVariables` / `GetGraphqlApiEnvironmentVariables`).
- **Custom domain names** (`CreateDomainName` / `Get` / `List` / `Update` /
  `Delete`) and **API associations** (`AssociateApi` / `GetApiAssociation` /
  `DisassociateApi`).
- **Event APIs** (`CreateApi` / `GetApi` / `ListApis` / `UpdateApi` /
  `DeleteApi`) and **channel namespaces** (`CreateChannelNamespace` and its
  Get/List/Update/Delete).
- **Source-API associations** (`AssociateSourceGraphqlApi` /
  `AssociateMergedGraphqlApi` / `GetSourceApiAssociation` /
  `ListSourceApiAssociations` / `UpdateSourceApiAssociation` /
  `DisassociateSourceGraphqlApi` / `DisassociateMergedGraphqlApi` /
  `StartSchemaMerge` / `ListTypesByAssociation`).

## Schema lifecycle

`StartSchemaCreation` ingests a base64-encoded SDL schema document and stores
it. `GetSchemaCreationStatus` settles the async lifecycle from `PROCESSING` to
`SUCCESS` on read (the same state-machine-on-read pattern other async fakecloud
operations use). `GetIntrospectionSchema` returns a representation derived from
the stored SDL: the SDL verbatim for `format=SDL`, or a deterministic JSON
projection listing the declared type names for `format=JSON`.

## Validation and errors

Model-derived validation rejects contract violations with the error codes each
operation declares — `BadRequestException` universally (missing required
members, out-of-range integers, invalid enums, over-length strings), plus
`NotFoundException` (a sub-resource op whose parent API — or the addressed
resource — does not exist), `ConcurrentModificationException`, and
`ConflictException` (a duplicate channel namespace). State is
account-partitioned and persists across restarts in persistent mode.

## GraphQL data plane

A GraphQL API answers on its own hosts, as on AWS:

- **`POST https://<apiId>.appsync-api.<region>.amazonaws.com/graphql`** runs a
  query or mutation. The caller authenticates with SigV4 (`AWS_IAM`), an API
  key (`x-api-key`, `API_KEY`) or a Cognito user pool token
  (`AMAZON_COGNITO_USER_POOLS`: the token's signature is checked with the
  pool's signing key, and its issuer, expiry and the provider's
  `appIdClientRegex` are checked). Fields are authorized by AppSync's rules:
  a field's `@aws_iam`, `@aws_cognito_user_pools` or `@aws_api_key`
  directives decide, else its type's, else only the API's default mode.
  Unauthenticated requests get a 401 `UnauthorizedException`; an unauthorized
  field is `null` with an `Unauthorized` error.
- **Resolvers** that are `UNIT` `APPSYNC_JS` resolvers on a `NONE` data source
  run in an embedded JavaScript engine: the code is an ES module importing
  `@aws-appsync/utils` (`util.authType`, `util.matches`, `util.error`,
  `util.appendError`, `util.unauthorized`, `util.autoId`, `util.time.*`,
  `util.transform.toSubscriptionFilter`, `extensions.*`, `runtime.earlyReturn`),
  its `request` handler's `payload` is the data source result, and its
  `response` handler's value is the field's. A run is bounded by loop and
  recursion limits.
- **`wss://<apiId>.appsync-realtime-api.<region>.amazonaws.com/graphql`**
  speaks AppSync's `graphql-ws` realtime protocol: the connection header as
  the `header-<base64url>` subprotocol or the `header` query parameter,
  `connection_init`/`connection_ack`, `start`/`start_ack`/`error`, `data`,
  `ka` keep-alives, and `stop`/`complete`. A subscription field's resolver
  authorizes it and may set an enhanced filter
  (`extensions.setSubscriptionFilter`) and an invalidation filter. Each
  mutation result is delivered to the subscriptions whose field names the
  mutation in `@aws_subscribe` and whose filter passes it, shaped by the
  subscription's selection; `extensions.invalidateSubscriptions` ends the
  matching subscriptions with `complete`.

Point a client's DNS (or an HTTP proxy) at fakecloud for these hostnames; a
client that needs TLS needs a TLS front with a certificate it trusts.

## Honest limitations

- **GraphQL execution covers `APPSYNC_JS` unit resolvers on `NONE` data
  sources.** A resolver of another kind (VTL, `PIPELINE`, or a DynamoDB,
  Lambda, HTTP, OpenSearch or RDS data source) answers its field with an
  `UnsupportedOperation` error that names what it uses. `OPENID_CONNECT` and
  `AWS_LAMBDA` authorization are not checked. SigV4 signatures are not
  recomputed, as everywhere in fakecloud.
- **`EvaluateCode` / `EvaluateMappingTemplate` run a documented evaluation
  subset.** They validate that the code/template and the `context` are
  well-formed and deterministically render the context's `arguments` (the
  overwhelmingly common `$util.toJson($ctx.arguments)` shape), returning the
  model's `error` output member on a malformed context. They do **not** run a
  full VTL or `APPSYNC_JS` interpreter.
- **Data-source introspection** (`StartDataSourceIntrospection` /
  `GetDataSourceIntrospection`) returns job metadata; it does not introspect a
  live relational database.
