+++
title = "Bedrock AgentCore"
description = "Agent runtimes run as containers, Cognito JWT authorizers, short-term Memory events and Code Interpreter sandboxes."
weight = 24
+++

fakecloud implements the parts of **Amazon Bedrock AgentCore** an agent deployed with Terraform or the SDKs uses: the control plane (`bedrock-agentcore-control.<region>.amazonaws.com`) for agent runtimes, memories, resource policies and tags, and the data plane (`bedrock-agentcore.<region>.amazonaws.com`) for invoking runtimes, short-term memory events and Code Interpreter sessions. Both sign as `bedrock-agentcore`.

## Agent runtimes

- **Control plane** — CreateAgentRuntime, GetAgentRuntime (by version too), UpdateAgentRuntime (a new version each time), DeleteAgentRuntime, ListAgentRuntimes, ListAgentRuntimeVersions, GetAgentRuntimeEndpoint and ListAgentRuntimeEndpoints (`DEFAULT`).
- **InvokeAgentRuntime runs your code.** Each `runtimeSessionId` gets its own container: the runtime's zip is read from S3 (`codeConfiguration.code.s3`, by version when given), mounted at `/var/task`, and run as `python <entryPoint>` in the AWS Lambda Python base image of its `PYTHON_3_x` runtime, listening on port 8080. The invocation is forwarded to the container's `POST /invocations` with `Content-Type`, `Accept`, the session id header, the headers `requestHeaderAllowlist` names and `X-Amzn-Bedrock-AgentCore-Runtime-Custom-*`; its status, body and content type come back unchanged.
- **Sessions outlive their invocations**, as AgentCore's microVMs do: work an agent starts after answering keeps running. A session ends after `idleRuntimeSessionTimeout` without invocations while its `/ping` does not report `HealthyBusy`, at `maxLifetime`, on StopRuntimeSession, or when the runtime is deleted.
- **The container runs as the runtime's role**: fakecloud mints session credentials for `roleArn` and sets `AWS_ENDPOINT_URL` to fakecloud, `AWS_REGION` and the runtime's `environmentVariables`. `FAKECLOUD_CONTAINER_HOSTS`, `FAKECLOUD_CONTAINER_HOSTS_FILE` and `FAKECLOUD_CONTAINER_CA_BUNDLE` apply as for Lambda.
- **Inbound auth.** A runtime with `customJWTAuthorizer` admits only a bearer token signed by the fakecloud Cognito user pool its `discoveryUrl` names, unexpired, with that issuer, and from an allowed client, audience and scope when those are set. Any other runtime admits only SigV4 callers. Refusals are `403 AccessDeniedException`.
- Container images (`containerConfiguration`) are not run; invoking such a runtime returns an error.

## Memory

- **Control plane** — CreateMemory, GetMemory, UpdateMemory, DeleteMemory, ListMemories. Memories keep short-term events only: a `memoryStrategies` (long-term extraction) request is refused with `ValidationException`.
- **Events** — CreateEvent, ListEvents (filtered by actor, session and branch, sorted by event time, with or without payloads, paged), GetEvent, DeleteEvent, ListSessions, ListActors.

## Code Interpreter

- StartCodeInterpreterSession, InvokeCodeInterpreter, StopCodeInterpreterSession and GetCodeInterpreterSession for any interpreter identifier, including `aws.codeinterpreter.v1`.
- Each session is a container with no network running a Python kernel that keeps one module scope across `executeCode` calls (`clearContext` resets it). The tools `executeCode` (Python), `executeCommand`, `writeFiles`, `readFiles`, `listFiles` and `removeFiles` answer as AgentCore's do, as one `result` event on the response's event stream, with `structuredContent` (`stdout`, `stderr`, `exitCode`, `executionTime`).
- The sandbox image is the Lambda Python base image; set `FAKECLOUD_CODE_INTERPRETER_IMAGE` to an image with the libraries your code imports (AgentCore's sandbox has pandas, NumPy and others preinstalled). Sessions end after `sessionTimeoutSeconds` without calls.

## Resource policies and tags

PutResourcePolicy, GetResourcePolicy, DeleteResourcePolicy, TagResource, UntagResource and ListTagsForResource store and return their documents. Resource policies are not evaluated against invocations.

## Not implemented

Gateways, credential providers, workload identities, browsers, harnesses, evaluations, policy engines, long-term memory records and extraction jobs, and container-image runtimes.
